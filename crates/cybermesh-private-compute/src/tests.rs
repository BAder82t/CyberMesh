#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::protocol::{Faults, run_with};
use cybermesh_sharing::gf256::mul;
use cybermesh_sharing::{RandomSource, SharingError};
use std::collections::BTreeSet;

/// Deterministic xorshift for tests only. NOT secret randomness.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}
impl RandomSource for Rng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), SharingError> {
        for b in buf {
            *b = (self.next() >> 24) as u8;
        }
        Ok(())
    }
}

/// Returns the scripted bytes in order, then fails.
struct Script(Vec<u8>, usize);
impl RandomSource for Script {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), SharingError> {
        for b in buf {
            *b = *self.0.get(self.1).ok_or(SharingError::Randomness)?;
            self.1 += 1;
        }
        Ok(())
    }
}

/// The same circuit on plain values.
fn plain(c: &Circuit, inputs: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    for g in &c.gates {
        let x = match *g {
            Gate::Input { index, .. } => inputs[index],
            Gate::Add(a, b) => v[a.0] ^ v[b.0],
            Gate::AddConst(a, k) => v[a.0] ^ k,
            Gate::MulConst(a, k) => mul(v[a.0], k),
            Gate::Mul(a, b) => mul(v[a.0], v[b.0]),
        };
        v.push(x);
    }
    c.outputs.iter().map(|w| v[w.0]).collect()
}

fn random_circuit(rng: &mut Rng, parties: usize, multiplying: bool) -> (Circuit, Vec<u8>) {
    let mut b = CircuitBuilder::new();
    let ninputs = 2 + (rng.next() % 3) as usize;
    let mut wires: Vec<Wire> = (0..ninputs)
        .map(|_| b.input(1 + (rng.next() as usize % parties)))
        .collect();
    for _ in 0..(6 + rng.next() % 9) {
        let pick = |rng: &mut Rng, w: &[Wire]| w[(rng.next() as usize) % w.len()];
        let (x, y) = (pick(rng, &wires), pick(rng, &wires));
        let k = (rng.next() >> 8) as u8;
        let w = match rng.next() % if multiplying { 4 } else { 3 } {
            0 => b.add(x, y),
            1 => b.add_const(x, k),
            2 => b.mul_const(x, k),
            _ => b.mul(x, y),
        };
        wires.push(w);
    }
    for _ in 0..(1 + rng.next() % 3) {
        let w = wires[(rng.next() as usize) % wires.len()];
        b.output(w);
    }
    let inputs = (0..ninputs).map(|_| (rng.next() >> 16) as u8).collect();
    (b.build(), inputs)
}

#[test]
fn computations_match_plain_evaluation_for_many_circuits_and_parameters() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for &(n, t) in &[(3, 1), (4, 1), (5, 2), (6, 2), (7, 3), (9, 4)] {
        let p = Params::new(n, t).unwrap();
        for _ in 0..40 {
            let (c, inputs) = random_circuit(&mut rng, n, true);
            let got = run(p, &c, &inputs, &mut rng).unwrap();
            assert_eq!(got.outputs, plain(&c, &inputs), "n={n} t={t}");
        }
    }
}

#[test]
fn linear_circuits_need_only_t_plus_one_parties_and_multiplication_needs_a_majority() {
    let mut rng = Rng(7);
    // n = t + 1 = 2: linear is fine.
    let p = Params::new(2, 1).unwrap();
    for _ in 0..20 {
        let (c, inputs) = random_circuit(&mut rng, 2, false);
        assert_eq!(
            run(p, &c, &inputs, &mut rng).unwrap().outputs,
            plain(&c, &inputs)
        );
    }
    // ...but a multiplication gate is refused below 2t + 1.
    let mut b = CircuitBuilder::new();
    let (x, y) = (b.input(1), b.input(2));
    let m = b.mul(x, y);
    b.output(m);
    let c = b.build();
    assert_eq!(
        run(p, &c, &[3, 4], &mut rng),
        Err(ComputeError::NeedsHonestMajority { n: 2, t: 1 })
    );
    assert_eq!(
        run(Params::new(4, 2).unwrap(), &c, &[3, 4], &mut rng),
        Err(ComputeError::NeedsHonestMajority { n: 4, t: 2 })
    );
    assert!(run(Params::new(5, 2).unwrap(), &c, &[3, 4], &mut rng).is_ok());
    // Parameter and input checks.
    for (n, t) in [(3, 0), (1, 1), (2, 2), (256, 1)] {
        assert_eq!(Params::new(n, t), Err(ComputeError::InvalidParams));
    }
    let p5 = Params::new(5, 2).unwrap();
    assert_eq!(
        run(p5, &c, &[1], &mut rng),
        Err(ComputeError::WrongInputCount {
            expected: 2,
            got: 1
        })
    );
    let mut b = CircuitBuilder::new();
    let x = b.input(9);
    b.output(x);
    assert_eq!(
        run(p5, &b.build(), &[1], &mut rng),
        Err(ComputeError::BadOwner(9))
    );
    let mut b = CircuitBuilder::new();
    let x = b.input(0);
    b.output(x);
    assert_eq!(
        run(p5, &b.build(), &[1], &mut rng),
        Err(ComputeError::BadOwner(0))
    );
}

#[test]
fn polynomial_evaluation_public_at_secret_and_secret_at_public() {
    let mut rng = Rng(11);
    let p = Params::new(5, 2).unwrap();
    // p(x) = 7 + 3x + 200x^2 + x^3 at a secret x.
    let coeffs = [7u8, 3, 200, 1];
    let mut b = CircuitBuilder::new();
    let x = b.input(1);
    let y = b.eval_public_poly_at_secret(&coeffs, x);
    b.output(y);
    let c = b.build();
    for secret in [0u8, 1, 2, 77, 255] {
        let horner = coeffs
            .iter()
            .rev()
            .fold(0u8, |acc, &k| mul(acc, secret) ^ k);
        assert_eq!(
            run(p, &c, &[secret], &mut rng).unwrap().outputs,
            vec![horner]
        );
    }
    assert_eq!(c.multiplications(), 3, "one multiplication per degree");
    // A secret polynomial at a public point is linear, hence local: no multiplication.
    let mut b = CircuitBuilder::new();
    let cs: Vec<Wire> = (0..4).map(|i| b.input(1 + i % 5)).collect();
    let y = b.eval_secret_poly_at_public(&cs, 9).unwrap();
    b.output(y);
    let c = b.build();
    assert_eq!(c.multiplications(), 0);
    let secret = [5u8, 6, 7, 8];
    let want = secret.iter().rev().fold(0u8, |acc, &k| mul(acc, 9) ^ k);
    assert_eq!(run(p, &c, &secret, &mut rng).unwrap().outputs, vec![want]);
    assert!(
        CircuitBuilder::new()
            .eval_secret_poly_at_public(&[], 3)
            .is_none()
    );
    // An empty public polynomial is the zero polynomial.
    let mut b = CircuitBuilder::new();
    let x = b.input(1);
    let z = b.eval_public_poly_at_secret(&[], x);
    b.output(z);
    assert_eq!(
        run(p, &b.build(), &[42], &mut rng).unwrap().outputs,
        vec![0]
    );
}

#[test]
fn communication_and_rounds_follow_the_stated_formulas() {
    let mut rng = Rng(3);
    let n = 5usize;
    let p = Params::new(n, 2).unwrap();
    // 2 inputs, 1 multiplication, 1 output.
    let mut b = CircuitBuilder::new();
    let (x, y) = (b.input(1), b.input(2));
    let m = b.mul(x, y);
    b.output(m);
    let s = run(p, &b.build(), &[3, 4], &mut rng).unwrap().stats;
    assert_eq!(s.multiplications, 1);
    assert_eq!(s.rounds, 3);
    assert_eq!(s.messages, 2 * (n - 1) + n * (n - 1) + n * (n - 1));
    // A chain of three multiplications has depth 3; two independent ones share a round.
    let mut b = CircuitBuilder::new();
    let x = b.input(1);
    let m1 = b.mul(x, x);
    let m2 = b.mul(m1, x);
    let m3 = b.mul(m2, x);
    let side = b.mul(x, x); // parallel with m1
    b.output(m3);
    b.output(side);
    let s = run(p, &b.build(), &[9], &mut rng).unwrap().stats;
    assert_eq!(s.rounds, 1 + 3 + 1);
    assert_eq!(s.multiplications, 4);
    assert_eq!(s.messages, (n - 1) + 4 * n * (n - 1) + 2 * n * (n - 1));
    // Linear-only: no multiplication rounds.
    let mut b = CircuitBuilder::new();
    let (x, y) = (b.input(1), b.input(2));
    let a = b.add(x, y);
    b.output(a);
    assert_eq!(
        run(p, &b.build(), &[1, 2], &mut rng).unwrap().stats.rounds,
        2
    );
}

#[test]
fn any_t_parties_see_nothing_about_an_input() {
    // n = 5, t = 2: parties 1 and 2 receive two shares of an input owned by party 3. For a fixed
    // secret, as the dealer's two random coefficients range over all 65,536 pairs, the pair of
    // shares takes every value exactly once, for every secret: the view is independent of it.
    let p = Params::new(5, 2).unwrap();
    let mut b = CircuitBuilder::new();
    b.input(3);
    let c = b.build();
    let view_pairs = |secret: u8| -> BTreeSet<(u8, u8)> {
        let mut set = BTreeSet::new();
        for a1 in 0..=255u8 {
            for a2 in 0..=255u8 {
                let r = run(p, &c, &[secret], &mut Script(vec![a1, a2], 0)).unwrap();
                set.insert((r.views[0][0], r.views[1][0]));
            }
        }
        set
    };
    let (s0, s1) = (view_pairs(7), view_pairs(200));
    assert_eq!(s0.len(), 65_536);
    assert_eq!(s0, s1);
}

#[test]
fn a_multiplication_gate_leaks_nothing_to_a_corrupt_party() {
    // n = 3, t = 1, party 1 corrupt. Party 2 owns `a`, party 3 owns `b`. Party 1 sees its share of
    // a, its share of b, and the re-shared products q_2(1), q_3(1). RNG order: a's coefficient,
    // b's coefficient, then one coefficient per party for the product re-sharing.
    let p = Params::new(3, 1).unwrap();
    let mut b = CircuitBuilder::new();
    let (x, y) = (b.input(2), b.input(3));
    b.mul(x, y);
    let c = b.build();
    let mut rng = Rng(99);
    for &(sx, sy) in &[(7u8, 9u8), (200, 1), (0, 0), (255, 255)] {
        for _ in 0..300 {
            // Any target view the corrupt party could see...
            let target = [
                rng.next() as u8,
                rng.next() as u8,
                rng.next() as u8,
                rng.next() as u8,
            ];
            // ...is produced, by exactly this randomness, whatever the inputs are.
            let (a1, b1) = (target[0] ^ sx, target[1] ^ sy);
            let h = |s: u8, k1: u8, j: u8| s ^ mul(k1, j);
            let h2 = mul(h(sx, a1, 2), h(sy, b1, 2));
            let h3 = mul(h(sx, a1, 3), h(sy, b1, 3));
            let (c2, c3) = (target[2] ^ h2, target[3] ^ h3);
            let r = run(p, &c, &[sx, sy], &mut Script(vec![a1, b1, 0x55, c2, c3], 0)).unwrap();
            assert_eq!(r.views[0], target.to_vec(), "inputs ({sx}, {sy})");
        }
    }
}

#[test]
fn tampering_with_an_opened_share_is_detected_when_there_are_spare_shares() {
    let mut rng = Rng(5);
    let p = Params::new(5, 2).unwrap();
    let mut b = CircuitBuilder::new();
    let (x, y) = (b.input(1), b.input(2));
    let m = b.mul(x, y);
    b.output(m);
    let c = b.build();
    let f = Faults {
        output_delta: vec![(0, 3, 0x40)],
        ..Faults::default()
    };
    assert_eq!(
        run_with(p, &c, &[3, 4], &mut rng, &f),
        Err(ComputeError::Inconsistent(0))
    );
    // With exactly t + 1 parties there is no redundancy to check against: the lie goes through.
    let p2 = Params::new(2, 1).unwrap();
    let mut b = CircuitBuilder::new();
    let (x, y) = (b.input(1), b.input(2));
    let s = b.add(x, y);
    b.output(s);
    let c = b.build();
    let f = Faults {
        output_delta: vec![(0, 1, 0x40)],
        ..Faults::default()
    };
    let wrong = run_with(p2, &c, &[3, 4], &mut rng, &f).unwrap().outputs;
    assert_ne!(
        wrong,
        vec![3 ^ 4],
        "undetected: n = t + 1 has no spare share"
    );
}

#[test]
fn a_party_that_lies_while_resharing_a_product_corrupts_the_result_silently() {
    // Documented limit: semi-honest security only. The result is a valid degree-t sharing of the
    // wrong value, so the output check passes.
    let mut rng = Rng(8);
    let p = Params::new(5, 2).unwrap();
    let mut b = CircuitBuilder::new();
    let (x, y) = (b.input(1), b.input(2));
    let m = b.mul(x, y);
    b.output(m);
    let c = b.build();
    let honest = run(p, &c, &[3, 4], &mut rng).unwrap().outputs[0];
    assert_eq!(honest, mul(3, 4));
    // Gate 2 is the multiplication; party index 1 adds 0x10 to its product before resharing.
    let f = Faults {
        mul_delta: vec![(2, 1, 0x10)],
        ..Faults::default()
    };
    let bad = run_with(p, &c, &[3, 4], &mut rng, &f).unwrap().outputs[0];
    assert_ne!(bad, honest);
    // Exactly the Lagrange weight of party 2 (point 2) times the injected error.
    let xs = [1u8, 2, 3, 4, 5];
    let lam2 = {
        let (mut num, mut den) = (1u8, 1u8);
        for (m, &xm) in xs.iter().enumerate() {
            if m != 1 {
                num = mul(num, xm);
                den = mul(den, xm ^ 2);
            }
        }
        mul(num, cybermesh_sharing::gf256::inv(den))
    };
    assert_eq!(bad, honest ^ mul(lam2, 0x10));
}

#[test]
fn randomness_failure_stops_the_run_and_wire_reuse_works() {
    let p = Params::new(3, 1).unwrap();
    let mut b = CircuitBuilder::new();
    let x = b.input(1);
    b.output(x);
    let c = b.build();
    assert_eq!(
        run(p, &c, &[5], &mut Script(vec![], 0)),
        Err(ComputeError::Randomness)
    );
    // A wire used several times and opened several times.
    let mut b = CircuitBuilder::new();
    let x = b.input(1);
    let sq = b.mul(x, x);
    let sum = b.add(sq, x);
    b.output(sq);
    b.output(sum);
    b.output(x);
    let mut rng = Rng(1);
    let r = run(Params::new(5, 2).unwrap(), &b.build(), &[17], &mut rng).unwrap();
    assert_eq!(r.outputs, vec![mul(17, 17), mul(17, 17) ^ 17, 17]);
    assert_eq!(r.views.len(), 5);
}
