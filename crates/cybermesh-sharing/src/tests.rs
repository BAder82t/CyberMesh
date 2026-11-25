#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use proptest::prelude::*;

const HEADER: usize = super::HEADER;

/// Deterministic xorshift for tests only. NOT secret randomness.
struct TestRng(u64);
impl RandomSource for TestRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), SharingError> {
        for b in buf {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *b = (self.0 >> 24) as u8;
        }
        Ok(())
    }
}
struct Failing;
impl RandomSource for Failing {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), SharingError> {
        Err(SharingError::Randomness)
    }
}
const SET: [u8; 16] = [7; 16];

fn take(v: &[Share], idx: &[usize]) -> Vec<Share> {
    idx.iter()
        .map(|&i| Share::from_bytes(&v[i].to_bytes()).unwrap())
        .collect()
}

#[test]
fn field_axioms() {
    assert_eq!(mul(0x57, 0x83), 0xc1, "FIPS-197 example");
    for a in 1..=255u8 {
        assert_eq!(mul(a, inv(a)), 1, "inverse of {a}");
        assert_eq!(mul(a, 1), a);
        assert_eq!(mul(a, 0), 0);
    }
    assert_eq!(inv(0), 0);
}

#[test]
fn any_k_subset_reconstructs() {
    let secret = b"correct horse battery staple".to_vec();
    let shares = split(&secret, 3, 5, SET, 1, &mut TestRng(1)).unwrap();
    for a in 0..5 {
        for b in a + 1..5 {
            for c in b + 1..5 {
                assert_eq!(reconstruct(&take(&shares, &[a, b, c])).unwrap(), secret);
            }
        }
    }
    assert_eq!(
        reconstruct(&shares).unwrap(),
        secret,
        "all five, cross-checked"
    );
}

#[test]
fn fewer_than_k_fails_and_is_perfectly_hiding() {
    let shares = split(&[42], 3, 4, SET, 1, &mut TestRng(2)).unwrap();
    assert_eq!(
        reconstruct(&take(&shares, &[0, 1])),
        Err(SharingError::TooFewShares { needed: 3, got: 2 })
    );
    // Perfect secrecy, exhaustively for k=2: for a fixed secret, the share at x=5 takes every
    // value exactly once over the 256 choices of the random coefficient.
    let mut hits = [0u32; 256];
    for c in 0..=255u8 {
        hits[usize::from(mul(c, 5) ^ 99)] += 1;
    }
    assert!(hits.iter().all(|&h| h == 1));
    // And for k=3 with two shares known: every candidate secret is consistent with exactly
    // one polynomial (so the two shares leave the secret uniform).
    let (x1, y1, x2, y2) = (1u8, 17u8, 2u8, 200u8);
    let mut consistent = 0;
    for s in 0..=255u8 {
        // Solve c1,c2 from p(x1)=y1,p(x2)=y2 with p(0)=s: c1*x+c2*x^2 = y^s.
        let (r1, r2) = (y1 ^ s, y2 ^ s);
        let det = mul(x1, mul(x2, x2)) ^ mul(x2, mul(x1, x1));
        assert_ne!(det, 0);
        let c1 = mul(inv(det), mul(r1, mul(x2, x2)) ^ mul(r2, mul(x1, x1)));
        let c2 = mul(inv(det), mul(x1, r2) ^ mul(x2, r1));
        assert_eq!(mul(c1, x1) ^ mul(c2, mul(x1, x1)), r1);
        assert_eq!(mul(c1, x2) ^ mul(c2, mul(x2, x2)), r2);
        consistent += 1;
    }
    assert_eq!(consistent, 256);
}

#[test]
fn rejects_bad_parameters_and_randomness_failure() {
    let r = &mut TestRng(3);
    assert_eq!(
        split(b"x", 1, 3, SET, 0, r).unwrap_err(),
        SharingError::InvalidThreshold
    );
    assert_eq!(
        split(b"x", 4, 3, SET, 0, r).unwrap_err(),
        SharingError::InvalidThreshold
    );
    assert_eq!(
        split(b"x", 2, 256, SET, 0, r).unwrap_err(),
        SharingError::InvalidThreshold
    );
    assert_eq!(
        split(b"", 2, 3, SET, 0, r).unwrap_err(),
        SharingError::InvalidSecretLength
    );
    assert_eq!(
        split(b"x", 2, 3, SET, 0, &mut Failing).unwrap_err(),
        SharingError::Randomness
    );
    assert_eq!(reconstruct(&[]).unwrap_err(), SharingError::NoShares);
}

#[test]
fn duplicates_mismatches_and_wrong_shares_fail_closed() {
    let a = split(b"secret!", 2, 4, SET, 1, &mut TestRng(4)).unwrap();
    let dup = vec![
        Share::from_bytes(&a[0].to_bytes()).unwrap(),
        Share::from_bytes(&a[0].to_bytes()).unwrap(),
    ];
    assert_eq!(
        reconstruct(&dup).unwrap_err(),
        SharingError::DuplicateIndex(1)
    );

    let other_epoch = split(b"secret!", 2, 4, SET, 2, &mut TestRng(5)).unwrap();
    let mixed = vec![
        take(&a, &[0])[0].clone_for_test(),
        take(&other_epoch, &[1])[0].clone_for_test(),
    ];
    assert_eq!(reconstruct(&mixed).unwrap_err(), SharingError::Mismatched);

    let other_set = split(b"secret!", 2, 4, [9; 16], 1, &mut TestRng(6)).unwrap();
    let mixed = vec![
        take(&a, &[0])[0].clone_for_test(),
        take(&other_set, &[1])[0].clone_for_test(),
    ];
    assert_eq!(reconstruct(&mixed).unwrap_err(), SharingError::Mismatched);

    // One corrupted share among three is detected, never silently accepted.
    let mut bytes = a[2].to_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let mut three = take(&a, &[0, 1]);
    three.push(Share::from_bytes(&bytes).unwrap());
    assert_eq!(reconstruct(&three).unwrap_err(), SharingError::Inconsistent);
}

impl Share {
    fn clone_for_test(&self) -> Self {
        Self::from_bytes(&self.to_bytes()).unwrap()
    }
}

#[test]
fn wire_format_is_strict_and_debug_is_redacted() {
    let s = split(b"hide me", 2, 3, SET, 9, &mut TestRng(7)).unwrap();
    let b = s[0].to_bytes();
    assert_eq!(Share::from_bytes(&b).unwrap(), s[0]);
    assert!(Share::from_bytes(&b[..b.len() - 1]).is_err(), "truncated");
    let mut long = b.clone();
    long.push(0);
    assert!(Share::from_bytes(&long).is_err(), "trailing byte");
    let mut v = b.clone();
    v[0] = 2;
    assert!(Share::from_bytes(&v).is_err(), "unknown version");
    let mut z = b.clone();
    z[22] = 0;
    assert_eq!(Share::from_bytes(&z).unwrap_err(), SharingError::ZeroIndex);
    let mut huge = b;
    huge[23..27].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(
        Share::from_bytes(&huge).is_err(),
        "declared length beyond bound"
    );
    assert!(!format!("{:?}", s[0]).contains("hide"));
    assert!(format!("{:?}", s[0]).contains("len"));
}

proptest! {
    #[test]
    fn roundtrip(secret in proptest::collection::vec(any::<u8>(), 1..64),
                 n in 2usize..12, seed in any::<u64>(), pick in any::<u64>()) {
        let k = 2 + (pick as usize) % (n - 1);
        let shares = split(&secret, k, n, SET, 3, &mut TestRng(seed | 1)).unwrap();
        // a pseudo-random k-subset
        let mut idx: Vec<usize> = (0..n).collect();
        let mut p = pick | 1;
        for i in (1..n).rev() { p = p.wrapping_mul(6364136223846793005).wrapping_add(1); idx.swap(i, (p >> 33) as usize % (i + 1)); }
        idx.truncate(k);
        prop_assert_eq!(reconstruct(&take(&shares, &idx)).unwrap(), secret);
    }
}

fn corrupt(v: &[Share], bad: &[usize], salt: u8) -> Vec<Share> {
    v.iter()
        .enumerate()
        .map(|(i, s)| {
            let mut b = s.to_bytes();
            if bad.contains(&i) {
                for (j, byte) in b[HEADER..].iter_mut().enumerate() {
                    *byte ^= salt.wrapping_add(j as u8).wrapping_mul(37) | 1;
                }
            }
            Share::from_bytes(&b).unwrap()
        })
        .collect()
}

#[test]
fn robust_corrects_every_placement_up_to_the_bound() {
    // n = 7, k = 3, all given: e = 2. Every pair of wrong shares is corrected and named.
    let secret = b"robust secret".to_vec();
    let shares = split(&secret, 3, 7, SET, 1, &mut TestRng(11)).unwrap();
    for a in 0..7 {
        for b in a..7 {
            let bad: Vec<usize> = if a == b { vec![a] } else { vec![a, b] };
            let r = reconstruct_robust(&corrupt(&shares, &bad, 5 + a as u8)).unwrap();
            assert_eq!(r.secret, secret, "bad {bad:?}");
            let want: Vec<u8> = bad.iter().map(|&i| shares[i].index()).collect();
            assert_eq!(r.corrupted, want);
        }
    }
    let clean = reconstruct_robust(&shares).unwrap();
    assert_eq!(clean.secret, secret);
    assert!(clean.corrupted.is_empty());
}

#[test]
fn robust_respects_the_reed_solomon_bound_with_missing_shares() {
    // n = 9, k = 3. Drop s = 2 shares, so m = 7 and e = 2: 2e + s = 6 <= n - k = 6.
    let secret = vec![1, 2, 3, 250];
    let shares = split(&secret, 3, 9, SET, 4, &mut TestRng(12)).unwrap();
    let given: Vec<Share> = take(&shares, &[0, 2, 3, 4, 6, 7, 8]);
    let r = reconstruct_robust(&corrupt(&given, &[1, 5], 9)).unwrap();
    assert_eq!(r.secret, secret);
    assert_eq!(r.corrupted.len(), 2);
}

#[test]
fn robust_corrects_a_share_wrong_in_one_byte_only() {
    let secret = b"abcdef".to_vec();
    let shares = split(&secret, 2, 5, SET, 1, &mut TestRng(13)).unwrap();
    let mut bytes = shares[3].to_bytes();
    bytes[HEADER + 2] ^= 0x40;
    let mut v = take(&shares, &[0, 1, 2]);
    v.push(Share::from_bytes(&bytes).unwrap());
    v.push(take(&shares, &[4]).remove(0));
    let r = reconstruct_robust(&v).unwrap();
    assert_eq!(r.secret, secret);
    assert_eq!(r.corrupted, vec![shares[3].index()]);
}

#[test]
fn robust_fails_closed_beyond_the_bound_and_on_bad_input() {
    // n = 5, k = 3: e = 1. Two wrong shares exceed the bound.
    let secret = b"beyond".to_vec();
    let shares = split(&secret, 3, 5, SET, 1, &mut TestRng(14)).unwrap();
    let mut returned_wrong = 0;
    for a in 0..5 {
        for b in a + 1..5 {
            match reconstruct_robust(&corrupt(&shares, &[a, b], 3)) {
                Err(SharingError::TooManyErrors { limit }) => assert_eq!(limit, 1),
                Ok(r) if r.secret == secret => panic!("cannot have corrected {a},{b}"),
                Ok(_) => returned_wrong += 1,
                Err(e) => panic!("{e}"),
            }
        }
    }
    // Past the bound a wrong secret is possible and silent (documented). Pin the measured
    // count for this fixed seed so a decoder change is noticed.
    assert_eq!(returned_wrong, 6, "past-bound wrong decodes of 10 pairs");
    assert_eq!(max_correctable(5, 3), 1);
    assert_eq!(max_correctable(2, 3), 0);
    assert_eq!(
        reconstruct_robust(&take(&shares, &[0, 1])).unwrap_err(),
        SharingError::TooFewShares { needed: 3, got: 2 }
    );
    assert_eq!(reconstruct_robust(&[]).unwrap_err(), SharingError::NoShares);
    let dup = vec![take(&shares, &[0]).remove(0), take(&shares, &[0]).remove(0)];
    assert_eq!(
        reconstruct_robust(&dup).unwrap_err(),
        SharingError::DuplicateIndex(1)
    );
}

proptest! {
    #[test]
    fn robust_roundtrip(secret in proptest::collection::vec(any::<u8>(), 1..24),
                        k in 2usize..5, extra in 0usize..6, seed in any::<u64>(),
                        pick in any::<u64>(), salt in any::<u8>()) {
        let n = k + extra;
        let e = (n - k) / 2;
        let shares = split(&secret, k, n, SET, 2, &mut TestRng(seed | 1)).unwrap();
        let mut idx: Vec<usize> = (0..n).collect();
        let mut p = pick | 1;
        for i in (1..n).rev() { p = p.wrapping_mul(6364136223846793005).wrapping_add(1); idx.swap(i, (p >> 33) as usize % (i + 1)); }
        idx.truncate(e);
        let r = reconstruct_robust(&corrupt(&shares, &idx, salt)).unwrap();
        prop_assert_eq!(&r.secret, &secret);
        prop_assert_eq!(r.corrupted.len(), idx.len());
    }
}

// ---- proactive refresh ----------------------------------------------------------------------

fn refresh_all(shares: &[Share], dealers: usize, seed: u64) -> Vec<Share> {
    let k = usize::from(shares[0].threshold());
    let idx: Vec<u8> = shares.iter().map(Share::index).collect();
    let mut rng = TestRng(seed | 1);
    let per_dealer: Vec<Vec<Delta>> = (0..dealers)
        .map(|_| {
            zero_sharing(k, &idx, shares[0].y.len(), SET, shares[0].epoch(), &mut rng).unwrap()
        })
        .collect();
    shares
        .iter()
        .enumerate()
        .map(|(h, s)| {
            let mine: Vec<Delta> = per_dealer
                .iter()
                .map(|d| Delta::from_bytes(&d[h].to_bytes()).unwrap())
                .collect();
            refresh_share(s, &mine).unwrap()
        })
        .collect()
}

#[test]
fn refresh_keeps_the_secret_changes_the_shares_and_steps_the_epoch() {
    let secret = b"long lived secret".to_vec();
    let old = split(&secret, 3, 5, SET, 7, &mut TestRng(21)).unwrap();
    let new = refresh_all(&old, 3, 22);
    assert!(new.iter().all(|s| s.epoch() == 8));
    assert_eq!(reconstruct(&new).unwrap(), secret);
    for (o, n) in old.iter().zip(&new) {
        assert_ne!(o.y, n.y, "share {} must change", o.index());
    }
    // Refresh again, and with a different number of dealers: still the same secret.
    let newer = refresh_all(&new, 1, 23);
    assert_eq!(reconstruct(&newer).unwrap(), secret);
    assert_eq!(newer[0].epoch(), 9);
    // Robust decoding still works on refreshed shares.
    let bad = corrupt(&newer, &[1], 5);
    assert_eq!(reconstruct_robust(&bad).unwrap().secret, secret);
}

#[test]
fn old_and_new_epochs_never_combine() {
    let old = split(b"abc", 2, 4, SET, 1, &mut TestRng(24)).unwrap();
    let new = refresh_all(&old, 2, 25);
    let mixed = vec![old[0].clone_for_test(), new[1].clone_for_test()];
    assert_eq!(reconstruct(&mixed).unwrap_err(), SharingError::Mismatched);
    assert_eq!(
        reconstruct_robust(&mixed).unwrap_err(),
        SharingError::Mismatched
    );
}

#[test]
fn shares_from_before_and_after_a_refresh_reveal_nothing_together() {
    // k = 2: an adversary holds holder 1's OLD share and holder 2's NEW share (the label check
    // would stop it combining them, so we model the strongest case: it ignores labels).
    // For a fixed secret the pair of raw values takes every one of the 65,536 combinations
    // exactly once as the dealing randomness (a1, d1) varies, so the pair is independent of the
    // secret.
    let pair_set = |s: u8| {
        let mut seen = vec![false; 1 << 16];
        for a1 in 0..=255u8 {
            for d1 in 0..=255u8 {
                let old1 = s ^ mul(a1, 1);
                let new2 = (s ^ mul(a1, 2)) ^ mul(d1, 2); // old share at x=2 plus delta at x=2
                seen[usize::from(old1) << 8 | usize::from(new2)] = true;
            }
        }
        seen.iter().filter(|&&b| b).count()
    };
    assert_eq!(pair_set(0), 65_536);
    assert_eq!(pair_set(77), 65_536);
}

#[test]
fn a_dishonest_dealer_silently_changes_the_secret() {
    // Documented limit: plain sharing cannot tell. The dealer shares a non-zero constant.
    let secret = vec![10, 20, 30];
    let old = split(&secret, 2, 3, SET, 1, &mut TestRng(26)).unwrap();
    let idx: Vec<u8> = old.iter().map(Share::index).collect();
    let evil: Vec<Delta> = deal(&[1, 1, 1], 2, &idx, SET, 1, &mut TestRng(27))
        .unwrap()
        .into_iter()
        .map(Delta)
        .collect();
    let new: Vec<Share> = old
        .iter()
        .zip(&evil)
        .map(|(s, d)| refresh_share(s, std::slice::from_ref(d)).unwrap())
        .collect();
    let got = reconstruct(&new).unwrap();
    assert_eq!(
        got,
        vec![10 ^ 1, 20 ^ 1, 30 ^ 1],
        "secret shifted, no error raised"
    );
    assert_ne!(got, secret);
}

#[test]
fn refresh_rejects_wrong_or_mismatched_deltas() {
    let old = split(b"xyz", 2, 3, SET, 5, &mut TestRng(28)).unwrap();
    let idx: Vec<u8> = old.iter().map(Share::index).collect();
    let good = zero_sharing(2, &idx, 3, SET, 5, &mut TestRng(29)).unwrap();
    assert_eq!(
        refresh_share(&old[0], &[]).unwrap_err(),
        SharingError::NoShares
    );
    // Delta for another holder.
    assert_eq!(
        refresh_share(&old[0], std::slice::from_ref(&good[1])).unwrap_err(),
        SharingError::Mismatched
    );
    // Wrong epoch, set, threshold, length.
    let w = |k, len, set, ep| zero_sharing(k, &idx, len, set, ep, &mut TestRng(30)).unwrap();
    for bad in [
        w(2, 3, SET, 4),
        w(2, 3, [1; 16], 5),
        w(3, 3, SET, 5),
        w(2, 4, SET, 5),
    ] {
        assert_eq!(
            refresh_share(&old[0], std::slice::from_ref(&bad[0])).unwrap_err(),
            SharingError::Mismatched
        );
    }
    // Epoch counter cannot wrap around.
    let top = split(b"x", 2, 3, SET, u32::MAX, &mut TestRng(31)).unwrap();
    let d = zero_sharing(2, &idx, 1, SET, u32::MAX, &mut TestRng(32)).unwrap();
    assert_eq!(
        refresh_share(&top[0], std::slice::from_ref(&d[0])).unwrap_err(),
        SharingError::EpochOverflow
    );
    // Bad dealing parameters.
    assert!(zero_sharing(1, &idx, 3, SET, 0, &mut TestRng(1)).is_err());
    assert!(zero_sharing(2, &[1, 1, 2], 3, SET, 0, &mut TestRng(1)).is_err());
    assert!(zero_sharing(2, &[0, 1, 2], 3, SET, 0, &mut TestRng(1)).is_err());
    assert!(zero_sharing(2, &idx, 0, SET, 0, &mut TestRng(1)).is_err());
    assert!(zero_sharing(2, &idx, 3, SET, 0, &mut Failing).is_err());
}

#[test]
fn deltas_and_shares_cannot_be_confused_on_the_wire() {
    let old = split(b"wire", 2, 3, SET, 1, &mut TestRng(33)).unwrap();
    let idx: Vec<u8> = old.iter().map(Share::index).collect();
    let d = zero_sharing(2, &idx, 4, SET, 1, &mut TestRng(34)).unwrap();
    assert_eq!(Delta::from_bytes(&d[0].to_bytes()).unwrap(), d[0]);
    assert!(
        Share::from_bytes(&d[0].to_bytes()).is_err(),
        "delta parsed as share"
    );
    assert!(
        Delta::from_bytes(&old[0].to_bytes()).is_err(),
        "share parsed as delta"
    );
    assert!(Delta::from_bytes(&[]).is_err());
    assert!(!format!("{:?}", d[0]).contains("y:"));
}

proptest! {
    #[test]
    fn refresh_roundtrip(secret in proptest::collection::vec(any::<u8>(), 1..24),
                         k in 2usize..5, extra in 0usize..5, dealers in 1usize..4,
                         seed in any::<u64>(), rounds in 1usize..4) {
        let n = k + extra;
        let mut shares = split(&secret, k, n, SET, 0, &mut TestRng(seed | 1)).unwrap();
        for r in 0..rounds {
            shares = refresh_all(&shares, dealers, seed.wrapping_add(r as u64));
        }
        prop_assert_eq!(shares[0].epoch(), rounds as u32);
        prop_assert_eq!(reconstruct(&shares).unwrap(), secret.clone());
        // Any k of them suffice.
        prop_assert_eq!(reconstruct(&take(&shares, &(0..k).collect::<Vec<_>>())).unwrap(), secret);
    }
}
