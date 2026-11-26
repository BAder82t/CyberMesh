use cybermesh_sharing::gf256::{inv, mul};
use cybermesh_sharing::{RandomSource, SharingError};

use crate::circuit::{Circuit, Gate, Wire};

/// Failures. None carries secret values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ComputeError {
    #[error("invalid parameters: need 1 <= t, t + 1 <= n <= 255")]
    InvalidParams,
    #[error("multiplication needs n >= 2t + 1 parties, have n = {n}, t = {t}")]
    NeedsHonestMajority { n: usize, t: usize },
    #[error("expected {expected} input values, got {got}")]
    WrongInputCount { expected: usize, got: usize },
    #[error("input owner {0} is not a party")]
    BadOwner(usize),
    #[error("opened shares of output {0} do not lie on a polynomial of degree at most t")]
    Inconsistent(usize),
    #[error("randomness source failed")]
    Randomness,
}

impl From<SharingError> for ComputeError {
    fn from(_: SharingError) -> Self {
        Self::Randomness
    }
}

/// Number of parties and the corruption threshold. Party `j` (1-based) holds the evaluation at
/// the point `j`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    n: usize,
    t: usize,
}

impl Params {
    /// # Errors
    /// [`ComputeError::InvalidParams`] unless `1 <= t` and `t + 1 <= n <= 255`.
    pub fn new(n: usize, t: usize) -> Result<Self, ComputeError> {
        if t == 0 || n < t + 1 || n > 255 {
            return Err(ComputeError::InvalidParams);
        }
        Ok(Self { n, t })
    }
    #[must_use]
    pub fn parties(&self) -> usize {
        self.n
    }
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.t
    }
}

/// What a run cost, counted from the messages the simulation actually exchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Communication rounds: inputs (1), each multiplicative layer (1), the opening (1).
    pub rounds: usize,
    /// Point-to-point messages; each carries one field element (one byte).
    pub messages: usize,
    pub multiplications: usize,
}

/// Result of a simulated run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// The opened output values, in the order the outputs were declared.
    pub outputs: Vec<u8>,
    pub stats: Stats,
    /// What each party received from the others, in order (index 0 is party 1). Lets tests check
    /// what a coalition of corrupt parties sees.
    pub views: Vec<Vec<u8>>,
}

/// Test hooks for deviating parties. Empty in normal runs.
#[derive(Debug, Default, Clone)]
pub(crate) struct Faults {
    /// `(output index, party index 0-based, delta)`: the party opens a wrong share.
    pub(crate) output_delta: Vec<(usize, usize, u8)>,
    /// `(gate index, party index 0-based, delta)`: the party re-shares a wrong product.
    pub(crate) mul_delta: Vec<(usize, usize, u8)>,
}

/// Shares of `secret` for the points `1..=n` from a fresh random polynomial of degree `t`.
fn share<R: RandomSource>(secret: u8, p: Params, rng: &mut R) -> Result<Vec<u8>, ComputeError> {
    let mut coeffs = vec![0u8; p.t];
    rng.fill(&mut coeffs)?;
    Ok((1..=p.n)
        .map(|j| {
            let x = j as u8;
            // secret + c_1 x + c_2 x^2 + ... + c_t x^t, by Horner from the top.
            let mut acc = 0u8;
            for &c in coeffs.iter().rev() {
                acc = mul(acc ^ c, x);
            }
            acc ^ secret
        })
        .collect())
}

/// Lagrange coefficients at 0 for the points `xs`.
fn lagrange_at_zero(xs: &[u8]) -> Vec<u8> {
    xs.iter()
        .enumerate()
        .map(|(i, &xi)| {
            let (mut num, mut den) = (1u8, 1u8);
            for (m, &xm) in xs.iter().enumerate() {
                if m != i {
                    num = mul(num, xm);
                    den = mul(den, xm ^ xi);
                }
            }
            mul(num, inv(den))
        })
        .collect()
}

/// Value at 0 of the polynomial through `(x, y)` points.
fn interpolate_zero(points: &[(u8, u8)]) -> u8 {
    let xs: Vec<u8> = points.iter().map(|p| p.0).collect();
    lagrange_at_zero(&xs)
        .into_iter()
        .zip(points)
        .fold(0, |acc, (l, p)| acc ^ mul(l, p.1))
}

/// Value at `x` of the polynomial through `points`.
fn interpolate_at(points: &[(u8, u8)], x: u8) -> u8 {
    let mut total = 0u8;
    for (i, &(xi, yi)) in points.iter().enumerate() {
        let (mut num, mut den) = (1u8, 1u8);
        for (m, &(xm, _)) in points.iter().enumerate() {
            if m != i {
                num = mul(num, x ^ xm);
                den = mul(den, xi ^ xm);
            }
        }
        total ^= mul(yi, mul(num, inv(den)));
    }
    total
}

/// Open shares: interpolate from the first `t + 1`, require every other share to agree.
fn open(shares: &[u8], p: Params) -> Option<u8> {
    let pts: Vec<(u8, u8)> = shares
        .iter()
        .enumerate()
        .map(|(j, &y)| ((j + 1) as u8, y))
        .collect();
    let base = &pts[..p.t + 1];
    pts[p.t + 1..]
        .iter()
        .all(|&(x, y)| interpolate_at(base, x) == y)
        .then(|| interpolate_zero(base))
}

/// Run `circuit` on `inputs` among `params.parties()` simulated parties.
///
/// # Errors
/// [`ComputeError::NeedsHonestMajority`] for a multiplying circuit with `n < 2t + 1`,
/// [`ComputeError::WrongInputCount`], [`ComputeError::BadOwner`],
/// [`ComputeError::Inconsistent`] if an opened output is not a degree-`t` sharing,
/// [`ComputeError::Randomness`].
pub fn run<R: RandomSource>(
    params: Params,
    circuit: &Circuit,
    inputs: &[u8],
    rng: &mut R,
) -> Result<Run, ComputeError> {
    run_with(params, circuit, inputs, rng, &Faults::default())
}

pub(crate) fn run_with<R: RandomSource>(
    p: Params,
    circuit: &Circuit,
    inputs: &[u8],
    rng: &mut R,
    faults: &Faults,
) -> Result<Run, ComputeError> {
    if circuit.multiplications() > 0 && p.n < 2 * p.t + 1 {
        return Err(ComputeError::NeedsHonestMajority { n: p.n, t: p.t });
    }
    if inputs.len() != circuit.inputs {
        return Err(ComputeError::WrongInputCount {
            expected: circuit.inputs,
            got: inputs.len(),
        });
    }
    let xs: Vec<u8> = (1..=p.n).map(|j| j as u8).collect();
    let lambda = lagrange_at_zero(&xs);
    let mut shares: Vec<Vec<u8>> = Vec::with_capacity(circuit.gates.len());
    let mut depth: Vec<usize> = Vec::with_capacity(circuit.gates.len());
    let mut views: Vec<Vec<u8>> = vec![Vec::new(); p.n];
    let (mut messages, mut mults) = (0usize, 0usize);
    let mut max_depth = 0usize;
    let d = |w: &Wire, depth: &[usize]| depth[w.0];
    for (gi, gate) in circuit.gates.iter().enumerate() {
        let (s, dep) = match *gate {
            Gate::Input { index, owner } => {
                if owner == 0 || owner > p.n {
                    return Err(ComputeError::BadOwner(owner));
                }
                let s = share(inputs[index], p, rng)?;
                for (j, &v) in s.iter().enumerate() {
                    if j + 1 != owner {
                        views[j].push(v);
                    }
                }
                messages += p.n - 1;
                (s, 0)
            }
            Gate::Add(a, b) => (
                shares[a.0]
                    .iter()
                    .zip(&shares[b.0])
                    .map(|(x, y)| x ^ y)
                    .collect(),
                d(&a, &depth).max(d(&b, &depth)),
            ),
            Gate::AddConst(a, c) => (shares[a.0].iter().map(|x| x ^ c).collect(), d(&a, &depth)),
            Gate::MulConst(a, c) => (
                shares[a.0].iter().map(|&x| mul(x, c)).collect(),
                d(&a, &depth),
            ),
            Gate::Mul(a, b) => {
                mults += 1;
                // Local product: a point of a degree-2t polynomial whose value at 0 is the product.
                let h: Vec<u8> = shares[a.0]
                    .iter()
                    .zip(&shares[b.0])
                    .map(|(&x, &y)| mul(x, y))
                    .collect();
                // Every party re-shares its point with a fresh degree-t polynomial.
                let mut sub: Vec<Vec<u8>> = Vec::with_capacity(p.n);
                for (i, &hi) in h.iter().enumerate() {
                    let delta: u8 = faults
                        .mul_delta
                        .iter()
                        .filter(|&&(g, party, _)| g == gi && party == i)
                        .fold(0, |acc, &(_, _, dlt)| acc ^ dlt);
                    sub.push(share(hi ^ delta, p, rng)?);
                }
                // Party j receives sub[i][j] from every i != j and recombines.
                let mut out = vec![0u8; p.n];
                for (j, o) in out.iter_mut().enumerate() {
                    for (i, row) in sub.iter().enumerate() {
                        *o ^= mul(lambda[i], row[j]);
                        if i != j {
                            views[j].push(row[j]);
                        }
                    }
                }
                messages += p.n * (p.n - 1);
                (out, d(&a, &depth).max(d(&b, &depth)) + 1)
            }
        };
        max_depth = max_depth.max(dep);
        shares.push(s);
        depth.push(dep);
    }
    let mut outputs = Vec::with_capacity(circuit.outputs.len());
    for (oi, w) in circuit.outputs.iter().enumerate() {
        let mut opened = shares[w.0].clone();
        for &(o, party, delta) in &faults.output_delta {
            if o == oi && party < p.n {
                opened[party] ^= delta;
            }
        }
        for (j, view) in views.iter_mut().enumerate() {
            for (k, &v) in opened.iter().enumerate() {
                if k != j {
                    view.push(v);
                }
            }
        }
        messages += p.n * (p.n - 1);
        outputs.push(open(&opened, p).ok_or(ComputeError::Inconsistent(oi))?);
    }
    let has_inputs = circuit.inputs > 0;
    let rounds = usize::from(has_inputs) + max_depth + usize::from(!circuit.outputs.is_empty());
    Ok(Run {
        outputs,
        stats: Stats {
            rounds,
            messages,
            multiplications: mults,
        },
        views,
    })
}
