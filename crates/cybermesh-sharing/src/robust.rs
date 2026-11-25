//! Error-correcting reconstruction: Berlekamp-Welch over GF(2^8), per secret byte.
//!
//! The shares of one sharing are points of a degree `< k` polynomial per byte, that is a
//! Reed-Solomon codeword. With `m` shares given out of the `n` issued, `s = n - m` are missing
//! (erasures) and up to `e` of the given ones may be wrong when `2e + s <= n - k`, which is
//! `2e <= m - k`. Beyond that bound the decoder does not promise anything: a corrupted set can
//! lie within the radius of a different polynomial and then decodes to the wrong secret. Callers
//! that need to detect that must authenticate shares separately.
//!
//! Variable-time on secret data (Gaussian elimination); no timing claim is made.

use zeroize::Zeroize;

use crate::{Share, SharingError, inv, mul, validate};

/// A successfully decoded secret and the shares that were found wrong.
pub struct Recovered {
    /// The reconstructed secret.
    pub secret: Vec<u8>,
    /// Indexes of shares that disagreed with the decoded polynomial in at least one byte.
    pub corrupted: Vec<u8>,
}

impl core::fmt::Debug for Recovered {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Recovered")
            .field("secret_len", &self.secret.len())
            .field("corrupted", &self.corrupted)
            .finish()
    }
}

impl Drop for Recovered {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Evaluate a polynomial (low degree first) at `x`.
fn eval(p: &[u8], x: u8) -> u8 {
    p.iter().rev().fold(0, |acc, &c| mul(acc, x) ^ c)
}

/// Solve `A z = b` over GF(2^8) by elimination. Free variables are set to 0.
/// `None` if the system is inconsistent.
fn solve(mut a: Vec<Vec<u8>>, cols: usize) -> Option<Vec<u8>> {
    let rows = a.len();
    let mut pivots = Vec::new();
    let mut r = 0;
    for c in 0..cols {
        let Some(p) = (r..rows).find(|&i| a[i][c] != 0) else {
            continue;
        };
        a.swap(r, p);
        let f = inv(a[r][c]);
        for v in &mut a[r] {
            *v = mul(*v, f);
        }
        let pivot_row = a[r].clone();
        for (i, row) in a.iter_mut().enumerate() {
            if i != r && row[c] != 0 {
                let m = row[c];
                for (dst, &src) in row.iter_mut().zip(&pivot_row) {
                    *dst ^= mul(m, src);
                }
            }
        }
        pivots.push(c);
        r += 1;
    }
    // A row `0 = nonzero` means no solution.
    if a.iter().skip(r).any(|row| row[cols] != 0) {
        return None;
    }
    let mut z = vec![0u8; cols];
    for (row, &c) in pivots.iter().enumerate() {
        z[c] = a[row][cols];
    }
    Some(z)
}

/// Decode one byte position: the unique polynomial of degree `< k` within `e` errors of the
/// points, or `None`.
fn decode_byte(xs: &[u8], ys: &[u8], k: usize, e: usize) -> Option<Vec<u8>> {
    // Unknowns: Q (e + k coefficients) and E's low coefficients (E is monic of degree e).
    // Q(x_i) = y_i * E(x_i)  =>  Q(x_i) + y_i * sum_{j<e} E_j x_i^j = y_i * x_i^e.
    let cols = 2 * e + k;
    let rows: Vec<Vec<u8>> = xs
        .iter()
        .zip(ys)
        .map(|(&x, &y)| {
            let mut row = Vec::with_capacity(cols + 1);
            let mut pw = 1u8;
            let mut powers = Vec::with_capacity(e + k + 1);
            for _ in 0..=(e + k) {
                powers.push(pw);
                pw = mul(pw, x);
            }
            row.extend_from_slice(&powers[..e + k]);
            row.extend(powers[..e].iter().map(|&p| mul(y, p)));
            row.push(mul(y, powers[e]));
            row
        })
        .collect();
    let z = solve(rows, cols)?;
    let q = &z[..e + k];
    let mut err_loc: Vec<u8> = z[e + k..].to_vec();
    err_loc.push(1);
    // Long division Q / E, highest degree first.
    let mut rem = q.to_vec();
    let mut quot = vec![0u8; k];
    for d in (0..=(q.len().checked_sub(err_loc.len())?)).rev() {
        let c = rem[d + e];
        if d < k {
            quot[d] = c;
        } else if c != 0 {
            return None;
        }
        for (j, &ej) in err_loc.iter().enumerate() {
            rem[d + j] ^= mul(c, ej);
        }
    }
    if rem.iter().any(|&v| v != 0) {
        return None;
    }
    // The decoded polynomial must agree with all but at most e points.
    let bad = xs
        .iter()
        .zip(ys)
        .filter(|&(&x, &y)| eval(&quot, x) != y)
        .count();
    (bad <= e).then_some(quot)
}

/// How many wrong shares [`reconstruct_robust`] corrects when `m` shares of a `k`-threshold
/// sharing are given: `(m - k) / 2`. Zero if `m <= k`.
#[must_use]
pub fn max_correctable(m: usize, k: usize) -> usize {
    m.saturating_sub(k) / 2
}

/// Reconstruct the secret even if some of the given shares are wrong.
///
/// Corrects up to `e = (m - k) / 2` wrong shares among the `m` given (missing shares need no
/// special handling: they are simply not given). Returns the secret and which shares were wrong.
///
/// **Past the bound the result can be wrong without any error**: a corrupted set may lie within
/// the decoding radius of a different polynomial. The caller must keep the number of wrong shares
/// within [`max_correctable`] by other means (authentication, trusted holders).
///
/// # Errors
/// The checks of [`crate::reconstruct`], plus [`SharingError::TooManyErrors`] when no polynomial
/// lies within the correctable distance.
pub fn reconstruct_robust(shares: &[Share]) -> Result<Recovered, SharingError> {
    let (first, k) = validate(shares)?;
    let m = shares.len();
    if m < k {
        return Err(SharingError::TooFewShares { needed: k, got: m });
    }
    let e = max_correctable(m, k);
    let xs: Vec<u8> = shares.iter().map(|s| s.index).collect();
    let mut secret = vec![0u8; first.y.len()];
    let mut corrupted = vec![false; m];
    for (pos, out) in secret.iter_mut().enumerate() {
        let ys: Vec<u8> = shares.iter().map(|s| s.y[pos]).collect();
        let Some(poly) = decode_byte(&xs, &ys, k, e) else {
            secret.zeroize();
            return Err(SharingError::TooManyErrors { limit: e });
        };
        *out = poly[0];
        for (i, (&x, &y)) in xs.iter().zip(&ys).enumerate() {
            corrupted[i] |= eval(&poly, x) != y;
        }
    }
    let corrupted = shares
        .iter()
        .zip(&corrupted)
        .filter(|&(_, &c)| c)
        .map(|(s, _)| s.index)
        .collect();
    Ok(Recovered { secret, corrupted })
}
