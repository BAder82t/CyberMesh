//! Shamir threshold secret sharing over GF(2^8) (EXPERIMENTAL, unaudited).
//!
//! Part of the CyberMesh Trust Fabric. The security claim is the classical one and nothing
//! more: with `k` of `n` shares a secret is recovered exactly, and any `k - 1` shares are
//! statistically independent of it (perfect secrecy), for an adversary with unbounded
//! computation. That holds only if:
//!
//! * the polynomial coefficients are fresh, uniform and secret ([`RandomSource`] is the caller's
//!   responsibility: a deterministic or short-seeded source gives no such guarantee);
//! * fewer than `k` holders collude, and shares travel over private channels;
//! * obsolete shares are erased (this crate zeroizes on drop but cannot prove erasure).
//!
//! Plain Shamir sharing is **not verifiable**: a wrong share is not detected on its own.
//! [`reconstruct`] therefore interpolates from `k` shares and checks every extra share against
//! the result, failing closed on any disagreement. It cannot say *which* share is wrong;
//! [`reconstruct_robust`] additionally corrects wrong shares (Berlekamp-Welch).
//!
//! The field is GF(2^8) with the AES polynomial; each secret byte is shared independently, so
//! `n <= 255`. Arithmetic is branch-free on secret data.

#![forbid(unsafe_code)]

use zeroize::Zeroize;

/// Maximum number of shares: the non-zero elements of GF(2^8).
pub const MAX_SHARES: usize = 255;
/// Maximum secret length in bytes (bounds memory use).
pub const MAX_SECRET_LEN: usize = 1 << 20;

/// Failures. None carries secret material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SharingError {
    #[error("invalid threshold: need 2 <= k <= n <= {MAX_SHARES}")]
    InvalidThreshold,
    #[error("secret is empty or longer than {MAX_SECRET_LEN} bytes")]
    InvalidSecretLength,
    #[error("randomness source failed")]
    Randomness,
    #[error("no shares given")]
    NoShares,
    #[error("share index 0 is not allowed")]
    ZeroIndex,
    #[error("duplicate share index {0}")]
    DuplicateIndex(u8),
    #[error("shares disagree on the set, epoch, threshold or length")]
    Mismatched,
    #[error("malformed share")]
    Malformed,
    #[error("need {needed} shares, got {got}")]
    TooFewShares { needed: usize, got: usize },
    #[error("shares are inconsistent: at least one is wrong")]
    Inconsistent,
    #[error("epoch counter would overflow")]
    EpochOverflow,
    #[error("more wrong shares than the {limit} correctable with the shares given")]
    TooManyErrors { limit: usize },
}

/// Where the polynomial coefficients come from. Must yield uniform secret randomness.
pub trait RandomSource {
    /// Fill `buf` with fresh uniform bytes.
    ///
    /// # Errors
    /// Fails if the source cannot supply entropy; sharing then fails closed.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), SharingError>;
}

/// Operating-system randomness (computational CSPRNG seeded by the OS). It is the right source
/// for local coefficient generation; it is not "shared secret randomness" between parties.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), SharingError> {
        getrandom::fill(buf).map_err(|_| SharingError::Randomness)
    }
}

/// One share. Secret material: zeroized on drop, `Debug` redacted, deliberately not `Clone`
/// or `Serialize`; use [`Share::to_bytes`] to move it on purpose.
#[derive(PartialEq, Eq)]
pub struct Share {
    set: [u8; 16],
    epoch: u32,
    threshold: u8,
    index: u8,
    y: Vec<u8>,
}

impl Drop for Share {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Share")
            .field("index", &self.index)
            .field("epoch", &self.epoch)
            .field("threshold", &self.threshold)
            .field("len", &self.y.len())
            .finish_non_exhaustive()
    }
}

pub(crate) const WIRE_VERSION: u8 = 1;
pub(crate) const HEADER: usize = 1 + 16 + 4 + 1 + 1 + 4;

impl Share {
    /// This share's evaluation point (1..=255).
    #[must_use]
    pub fn index(&self) -> u8 {
        self.index
    }
    /// Epoch (generation) of the sharing. Shares of different epochs never combine.
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
    /// Reconstruction threshold.
    #[must_use]
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Versioned wire encoding: version, set id, epoch, k, index, length, bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + self.y.len());
        out.push(WIRE_VERSION);
        out.extend_from_slice(&self.set);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.push(self.threshold);
        out.push(self.index);
        out.extend_from_slice(
            &u32::try_from(self.y.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.y);
        out
    }

    /// Strict decoding: exact length, known version, valid index and threshold.
    ///
    /// # Errors
    /// [`SharingError::Malformed`] or [`SharingError::ZeroIndex`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, SharingError> {
        if b.len() < HEADER || b[0] != WIRE_VERSION {
            return Err(SharingError::Malformed);
        }
        let mut set = [0u8; 16];
        set.copy_from_slice(&b[1..17]);
        let epoch = u32::from_be_bytes([b[17], b[18], b[19], b[20]]);
        let (threshold, index) = (b[21], b[22]);
        let len = u32::from_be_bytes([b[23], b[24], b[25], b[26]]) as usize;
        if len == 0 || len > MAX_SECRET_LEN || b.len() != HEADER + len || threshold < 2 {
            return Err(SharingError::Malformed);
        }
        if index == 0 {
            return Err(SharingError::ZeroIndex);
        }
        Ok(Self {
            set,
            epoch,
            threshold,
            index,
            y: b[HEADER..].to_vec(),
        })
    }
}

// ---- GF(2^8), polynomial x^8 + x^4 + x^3 + x + 1 -------------------------------------------

/// Branch-free multiplication.
pub(crate) fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a & 0u8.wrapping_sub(b & 1);
        let carry = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1b & carry);
        b >>= 1;
    }
    p
}

/// a^254 = a^-1 for a != 0 (and 0 for 0).
pub(crate) fn inv(a: u8) -> u8 {
    let a2 = mul(a, a);
    let a4 = mul(a2, a2);
    let a8 = mul(a4, a4);
    let a16 = mul(a8, a8);
    let a32 = mul(a16, a16);
    let a64 = mul(a32, a32);
    let a128 = mul(a64, a64);
    // 254 = 128+64+32+16+8+4+2
    mul(mul(mul(mul(mul(mul(a128, a64), a32), a16), a8), a4), a2)
}

/// Split `secret` into `n` shares, any `k` of which reconstruct it.
///
/// `set` identifies this sharing and `epoch` its generation; both are public labels bound to
/// every share so unrelated or stale shares are refused at reconstruction.
///
/// # Errors
/// Invalid `k`/`n`, empty or oversized secret, or a randomness failure.
pub fn split<R: RandomSource>(
    secret: &[u8],
    k: usize,
    n: usize,
    set: [u8; 16],
    epoch: u32,
    rng: &mut R,
) -> Result<Vec<Share>, SharingError> {
    if k < 2 || k > n || n > MAX_SHARES {
        return Err(SharingError::InvalidThreshold);
    }
    // 1..=255 by the check above.
    let indices: Vec<u8> = (1..=u8::try_from(n).unwrap_or(u8::MAX)).collect();
    deal(secret, k, &indices, set, epoch, rng)
}

/// Evaluate a fresh random degree-`k-1` polynomial with constant term `secret` at `indices`.
fn deal<R: RandomSource>(
    secret: &[u8],
    k: usize,
    indices: &[u8],
    set: [u8; 16],
    epoch: u32,
    rng: &mut R,
) -> Result<Vec<Share>, SharingError> {
    if k < 2 || k > indices.len() || indices.len() > MAX_SHARES {
        return Err(SharingError::InvalidThreshold);
    }
    if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
        return Err(SharingError::InvalidSecretLength);
    }
    let mut seen = [false; 256];
    for &i in indices {
        if i == 0 {
            return Err(SharingError::ZeroIndex);
        }
        if core::mem::replace(&mut seen[usize::from(i)], true) {
            return Err(SharingError::DuplicateIndex(i));
        }
    }
    let mut shares: Vec<Share> = indices
        .iter()
        .map(|&index| Share {
            set,
            epoch,
            // k <= indices.len() <= 255 checked above
            threshold: u8::try_from(k).unwrap_or(u8::MAX),
            index,
            y: vec![0; secret.len()],
        })
        .collect();
    let mut coeffs = vec![0u8; k - 1];
    for (pos, &s) in secret.iter().enumerate() {
        rng.fill(&mut coeffs)?;
        for share in &mut shares {
            // Horner: ((c_{k-1} x + ... + c_1) x + s)
            let mut acc = 0u8;
            for &c in coeffs.iter().rev() {
                acc = mul(acc ^ c, share.index);
            }
            share.y[pos] = acc ^ s;
        }
    }
    coeffs.zeroize();
    Ok(shares)
}

fn lagrange_at_zero(points: &[&Share], pos: usize) -> u8 {
    let mut total = 0u8;
    for (j, sj) in points.iter().enumerate() {
        let mut num = 1u8;
        let mut den = 1u8;
        for (m, sm) in points.iter().enumerate() {
            if m != j {
                num = mul(num, sm.index);
                den = mul(den, sm.index ^ sj.index);
            }
        }
        total ^= mul(sj.y[pos], mul(num, inv(den)));
    }
    total
}

/// Checks labels, indexes and duplicates; returns the first share and the threshold.
fn validate(shares: &[Share]) -> Result<(&Share, usize), SharingError> {
    let first = shares.first().ok_or(SharingError::NoShares)?;
    let mut seen = [false; 256];
    for s in shares {
        if s.index == 0 {
            return Err(SharingError::ZeroIndex);
        }
        if s.set != first.set
            || s.epoch != first.epoch
            || s.threshold != first.threshold
            || s.y.len() != first.y.len()
        {
            return Err(SharingError::Mismatched);
        }
        if core::mem::replace(&mut seen[usize::from(s.index)], true) {
            return Err(SharingError::DuplicateIndex(s.index));
        }
    }
    Ok((first, usize::from(first.threshold)))
}

/// Reconstruct the secret.
///
/// Uses the first `k` shares, then checks every further share lies on the same polynomial.
///
/// # Errors
/// Mixed sets/epochs/thresholds, duplicates, too few shares, or [`SharingError::Inconsistent`]
/// when any share disagrees (the secret is then not returned).
pub fn reconstruct(shares: &[Share]) -> Result<Vec<u8>, SharingError> {
    let (first, k) = validate(shares)?;
    if shares.len() < k {
        return Err(SharingError::TooFewShares {
            needed: k,
            got: shares.len(),
        });
    }
    let base: Vec<&Share> = shares.iter().take(k).collect();
    let mut secret = vec![0u8; first.y.len()];
    for (pos, out) in secret.iter_mut().enumerate() {
        *out = lagrange_at_zero(&base, pos);
    }
    // Every extra share must agree with the polynomial through the first k.
    for extra in shares.iter().skip(k) {
        for pos in 0..secret.len() {
            if !same_poly(&base, extra, pos) {
                secret.zeroize();
                return Err(SharingError::Inconsistent);
            }
        }
    }
    Ok(secret)
}

/// Does `extra` lie on the polynomial interpolated through `base` at byte `pos`?
fn same_poly(base: &[&Share], extra: &Share, pos: usize) -> bool {
    let x = extra.index;
    let mut acc = 0u8;
    for (j, sj) in base.iter().enumerate() {
        let mut num = 1u8;
        let mut den = 1u8;
        for (m, sm) in base.iter().enumerate() {
            if m != j {
                num = mul(num, x ^ sm.index);
                den = mul(den, sj.index ^ sm.index);
            }
        }
        acc ^= mul(sj.y[pos], mul(num, inv(den)));
    }
    acc == extra.y[pos]
}

/// GF(2^8) arithmetic (polynomial `x^8 + x^4 + x^3 + x + 1`), exposed so protocols built on these
/// shares compute in the same field. Addition and subtraction are both XOR.
pub mod gf256 {
    /// Product, without secret-dependent branches.
    #[must_use]
    pub fn mul(a: u8, b: u8) -> u8 {
        super::mul(a, b)
    }
    /// Multiplicative inverse; `inv(0)` is 0.
    #[must_use]
    pub fn inv(a: u8) -> u8 {
        super::inv(a)
    }
}

mod refresh;
mod robust;
pub use refresh::{Delta, refresh_share, zero_sharing};
pub use robust::{Recovered, max_correctable, reconstruct_robust};

#[cfg(test)]
mod tests;
