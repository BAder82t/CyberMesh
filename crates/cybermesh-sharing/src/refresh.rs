//! Proactive refresh (Herzberg-Jarecki-Krawczyk-Yung): new shares of the same secret.
//!
//! A *dealer* shares zero: a random polynomial of degree `< k` with constant term 0, evaluated at
//! each holder's index. Each holder adds the deltas it receives to its share. The sum is a share
//! of the same secret on a new random polynomial, labelled with the next epoch. Shares of
//! different epochs never combine, so what an adversary learned from fewer than `k` shares in an
//! earlier epoch does not add up with what it learns in a later one (the mobile-adversary model).
//!
//! Herzberg et al. (CRYPTO 1995, Section 3.3) describe this renewal. Their **full scheme is
//! computational**: it assumes a broadcast channel, a synchronous clock, a bounded adversary,
//! signatures and encryption, a verifiable secret sharing (Feldman or Pedersen), erasure and
//! `k < n/2` per period. Only the bare renewal step is information-theoretic, and only if the
//! sub-shares are delivered perfectly secretly. This module is **the bare renewal only**: none of
//! their detection of wrong shares or their recovery protocol (see
//! `docs/trust-fabric/literature-review.md`, `herzberg1995proactive`).
//!
//! Assumptions this does NOT discharge, and which the caller must supply:
//!
//! * **Honest dealers.** Plain sharing is not verifiable. A dealer that shares a non-zero
//!   polynomial silently changes the secret (the tests show it), and the result still looks
//!   consistent. Detecting that needs verifiable secret sharing, which is not built here and
//!   which in the unconditional setting needs its own honest-majority assumptions.
//! * **Private, authenticated channels** for the deltas, and agreement among holders on exactly
//!   which deltas to add (a holder that misses one is out of step with the others).
//! * **Erasure** of the old share and of the deltas after the epoch step.
//! * Fresh uniform randomness for every dealing ([`crate::RandomSource`]).

use crate::{HEADER, MAX_SHARES, RandomSource, Share, SharingError, WIRE_VERSION, deal};

const DELTA_VERSION: u8 = 0x11;

/// One dealer's share of zero for one holder, to be added to that holder's share.
/// Secret material: zeroized on drop and redacted in `Debug`, like [`Share`].
#[derive(PartialEq, Eq)]
pub struct Delta(pub(crate) Share);

impl core::fmt::Debug for Delta {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Delta")
            .field("index", &self.0.index)
            .field("applies_to_epoch", &self.0.epoch)
            .finish_non_exhaustive()
    }
}

impl Delta {
    /// The holder this delta is for.
    #[must_use]
    pub fn index(&self) -> u8 {
        self.0.index
    }
    /// The epoch of the shares it can be added to.
    #[must_use]
    pub fn applies_to_epoch(&self) -> u32 {
        self.0.epoch
    }
    /// Wire encoding: the share layout with a distinct version byte, so a delta can never be
    /// parsed as a share or the reverse.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.0.to_bytes();
        b[0] = DELTA_VERSION;
        b
    }
    /// Strict decoding, as for [`Share::from_bytes`].
    ///
    /// # Errors
    /// [`SharingError::Malformed`] and the errors of [`Share::from_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, SharingError> {
        if b.len() < HEADER || b[0] != DELTA_VERSION {
            return Err(SharingError::Malformed);
        }
        let mut v = b.to_vec();
        v[0] = WIRE_VERSION;
        Share::from_bytes(&v).map(Self)
    }
}

/// A dealer shares zero for the holders at `indices`, for shares currently in `epoch`.
///
/// Returns one [`Delta`] per index, in the same order. `k` and `secret_len` must equal those of
/// the shares being refreshed.
///
/// # Errors
/// Bad threshold, bad or duplicate indexes, bad length, or a randomness failure.
pub fn zero_sharing<R: RandomSource>(
    k: usize,
    indices: &[u8],
    secret_len: usize,
    set: [u8; 16],
    epoch: u32,
    rng: &mut R,
) -> Result<Vec<Delta>, SharingError> {
    if indices.len() > MAX_SHARES || secret_len == 0 || secret_len > crate::MAX_SECRET_LEN {
        return Err(SharingError::InvalidSecretLength);
    }
    let zero = vec![0u8; secret_len];
    Ok(deal(&zero, k, indices, set, epoch, rng)?
        .into_iter()
        .map(Delta)
        .collect())
}

/// Add every delta to `share`, producing the share for the next epoch.
///
/// The caller must pass the deltas of the same set of dealers to every holder. Each delta must be
/// for this holder, this set and epoch, and this threshold and length.
///
/// # Errors
/// [`SharingError::NoShares`] if `deltas` is empty, [`SharingError::Mismatched`] for any
/// disagreeing label, and [`SharingError::EpochOverflow`] at `u32::MAX`.
pub fn refresh_share(share: &Share, deltas: &[Delta]) -> Result<Share, SharingError> {
    if deltas.is_empty() {
        return Err(SharingError::NoShares);
    }
    let epoch = share
        .epoch
        .checked_add(1)
        .ok_or(SharingError::EpochOverflow)?;
    let mut y = share.y.clone();
    for d in deltas {
        let d = &d.0;
        if d.set != share.set
            || d.epoch != share.epoch
            || d.threshold != share.threshold
            || d.index != share.index
            || d.y.len() != y.len()
        {
            return Err(SharingError::Mismatched);
        }
        for (a, b) in y.iter_mut().zip(&d.y) {
            *a ^= b;
        }
    }
    Ok(Share {
        set: share.set,
        epoch,
        threshold: share.threshold,
        index: share.index,
        y,
    })
}
