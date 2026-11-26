//! Authenticated secret shares: information checking in the Rabin-Ben-Or style.
//!
//! A *dealer* D tags every share of a sharing with a MAC key that the share's *holder* never
//! sees. D and the party that will later reconstruct, the *verifier* V, hold identical secret
//! material from a pairwise `Authentication` pool (see `cybermesh-entropy`). The holder keeps
//! `(share, tag)` and presents both to V. A holder who alters its share, or swaps it for another
//! share, cannot produce a matching tag without the key: it succeeds with probability at most
//! `q (n + 1) / 2^128` after `q` failed presentations (see [`crate::mac`]), against an
//! adversary with unbounded computation.
//!
//! This closes the weakness of Reed-Solomon decoding in `cybermesh-sharing`: decoding silently
//! returns a wrong secret when more shares are wrong than it can correct. Here wrong shares are
//! **rejected one by one before reconstruction**, so the result is either the dealer's secret or
//! an error; a wrong secret cannot come from altered shares.
//!
//! # Material layout
//!
//! One reservation per dealing, `16 * (1 + n)` bytes: a fresh 16-byte hash key, then one
//! 16-byte pad per holder slot (slot = share index - 1). Each slot is tagged once by the dealer.
//! V re-computes with its own copy of the same block and may check a slot repeatedly, which is
//! verification, not tagging. Every mismatch counts against a failure budget.
//!
//! # What this does not give
//!
//! * **A dishonest dealer.** A valid tag says the share is the one D issued, unchanged. A dealer
//!   that issues shares of different polynomials with valid tags is caught only by the
//!   consistency check when more than `k` shares are presented ([`SharesError::Sharing`] with
//!   `Inconsistent`). Verifiable secret sharing against dealers is not built.
//! * **Public verifiability.** Only V (and D) can check a tag. A third party cannot, and V
//!   could forge. Different verifiers each need their own pairwise material.
//! * **Refreshed shares.** A share changed by proactive refresh has no tag; re-dealing (a new
//!   block and new tags) is required. Authenticated refresh is not built.
//! * **Persistence.** The verifier's block is held in memory; if it is lost, the dealing can no
//!   longer be checked and verification fails closed.

use cybermesh_entropy::{PoolId, Reservation};
use cybermesh_sharing::{Share, SharingError, reconstruct};

use crate::block::Block;
use crate::mac::{MacError, TAG_LEN, Tag};

const DOMAIN: &[u8] = b"cybermesh-trust share-auth v1";
const BLOCK_HEADER: usize = 8 + TAG_LEN;

/// Failures. None carries key material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SharesError {
    #[error("block must be an Authentication reservation of 16 * (1 + n) bytes, 1 <= n <= 255")]
    BadMaterial,
    #[error("share index {0} has no slot in this block")]
    NoSlot(u8),
    #[error("tag was made from a different block (offset {got}, this block {have})")]
    OutOfStep { have: u64, got: u64 },
    #[error("share {0} failed authentication")]
    Invalid(u8),
    #[error("too many failed verifications: replace this dealing's material")]
    KeyRetired,
    #[error("only {got} authentic shares, {needed} needed")]
    TooFewAuthentic { needed: usize, got: usize },
    #[error("malformed authenticated share")]
    Malformed,
    #[error("sharing: {0}")]
    Sharing(#[from] SharingError),
    #[error("mac: {0}")]
    Mac(#[from] MacError),
}

/// A share with the dealer's tag, as the holder keeps and presents it.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthShare {
    share: Share,
    tag: Tag,
    offset: u64,
}

impl AuthShare {
    /// The share (still secret material).
    #[must_use]
    pub fn share(&self) -> &Share {
        &self.share
    }
    /// Wire encoding: block offset (8), tag (16), then the share's own encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.extend_from_slice(&self.tag.to_bytes());
        out.extend_from_slice(&self.share.to_bytes());
        out
    }
    /// Strict decoding.
    ///
    /// # Errors
    /// [`SharesError::Malformed`] or the share's own decoding errors.
    pub fn from_bytes(b: &[u8]) -> Result<Self, SharesError> {
        if b.len() <= BLOCK_HEADER {
            return Err(SharesError::Malformed);
        }
        let mut off = [0u8; 8];
        off.copy_from_slice(&b[..8]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&b[8..BLOCK_HEADER]);
        Ok(Self {
            share: Share::from_bytes(&b[BLOCK_HEADER..])?,
            tag: Tag::from_bytes(tag),
            offset: u64::from_be_bytes(off),
        })
    }
}

/// What is authenticated: domain, pool, block offset and the share's full encoding (set, epoch,
/// threshold, index, length, bytes), so a tag cannot be moved to another share, set, epoch or
/// dealing.
fn message(pool: PoolId, offset: u64, share: &Share) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(&pool.0);
    m.extend_from_slice(&offset.to_be_bytes());
    m.extend_from_slice(&share.to_bytes());
    m
}

/// Pad of the slot for share `index` (slot = index - 1).
fn slot_pad(block: &Block, index: u8) -> Result<[u8; TAG_LEN], SharesError> {
    let slot = usize::from(index)
        .checked_sub(1)
        .ok_or(SharesError::NoSlot(index))?;
    block.pad(slot).ok_or(SharesError::NoSlot(index))
}

/// Tag every share of a dealing with a block of `16 * (1 + n)` bytes of `Authentication`
/// material (consumed). `n` must be at least the highest share index.
///
/// # Errors
/// [`SharesError::BadMaterial`] or [`SharesError::NoSlot`] if a share index has no pad.
pub fn authenticate_shares(
    shares: Vec<Share>,
    block: Reservation,
) -> Result<Vec<AuthShare>, SharesError> {
    let block = Block::from_reservation(block).ok_or(SharesError::BadMaterial)?;
    shares
        .into_iter()
        .map(|share| {
            let mut pad = slot_pad(&block, share.index())?;
            let tag = block
                .key
                .tag_with_pad(&message(block.pool, block.offset, &share), &pad);
            zeroize::Zeroize::zeroize(&mut pad);
            Ok(AuthShare {
                tag: Tag::from_bytes(tag?),
                offset: block.offset,
                share,
            })
        })
        .collect()
}

/// A verifier's copy of the dealing's material, with a failure budget.
pub struct ShareChecker {
    block: Block,
    failures: u32,
    max_failures: u32,
}

impl core::fmt::Debug for ShareChecker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShareChecker")
            .field("offset", &self.block.offset)
            .field("failures", &self.failures)
            .finish_non_exhaustive()
    }
}

/// A reconstructed secret and the indexes of the shares that failed authentication.
pub struct AuthRecovered {
    /// The secret.
    pub secret: Vec<u8>,
    /// Shares that were rejected before reconstruction.
    pub rejected: Vec<u8>,
}

impl core::fmt::Debug for AuthRecovered {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthRecovered")
            .field("secret_len", &self.secret.len())
            .field("rejected", &self.rejected)
            .finish()
    }
}

impl Drop for AuthRecovered {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.secret);
    }
}

impl ShareChecker {
    /// Take the verifier's copy of the dealing's block (consumed). It must come from the same
    /// offset of the pairwise pool as the dealer's.
    ///
    /// # Errors
    /// [`SharesError::BadMaterial`].
    pub fn new(block: Reservation, max_failures: u32) -> Result<Self, SharesError> {
        Ok(Self {
            block: Block::from_reservation(block).ok_or(SharesError::BadMaterial)?,
            failures: 0,
            max_failures,
        })
    }

    /// Failed authentications so far.
    #[must_use]
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Check one presented share.
    ///
    /// # Errors
    /// [`SharesError::OutOfStep`] and [`SharesError::NoSlot`] (not counted),
    /// [`SharesError::Invalid`] (counted), [`SharesError::KeyRetired`].
    pub fn check(&mut self, presented: &AuthShare) -> Result<(), SharesError> {
        if self.failures >= self.max_failures {
            return Err(SharesError::KeyRetired);
        }
        if presented.offset != self.block.offset {
            return Err(SharesError::OutOfStep {
                have: self.block.offset,
                got: presented.offset,
            });
        }
        let mut pad = slot_pad(&self.block, presented.share.index())?;
        let want = self.block.key.tag_with_pad(
            &message(self.block.pool, self.block.offset, &presented.share),
            &pad,
        );
        zeroize::Zeroize::zeroize(&mut pad);
        if Tag::from_bytes(want?) == presented.tag {
            Ok(())
        } else {
            self.failures = self.failures.saturating_add(1);
            Err(SharesError::Invalid(presented.share.index()))
        }
    }

    /// Reconstruct from presented shares: authenticate each, drop the ones that fail, then
    /// reconstruct from the authentic ones (cross-checking any beyond the threshold).
    ///
    /// The result is the dealer's secret or an error. Altered shares cannot make it wrong.
    ///
    /// # Errors
    /// [`SharesError::TooFewAuthentic`], [`SharesError::KeyRetired`] if the budget is spent
    /// while checking, [`SharesError::OutOfStep`] / [`SharesError::NoSlot`] for shares from
    /// another dealing, and sharing errors (duplicates, mixed sets, `Inconsistent` for a
    /// dishonest dealer).
    pub fn reconstruct(&mut self, presented: Vec<AuthShare>) -> Result<AuthRecovered, SharesError> {
        let mut authentic = Vec::new();
        let mut rejected = Vec::new();
        for p in presented {
            match self.check(&p) {
                Ok(()) => authentic.push(p.share),
                Err(SharesError::Invalid(i)) => rejected.push(i),
                Err(e) => return Err(e),
            }
        }
        let needed = authentic
            .first()
            .map_or(usize::MAX, |s| usize::from(s.threshold()));
        if authentic.len() < needed {
            return Err(SharesError::TooFewAuthentic {
                needed: if needed == usize::MAX { 0 } else { needed },
                got: authentic.len(),
            });
        }
        let secret = reconstruct(&authentic)?;
        Ok(AuthRecovered { secret, rejected })
    }
}

#[cfg(test)]
mod tests;
