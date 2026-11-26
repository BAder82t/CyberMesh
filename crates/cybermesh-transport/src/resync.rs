//! Resynchronising the pools after a lost record or a crash.
//!
//! A record that never arrived leaves the sender's cursor ahead of the receiver's copy of the
//! same pool, and every later record would be read with the wrong pad. Resync fixes that by
//! **burning forward**: for each of the four pools both parties move their copy to the larger of
//! the two cursors. Cursors never move backwards.
//!
//! # Authenticated
//!
//! A sync message carries the sender's four cursors and a **one-time tag**. The sender takes 32
//! fresh bytes from its own send authentication pool (a hash key, then a pad) and tags the message
//! with them; the receiver reads the same 32 bytes at the offset the message names **without
//! consuming them** ([`cybermesh_entropy::Pool::peek_unspent`]) and verifies the tag **before any
//! state changes**. A forger, who has none of that material, succeeds with probability at most
//! `(blocks + 1) / 2^128` per message and a forged message burns nothing. A replay names material
//! already spent on the receiver's side and is refused ([`TransportError::SyncStale`]). The
//! receiver then spends the 32 bytes it used and burns forward.
//!
//! Burning forward is also safe on its own: every byte below a party's cursor is already spent or
//! erased on that side, so it can only waste material, never make a pad usable twice.
//!
//! # What this does not fix
//!
//! * **The sender must not tag with material it already used.** After a restore of a pool
//!   directory from a backup, a party's cursor is behind and the next 32 bytes it takes are bytes
//!   it has used before (see `docs/trust-fabric/known-issues.md`, #1). Therefore the order
//!   matters: a party that might have been restored should **verify the peer's message first**
//!   (which burns it forward) and only then create its own. [`Endpoint::sync_message`] on a
//!   restored endpoint produces a message the peer refuses as stale, and its tag reuses a key and
//!   pad.
//! * Resync is a manual, quiescent step. A message is refused if it is more than `max_burn` bytes
//!   ahead of the receiver in any pool, and when the genuine peer is further ahead than the policy
//!   allows, nothing heals until the policy is raised.
//! * When both parties are restored to the same moment nothing is detected.

use cybermesh_entropy::{EntropyError, MAX_RESERVATION, MIN_RESERVATION};
use cybermesh_trust::mac::{ONE_TIME_MATERIAL_LEN, TAG_LEN, Tag, tag_one_time, verify_one_time};
use zeroize::Zeroizing;

use crate::session::{Endpoint, TransportError};

/// Length of a sync message: `'S'`, version, role, four cursors, tag.
pub const SYNC_LEN: usize = 3 + 4 * 8 + TAG_LEN;
const BODY_LEN: usize = SYNC_LEN - TAG_LEN;
const VERSION: u8 = 2;
const DOM_SYNC: &[u8] = b"cybermesh-transport v1 sync";
const AUTH: usize = 3; // index of the receive authentication pool in `Endpoint::pools`

/// One party's four cursors (bytes consumed), in its own send/receive terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursors {
    pub send_enc: u64,
    pub send_auth: u64,
    pub recv_enc: u64,
    pub recv_auth: u64,
}

impl Cursors {
    fn as_array(self) -> [u64; 4] {
        [self.send_enc, self.send_auth, self.recv_enc, self.recv_auth]
    }
}

/// What a resync did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResyncReport {
    /// Bytes burned in each pool: send encryption, send authentication, receive encryption,
    /// receive authentication. The 32 bytes of the sync message's own tag, which are spent and not
    /// burned, are not counted.
    pub burned: [u64; 4],
}

impl ResyncReport {
    /// True when the pools already agreed and nothing was burned.
    #[must_use]
    pub fn was_in_step(&self) -> bool {
        self.burned == [0; 4]
    }
}

fn tagged(body: &[u8]) -> Vec<u8> {
    let mut m = DOM_SYNC.to_vec();
    m.extend_from_slice(body);
    m
}

impl Endpoint {
    /// This party's cursors.
    ///
    /// # Errors
    /// Entropy errors.
    pub fn cursors(&self) -> Result<Cursors, TransportError> {
        let p = self.pools();
        let c = |i: usize| -> Result<u64, TransportError> { Ok(p[i].1.stats()?.consumed) };
        Ok(Cursors {
            send_enc: c(0)?,
            send_auth: c(1)?,
            recv_enc: c(2)?,
            recv_auth: c(3)?,
        })
    }

    /// The message to send to the peer: this party's cursors, authenticated with 32 fresh bytes
    /// taken (and spent) from the send authentication pool. The cursors in it are the ones **after**
    /// that spending. Call it once per attempt; each call spends 32 more bytes.
    ///
    /// On an endpoint that may have been restored from a backup, call
    /// [`Endpoint::resync`] on the peer's message first (see the module docs).
    ///
    /// # Errors
    /// Entropy errors (including an exhausted pool).
    pub fn sync_message(&self) -> Result<Vec<u8>, TransportError> {
        let material = self.pools()[1]
            .1
            .reserve(ONE_TIME_MATERIAL_LEN)?
            .into_secret();
        let mut m = [0u8; ONE_TIME_MATERIAL_LEN];
        m.copy_from_slice(&material);
        let mut body = vec![b'S', VERSION, self.role() as u8];
        for c in self.cursors()?.as_array() {
            body.extend_from_slice(&c.to_be_bytes());
        }
        let tag = tag_one_time(&m, &tagged(&body))?;
        zeroize::Zeroize::zeroize(&mut m);
        body.extend_from_slice(&tag.to_bytes());
        Ok(body)
    }

    /// Authenticate the peer's sync message, then burn forward to the larger of the two cursors in
    /// each pool.
    ///
    /// Nothing is changed unless the tag verifies. All four targets are validated before anything
    /// is burned. My send pool pairs with the peer's receive copy of it and vice versa.
    ///
    /// # Errors
    /// [`TransportError::BadSync`] for a malformed message or one from the wrong role;
    /// [`TransportError::SyncStale`] for material this side has already spent;
    /// [`TransportError::SyncAuthentication`] for a tag that does not verify;
    /// [`TransportError::ResyncExceedsPool`], [`TransportError::ResyncExceedsPolicy`] and
    /// [`TransportError::Misaligned`] leave every pool untouched.
    pub fn resync(&self, peer: &[u8], max_burn: u64) -> Result<ResyncReport, TransportError> {
        if peer.len() != SYNC_LEN || peer[0] != b'S' || peer[1] != VERSION {
            return Err(TransportError::BadSync);
        }
        let their_role = peer[2];
        if their_role > 1 || their_role == self.role() as u8 {
            return Err(TransportError::BadSync);
        }
        let theirs: Vec<u64> = peer[3..BODY_LEN]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_be_bytes(*c))
            .collect();
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&peer[BODY_LEN..]);

        // 1. Authenticate first, changing nothing. The tag's material is the 32 bytes the peer
        //    spent just before the cursor it reports for its send authentication pool.
        let (name, auth_pool) = self.pools()[AUTH];
        let offset = theirs[1]
            .checked_sub(ONE_TIME_MATERIAL_LEN as u64)
            .ok_or(TransportError::BadSync)?;
        let stats = auth_pool.stats()?;
        let cursor = stats.consumed;
        if offset.saturating_add(ONE_TIME_MATERIAL_LEN as u64) > stats.capacity {
            return Err(TransportError::ResyncExceedsPool { pool: name });
        }
        if offset >= cursor && offset - cursor > max_burn {
            return Err(TransportError::ResyncExceedsPolicy {
                pool: name,
                gap: offset - cursor,
                max: max_burn,
            });
        }
        let bytes = auth_pool
            .peek_unspent(offset, ONE_TIME_MATERIAL_LEN)
            .map_err(|e| match e {
                EntropyError::AlreadySpent { .. } | EntropyError::Burned => {
                    TransportError::SyncStale
                }
                EntropyError::OutOfRange => TransportError::ResyncExceedsPool { pool: name },
                other => other.into(),
            })?;
        let mut material = Zeroizing::new([0u8; ONE_TIME_MATERIAL_LEN]);
        material.copy_from_slice(&bytes);
        verify_one_time(&material, &tagged(&peer[..BODY_LEN]), &Tag::from_bytes(tag))
            .map_err(|_| TransportError::SyncAuthentication)?;

        // 2. Plan: validate all four targets before burning anything.
        let paired = [theirs[2], theirs[3], theirs[0], theirs[1]];
        let mut plan = [0u64; 4]; // bytes to move each pool forward
        for (i, (pname, pool)) in self.pools().into_iter().enumerate() {
            let st = pool.stats()?;
            let target = st.consumed.max(paired[i]);
            let gap = target - st.consumed;
            if target > st.capacity {
                return Err(TransportError::ResyncExceedsPool { pool: pname });
            }
            // The message's own 32 bytes are spent, not burned: only the skipped bytes count
            // against the policy and the alignment rule.
            let skipped = if i == AUTH {
                gap.saturating_sub(ONE_TIME_MATERIAL_LEN as u64)
            } else {
                gap
            };
            if skipped > max_burn {
                return Err(TransportError::ResyncExceedsPolicy {
                    pool: pname,
                    gap: skipped,
                    max: max_burn,
                });
            }
            if skipped != 0 && skipped < MIN_RESERVATION as u64 {
                return Err(TransportError::Misaligned {
                    pool: pname,
                    gap: skipped,
                });
            }
            plan[i] = gap;
        }

        // 3. Spend and burn.
        let mut burned = [0u64; 4];
        for (i, (_, pool)) in self.pools().into_iter().enumerate() {
            let mut left = plan[i];
            while left > 0 {
                let mut chunk = left.min(MAX_RESERVATION as u64);
                if (1..MIN_RESERVATION as u64).contains(&(left - chunk)) {
                    chunk -= MIN_RESERVATION as u64;
                }
                // A region that is already erased still counts as burned (the cursor moves).
                match pool.reserve(chunk as usize) {
                    Ok(_) | Err(EntropyError::Burned) => {}
                    Err(e) => return Err(e.into()),
                }
                left -= chunk;
            }
            burned[i] = if i == AUTH {
                plan[i].saturating_sub(ONE_TIME_MATERIAL_LEN as u64)
            } else {
                plan[i]
            };
        }
        Ok(ResyncReport { burned })
    }
}

#[cfg(test)]
mod tests;
