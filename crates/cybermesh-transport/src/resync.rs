//! Resynchronising the pools after a lost record or a crash.
//!
//! A record that never arrived leaves the sender's cursor ahead of the receiver's copy of the
//! same pool, and every later record would be read with the wrong pad. Resync fixes that by
//! **burning forward**: for each of the four pools both parties move their copy to the larger of
//! the two cursors. Cursors never move backwards.
//!
//! # Authenticated and fresh
//!
//! A sync **response** carries the sender's four cursors, the **nonce** of the request it answers,
//! and a **one-time tag**. The sender takes 32 fresh bytes from its own send authentication pool
//! (a hash key, then a pad) and tags the message with them; the receiver reads the same 32 bytes at
//! the offset the message names **without consuming them**
//! ([`cybermesh_entropy::Pool::peek_unspent`]) and verifies the tag **before any state changes**. A
//! forger, who has none of that material, succeeds with probability at most `(blocks + 1) / 2^128`
//! per message and a forged message burns nothing. A replay names material already spent on the
//! receiver's side and is refused ([`TransportError::SyncStale`]).
//!
//! **Freshness.** A response is accepted only as the answer to a request the receiver made: the
//! requester picks a random 16-byte nonce ([`Endpoint::sync_request`]), the responder's tag covers
//! it ([`Endpoint::sync_response`]), and [`Endpoint::resync`] refuses a response that does not echo
//! the nonce of the request it is given ([`TransportError::SyncNotRequested`]). A genuine but old
//! message, which the peer made for an earlier request, cannot be accepted by a party that has
//! restarted since. The nonce is public and needs only to be fresh; it is held by the caller in a
//! [`SyncRequest`], so a restart forgets it. This closes a hole the TLA+ model in `formal/tla`
//! found (`docs/trust-fabric/formal-model.md`).
//!
//! Burning forward is also safe on its own: every byte below a party's cursor is already spent or
//! erased on that side, so it can only waste material, never make a pad usable twice.
//!
//! # What this does not fix
//!
//! * **A responder that was restored spends material it already used when it answers.** Answering
//!   spends 32 bytes at the responder's own cursor. A party that might have been restored should
//!   therefore **request first and answer only after it has applied a fresh response**. Nothing local
//!   says a party was restored, so this is a procedure, not a guarantee, and two parties that both
//!   wait for the other are not sequenced here.
//! * **A message lost or in flight when a party is restored.** Its slot was used and seen on the wire
//!   but the peer never accepted it, so the peer cannot tell the restored party; it reuses that
//!   slot. No exchange fixes that (`known-issues.md`, #1).
//! * **Nonce uniqueness is assumed.** Restoring a whole virtual machine can also restore the random
//!   number generator and a nonce already chosen.
//! * **A forged request costs the responder 32 authentication bytes** and leaves the pair out of
//!   step until a resync: a small denial of service, in line with the transport not protecting
//!   availability.
//! * Resync is a manual, quiescent step. A response is refused if it is more than `max_burn` bytes
//!   ahead of the receiver in any pool, and when the genuine peer is further ahead than the policy
//!   allows, nothing heals until the policy is raised.
//! * When both parties are restored to the same moment nothing is detected.

use cybermesh_entropy::{EntropyError, MAX_RESERVATION, MIN_RESERVATION};
use cybermesh_trust::mac::{ONE_TIME_MATERIAL_LEN, TAG_LEN, Tag, tag_one_time, verify_one_time};
use zeroize::Zeroizing;

use crate::session::{Endpoint, TransportError};

/// Length of the nonce in a sync request.
pub const NONCE_LEN: usize = 16;
/// Length of a sync request: `'Q'`, version, role, nonce.
pub const REQUEST_LEN: usize = 3 + NONCE_LEN;
/// Length of a sync response: `'S'`, version, role, nonce, four cursors, tag.
pub const SYNC_LEN: usize = 3 + NONCE_LEN + 4 * 8 + TAG_LEN;
const BODY_LEN: usize = SYNC_LEN - TAG_LEN;
const CURSORS_AT: usize = 3 + NONCE_LEN;
const VERSION: u8 = 3;
const DOM_SYNC: &[u8] = b"cybermesh-transport v2 sync";
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

/// A request for a sync response: a fresh nonce, held by the party that made it.
///
/// Not `Clone` and not `Copy`: it is used by one successful [`Endpoint::resync`], and a restart
/// forgets it, which is what makes an old response unacceptable.
#[derive(Debug)]
pub struct SyncRequest {
    nonce: [u8; NONCE_LEN],
    role: u8,
    used: bool,
}

impl SyncRequest {
    /// The bytes to send to the peer.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut m = vec![b'Q', VERSION, self.role];
        m.extend_from_slice(&self.nonce);
        m
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

    /// Start a resync: choose a fresh random nonce and return the request to send to the peer.
    /// Spends no pool material. Keep the [`SyncRequest`] and pass it to [`Endpoint::resync`] with
    /// the response.
    ///
    /// # Errors
    /// [`TransportError::Randomness`] if the system's random source fails.
    pub fn sync_request(&self) -> Result<SyncRequest, TransportError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| TransportError::Randomness)?;
        Ok(SyncRequest {
            nonce,
            role: self.role() as u8,
            used: false,
        })
    }

    /// Answer the peer's request: this party's cursors and the request's nonce, authenticated with
    /// 32 fresh bytes taken (and spent) from the send authentication pool. The cursors in it are the
    /// ones **after** that spending. Each call spends 32 more bytes, whoever sent the request.
    ///
    /// On an endpoint that may have been restored from a backup, make your own request and apply
    /// its response first (see the module docs).
    ///
    /// # Errors
    /// [`TransportError::BadSync`] for a malformed request or one from the wrong role; entropy
    /// errors (including an exhausted pool).
    pub fn sync_response(&self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        if request.len() != REQUEST_LEN || request[0] != b'Q' || request[1] != VERSION {
            return Err(TransportError::BadSync);
        }
        if request[2] > 1 || request[2] == self.role() as u8 {
            return Err(TransportError::BadSync);
        }
        let material = self.pools()[1]
            .1
            .reserve(ONE_TIME_MATERIAL_LEN)?
            .into_secret();
        let mut m = [0u8; ONE_TIME_MATERIAL_LEN];
        m.copy_from_slice(&material);
        let mut body = vec![b'S', VERSION, self.role() as u8];
        body.extend_from_slice(&request[3..]);
        for c in self.cursors()?.as_array() {
            body.extend_from_slice(&c.to_be_bytes());
        }
        let tag = tag_one_time(&m, &tagged(&body))?;
        zeroize::Zeroize::zeroize(&mut m);
        body.extend_from_slice(&tag.to_bytes());
        Ok(body)
    }

    /// Authenticate the peer's sync response to `request`, then burn forward to the larger of the two cursors in
    /// each pool.
    ///
    /// Nothing is changed unless the response echoes the nonce of `request` and the tag verifies.
    /// `request` is marked used only after a successful burn, so a refusal (a forgery, or a policy
    /// that is too small) leaves it usable.
    ///
    ///  All four targets are validated before anything
    /// is burned. My send pool pairs with the peer's receive copy of it and vice versa.
    ///
    /// # Errors
    /// [`TransportError::BadSync`] for a malformed message or one from the wrong role;
    /// [`TransportError::SyncNotRequested`] for a response that does not answer `request`;
    /// [`TransportError::SyncStale`] for material this side has already spent;
    /// [`TransportError::SyncAuthentication`] for a tag that does not verify;
    /// [`TransportError::ResyncExceedsPool`], [`TransportError::ResyncExceedsPolicy`] and
    /// [`TransportError::Misaligned`] leave every pool untouched.
    pub fn resync(
        &self,
        peer: &[u8],
        request: &mut SyncRequest,
        max_burn: u64,
    ) -> Result<ResyncReport, TransportError> {
        if peer.len() != SYNC_LEN || peer[0] != b'S' || peer[1] != VERSION {
            return Err(TransportError::BadSync);
        }
        let their_role = peer[2];
        if their_role > 1 || their_role == self.role() as u8 {
            return Err(TransportError::BadSync);
        }
        if request.used || request.role != self.role() as u8 || peer[3..CURSORS_AT] != request.nonce
        {
            return Err(TransportError::SyncNotRequested);
        }
        let theirs: Vec<u64> = peer[CURSORS_AT..BODY_LEN]
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
        request.used = true;
        Ok(ResyncReport { burned })
    }
}

#[cfg(test)]
mod tests;
