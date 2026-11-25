//! Resynchronising the pools after a lost record or a crash.
//!
//! A record that never arrived leaves the sender's cursor ahead of the receiver's copy of the
//! same pool, and every later record would be read with the wrong pad. Resync fixes that by
//! **burning forward**: for each of the four pools both parties move their copy to the larger of
//! the two cursors. Cursors never move backwards.
//!
//! # Why this is safe without authenticating the cursors
//!
//! Every byte below a party's cursor is already spent or erased on that party's side, so burning
//! forward can only waste material; it cannot make a pad usable twice. A forged or replayed sync
//! message can therefore do one thing: persuade a party to burn material (a denial of service).
//! That is bounded in two ways: a target beyond the pool's provisioned size is refused, and the
//! caller passes the most it is willing to burn per pool (`max_burn`). The next handshake is
//! authenticated and checks the cursors again, so a lie that leaves the pair out of step is
//! detected there and healed by another exchange; the cost is only burned material.
//!
//! Resync is a manual, quiescent step: run it with no session active, and apply it only once
//! per exchange of the two parties' messages.

use cybermesh_entropy::EntropyError;

use crate::session::{Endpoint, TransportError};

/// Length of a sync message: `'S'`, version, four cursors.
pub const SYNC_LEN: usize = 2 + 4 * 8;
const VERSION: u8 = 1;

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
    /// receive authentication.
    pub burned: [u64; 4],
}

impl ResyncReport {
    /// True when the pools already agreed and nothing was burned.
    #[must_use]
    pub fn was_in_step(&self) -> bool {
        self.burned == [0; 4]
    }
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

    /// The message to send to the peer: this party's cursors. It is not authenticated (see the
    /// module docs for why that is safe) and carries no secret.
    ///
    /// # Errors
    /// Entropy errors.
    pub fn sync_message(&self) -> Result<Vec<u8>, TransportError> {
        let mut m = vec![b'S', VERSION];
        for c in self.cursors()?.as_array() {
            m.extend_from_slice(&c.to_be_bytes());
        }
        Ok(m)
    }

    /// Burn forward to the larger of the two cursors in each pool, given the peer's sync message.
    ///
    /// All four targets are validated before anything is burned. My send pool pairs with the
    /// peer's receive copy of it and vice versa.
    ///
    /// # Errors
    /// [`TransportError::BadSync`] for a malformed message;
    /// [`TransportError::ResyncExceedsPool`], [`TransportError::ResyncExceedsPolicy`] and
    /// [`TransportError::Misaligned`] leave every pool untouched.
    pub fn resync(&self, peer: &[u8], max_burn: u64) -> Result<ResyncReport, TransportError> {
        if peer.len() != SYNC_LEN || peer[0] != b'S' || peer[1] != VERSION {
            return Err(TransportError::BadSync);
        }
        let theirs: Vec<u64> = peer[2..]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_be_bytes(*c))
            .collect();
        // Mine (send_enc, send_auth, recv_enc, recv_auth) against theirs
        // (recv_enc, recv_auth, send_enc, send_auth) for the same four pools.
        let paired = [theirs[2], theirs[3], theirs[0], theirs[1]];
        let mut plan = [(0u64, 0u64); 4]; // (target, gap)
        for (i, (name, pool)) in self.pools().into_iter().enumerate() {
            let st = pool.stats()?;
            let target = st.consumed.max(paired[i]);
            let gap = target - st.consumed;
            if target > st.capacity {
                return Err(TransportError::ResyncExceedsPool { pool: name });
            }
            if gap > max_burn {
                return Err(TransportError::ResyncExceedsPolicy {
                    pool: name,
                    gap,
                    max: max_burn,
                });
            }
            if gap != 0 && gap < cybermesh_entropy::MIN_RESERVATION as u64 {
                return Err(TransportError::Misaligned { pool: name, gap });
            }
            plan[i] = (target, gap);
        }
        let mut burned = [0u64; 4];
        for (i, (_, pool)) in self.pools().into_iter().enumerate() {
            let mut left = plan[i].1;
            while left > 0 {
                let mut chunk = left.min(cybermesh_entropy::MAX_RESERVATION as u64);
                if (1..cybermesh_entropy::MIN_RESERVATION as u64).contains(&(left - chunk)) {
                    chunk -= cybermesh_entropy::MIN_RESERVATION as u64;
                }
                // A region that is already erased still counts as burned (the cursor moves).
                match pool.reserve(chunk as usize) {
                    Ok(_) | Err(EntropyError::Burned) => {}
                    Err(e) => return Err(e.into()),
                }
                left -= chunk;
            }
            burned[i] = plan[i].1;
        }
        Ok(ResyncReport { burned })
    }
}

#[cfg(test)]
mod tests;
