//! Bounded replay cache.
//!
//! Every accepted message id is remembered until the message itself expires; after that the
//! expiry check rejects it anyway. When the cache is full it fails closed (rejects new
//! messages) rather than evicting live entries, which would re-open a replay window. With
//! per-peer rate limits and bounded message lifetimes the steady-state size is bounded by
//! `rate * lifetime`.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

use cybermesh_crypto::Digest;

use crate::ProtocolError;

#[derive(Debug)]
pub struct ReplayCache {
    entries: HashMap<Digest, u64>,
    expiry: BinaryHeap<Reverse<(u64, Digest)>>,
    capacity: usize,
}

impl ReplayCache {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            expiry: BinaryHeap::new(),
            capacity: capacity.max(1),
        }
    }

    /// Records `id` until `forget_after`. Errors if `id` was already seen and has not yet
    /// been forgotten, or if the cache is full.
    pub fn check_and_insert(
        &mut self,
        id: Digest,
        forget_after: u64,
        now: u64,
    ) -> Result<(), ProtocolError> {
        self.prune(now);
        if self.entries.contains_key(&id) {
            return Err(ProtocolError::Replay);
        }
        if self.entries.len() >= self.capacity {
            return Err(ProtocolError::ReplayCacheFull);
        }
        self.entries.insert(id, forget_after);
        self.expiry.push(Reverse((forget_after, id)));
        Ok(())
    }

    #[must_use]
    pub fn contains(&self, id: &Digest) -> bool {
        self.entries.contains_key(id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn prune(&mut self, now: u64) {
        while let Some(Reverse((t, id))) = self.expiry.peek().copied() {
            if t > now {
                break;
            }
            self.expiry.pop();
            if self.entries.get(&id) == Some(&t) {
                self.entries.remove(&id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_replay_until_expiry() {
        let mut c = ReplayCache::new(10);
        let id = Digest::of(b"m1");
        c.check_and_insert(id, 100, 10).unwrap();
        assert_eq!(c.check_and_insert(id, 100, 50), Err(ProtocolError::Replay));
        // After expiry the id is forgotten (the message's own expiry check takes over).
        c.check_and_insert(id, 200, 100).unwrap();
    }

    #[test]
    fn fails_closed_when_full() {
        let mut c = ReplayCache::new(2);
        c.check_and_insert(Digest::of(b"a"), 100, 0).unwrap();
        c.check_and_insert(Digest::of(b"b"), 100, 0).unwrap();
        assert_eq!(
            c.check_and_insert(Digest::of(b"c"), 100, 0),
            Err(ProtocolError::ReplayCacheFull)
        );
        // Space frees up once entries expire.
        c.check_and_insert(Digest::of(b"c"), 300, 100).unwrap();
        assert_eq!(c.len(), 1);
    }
}
