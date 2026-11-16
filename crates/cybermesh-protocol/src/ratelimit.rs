//! Token-bucket rate limiting keyed by peer (or any hashable key).

use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Tokens scaled by 1000.
    milli_tokens: u64,
    last_ms: u64,
}

/// Per-key token buckets. New keys beyond `max_keys` are refused, so memory is bounded
/// even if an attacker rotates identities (in a permissioned network keys are allowlisted).
#[derive(Debug)]
pub struct RateLimiter<K> {
    buckets: HashMap<K, Bucket>,
    burst: u64,
    refill_per_sec: u64,
    max_keys: usize,
}

impl<K: Hash + Eq + Clone> RateLimiter<K> {
    #[must_use]
    pub fn new(burst: u32, refill_per_sec: u32, max_keys: usize) -> Self {
        Self {
            buckets: HashMap::new(),
            burst: u64::from(burst.max(1)),
            refill_per_sec: u64::from(refill_per_sec),
            max_keys: max_keys.max(1),
        }
    }

    /// Consumes `cost` tokens for `key` at time `now_ms` (monotonic milliseconds).
    pub fn allow(&mut self, key: &K, cost: u32, now_ms: u64) -> bool {
        let cap = self.burst * 1000;
        if !self.buckets.contains_key(key) {
            if self.buckets.len() >= self.max_keys {
                // Drop buckets that are full (idle peers) before refusing.
                let burst = self.burst;
                let rate = self.refill_per_sec;
                self.buckets.retain(|_, b| {
                    let refilled =
                        b.milli_tokens + now_ms.saturating_sub(b.last_ms) * rate;
                    refilled < burst * 1000
                });
                if self.buckets.len() >= self.max_keys {
                    return false;
                }
            }
            self.buckets.insert(
                key.clone(),
                Bucket {
                    milli_tokens: cap,
                    last_ms: now_ms,
                },
            );
        }
        let Some(b) = self.buckets.get_mut(key) else {
            return false;
        };
        let elapsed = now_ms.saturating_sub(b.last_ms);
        b.milli_tokens = (b.milli_tokens + elapsed * self.refill_per_sec).min(cap);
        b.last_ms = now_ms.max(b.last_ms);
        let need = u64::from(cost) * 1000;
        if b.milli_tokens >= need {
            b.milli_tokens -= need;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refill() {
        let mut rl = RateLimiter::new(3, 1, 10);
        let k = "peer-a";
        assert!(rl.allow(&k, 1, 0));
        assert!(rl.allow(&k, 1, 0));
        assert!(rl.allow(&k, 1, 0));
        assert!(!rl.allow(&k, 1, 0));
        assert!(!rl.allow(&k, 1, 500));
        assert!(rl.allow(&k, 1, 1000));
        // Other keys are independent.
        assert!(rl.allow(&"peer-b", 3, 1000));
    }

    #[test]
    fn bounded_number_of_keys() {
        let mut rl = RateLimiter::new(1, 0, 2);
        assert!(rl.allow(&1, 1, 0));
        assert!(rl.allow(&2, 1, 0));
        // Both buckets are empty (not idle), so a third key is refused.
        assert!(!rl.allow(&3, 1, 0));
    }
}
