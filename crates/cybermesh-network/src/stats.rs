use std::sync::atomic::{AtomicU64, Ordering};

/// Network counters (shared, lock-free).
#[derive(Debug, Default)]
pub struct NetStats {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub messages_in: AtomicU64,
    pub messages_out: AtomicU64,
    pub dropped_rate_limited: AtomicU64,
    pub dropped_queue_full: AtomicU64,
    pub rejected_unknown_author: AtomicU64,
    pub rejected_by_application: AtomicU64,
    pub publish_failures: AtomicU64,
    pub connected_peers: AtomicU64,
    /// Authors with a negative score: they recently sent provably invalid messages
    /// (`peer_scoring`).
    pub penalised_peers: AtomicU64,
    /// Messages dropped because their author is graylisted.
    pub dropped_penalised: AtomicU64,
}

/// A plain snapshot of [`NetStats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetStatsSnapshot {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub messages_in: u64,
    pub messages_out: u64,
    pub dropped_rate_limited: u64,
    pub dropped_queue_full: u64,
    pub rejected_unknown_author: u64,
    pub rejected_by_application: u64,
    pub publish_failures: u64,
    pub connected_peers: u64,
    pub penalised_peers: u64,
    pub dropped_penalised: u64,
}

impl NetStats {
    pub(crate) fn add(c: &AtomicU64, v: u64) {
        c.fetch_add(v, Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> NetStatsSnapshot {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        NetStatsSnapshot {
            bytes_in: g(&self.bytes_in),
            bytes_out: g(&self.bytes_out),
            messages_in: g(&self.messages_in),
            messages_out: g(&self.messages_out),
            dropped_rate_limited: g(&self.dropped_rate_limited),
            dropped_queue_full: g(&self.dropped_queue_full),
            rejected_unknown_author: g(&self.rejected_unknown_author),
            rejected_by_application: g(&self.rejected_by_application),
            publish_failures: g(&self.publish_failures),
            connected_peers: g(&self.connected_peers),
            penalised_peers: g(&self.penalised_peers),
            dropped_penalised: g(&self.dropped_penalised),
        }
    }
}
