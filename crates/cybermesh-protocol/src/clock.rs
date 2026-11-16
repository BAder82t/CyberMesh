use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Source of the current Unix time in seconds. Injected so expiry logic is testable.
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> u64;
}

/// Wall-clock time.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        // A clock before the epoch is broken; fail closed (everything looks expired) rather
        // than open (nothing ever expires).
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(u64::MAX / 2, |d| d.as_secs())
    }
}

/// A settable clock for tests and simulations.
#[derive(Debug, Default, Clone)]
pub struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    #[must_use]
    pub fn new(t: u64) -> Self {
        Self(Arc::new(AtomicU64::new(t)))
    }
    pub fn set(&self, t: u64) {
        self.0.store(t, Ordering::SeqCst);
    }
    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
