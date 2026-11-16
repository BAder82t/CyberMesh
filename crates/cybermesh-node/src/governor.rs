//! Worker resource governor.
//!
//! Enforcement here is *cooperative*, inside the worker process:
//! * CPU: a token bucket on process CPU time. Credit accrues at `cpu_percent` of wall time
//!   (capped at one window's worth) and is spent by measured process CPU, including
//!   networking. When credit is negative the worker sleeps before starting more work.
//! * Memory: tasks are not started while resident memory exceeds the budget.
//! * Load: tasks are not started while the 1-minute load average per CPU exceeds a limit.
//! * Working hours and administrator PAUSE/STOP files.
//!
//! Hard OS-level limits (cgroups via systemd `CPUQuota=`/`MemoryMax=` or Docker
//! `cpus`/`mem_limit`) are recommended in addition; see `deploy/`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::NodeError;

/// Administrator-defined limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcePolicy {
    /// Average process CPU ceiling, percent of one core.
    pub cpu_percent: f64,
    /// Averaging window in seconds (also the maximum burst credit).
    pub cpu_window_secs: u64,
    /// Resident memory budget in MiB.
    pub memory_mb: u64,
    /// Pause while 1-minute load average per CPU exceeds this.
    pub max_load_per_cpu: f64,
    /// Outbound application bandwidth in KiB/s (0 = unlimited).
    pub outbound_kib_per_sec: u64,
    /// Tasks queued at most; further assigned tasks are dropped.
    pub max_queue: usize,
    /// Allowed UTC windows, `HH:MM-HH:MM` (may wrap midnight).
    pub active_hours_utc: Vec<String>,
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        Self {
            cpu_percent: 1.0,
            cpu_window_secs: 60,
            memory_mb: 200,
            max_load_per_cpu: 0.8,
            outbound_kib_per_sec: 64,
            max_queue: 16,
            active_hours_utc: vec!["00:00-24:00".into()],
        }
    }
}

fn parse_hhmm(s: &str) -> Option<u64> {
    let (h, m) = s.split_once(':')?;
    let h: u64 = h.parse().ok()?;
    let m: u64 = m.parse().ok()?;
    if h > 24 || m > 59 || (h == 24 && m != 0) {
        return None;
    }
    Some(h * 3600 + m * 60)
}

fn parse_window(s: &str) -> Option<(u64, u64)> {
    let (a, b) = s.split_once('-')?;
    Some((parse_hhmm(a.trim())?, parse_hhmm(b.trim())?))
}

impl ResourcePolicy {
    pub fn validate(&self) -> Result<(), NodeError> {
        if !(self.cpu_percent > 0.0 && self.cpu_percent <= 100.0) {
            return Err(NodeError::Config("cpu_percent must be in (0, 100]".into()));
        }
        if self.cpu_window_secs == 0 || self.max_queue == 0 || self.memory_mb == 0 {
            return Err(NodeError::Config(
                "cpu_window_secs, max_queue and memory_mb must be positive".into(),
            ));
        }
        for w in &self.active_hours_utc {
            if parse_window(w).is_none() {
                return Err(NodeError::Config(format!("bad active hours window {w}")));
            }
        }
        Ok(())
    }

    /// Whether `unix_secs` falls inside an allowed window.
    #[must_use]
    pub fn within_hours(&self, unix_secs: u64) -> bool {
        let t = unix_secs % 86_400;
        self.active_hours_utc.iter().filter_map(|w| parse_window(w)).any(|(a, b)| {
            if a <= b {
                t >= a && t < b
            } else {
                t >= a || t < b
            }
        })
    }
}

/// Why the worker is not taking work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PauseReason {
    Administrator,
    OutsideWorkingHours,
    SystemLoad,
    MemoryBudget,
    CpuBudget,
}

/// Governor decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Run,
    Pause(PauseReason),
    Stop,
}

/// Point-in-time resource measurements.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    pub cpu_seconds: f64,
    pub wall_seconds: f64,
    /// Average process CPU since start, percent of one core.
    pub cpu_percent_avg: f64,
    pub rss_bytes: u64,
    pub load_per_cpu: Option<f64>,
}

/// Process CPU time (user + system).
#[must_use]
pub fn process_cpu() -> Duration {
    cpu_time::ProcessTime::try_now()
        .map(|t| t.as_duration())
        .unwrap_or_default()
}

/// Resident set size in bytes.
#[must_use]
pub fn rss_bytes() -> u64 {
    memory_stats::memory_stats().map_or(0, |m| m.physical_mem as u64)
}

/// 1-minute load average divided by available CPUs.
#[must_use]
pub fn load_per_cpu() -> Option<f64> {
    let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get) as f64;
    let one = if cfg!(target_os = "linux") {
        std::fs::read_to_string("/proc/loadavg")
            .ok()?
            .split_whitespace()
            .next()?
            .parse::<f64>()
            .ok()?
    } else if cfg!(target_os = "macos") {
        let out = std::process::Command::new("/usr/sbin/sysctl")
            .args(["-n", "vm.loadavg"])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .find_map(|t| t.parse::<f64>().ok())?
    } else {
        return None;
    };
    Some(one / cpus)
}

/// The governor.
#[derive(Debug)]
pub struct Governor {
    policy: ResourcePolicy,
    control_dir: PathBuf,
    started: Instant,
    cpu_at_start: Duration,
    /// CPU-seconds of credit.
    credit: f64,
    last_wall: Instant,
    last_cpu: Duration,
    last_load_check: Option<(Instant, Option<f64>)>,
}

impl Governor {
    #[must_use]
    pub fn new(policy: ResourcePolicy, control_dir: &Path) -> Self {
        let now = Instant::now();
        let cpu = process_cpu();
        Self {
            credit: policy.cpu_percent / 100.0 * policy.cpu_window_secs as f64,
            policy,
            control_dir: control_dir.to_owned(),
            started: now,
            cpu_at_start: cpu,
            last_wall: now,
            last_cpu: cpu,
            last_load_check: None,
        }
    }

    #[must_use]
    pub fn policy(&self) -> &ResourcePolicy {
        &self.policy
    }

    fn refresh_credit(&mut self) {
        let now = Instant::now();
        let cpu = process_cpu();
        let dt = now.duration_since(self.last_wall).as_secs_f64();
        let used = cpu.saturating_sub(self.last_cpu).as_secs_f64();
        let f = self.policy.cpu_percent / 100.0;
        let cap = f * self.policy.cpu_window_secs as f64;
        self.credit = (self.credit + f * dt - used).min(cap);
        self.last_wall = now;
        self.last_cpu = cpu;
    }

    /// How long to sleep before starting more work to stay within the CPU budget.
    pub fn cpu_wait(&mut self) -> Option<Duration> {
        self.refresh_credit();
        if self.credit >= 0.0 {
            return None;
        }
        let f = self.policy.cpu_percent / 100.0;
        Some(Duration::from_secs_f64((-self.credit / f).min(3600.0)))
    }

    fn load(&mut self) -> Option<f64> {
        let now = Instant::now();
        match self.last_load_check {
            Some((t, v)) if now.duration_since(t) < Duration::from_secs(10) => v,
            _ => {
                let v = load_per_cpu();
                self.last_load_check = Some((now, v));
                v
            }
        }
    }

    /// Evaluates administrator controls and policy.
    pub fn decide(&mut self, unix_now: u64) -> Decision {
        if self.control_dir.join("STOP").exists() {
            return Decision::Stop;
        }
        if self.control_dir.join("PAUSE").exists() {
            return Decision::Pause(PauseReason::Administrator);
        }
        if !self.policy.within_hours(unix_now) {
            return Decision::Pause(PauseReason::OutsideWorkingHours);
        }
        if rss_bytes() > self.policy.memory_mb * 1024 * 1024 {
            return Decision::Pause(PauseReason::MemoryBudget);
        }
        if self.load().is_some_and(|l| l > self.policy.max_load_per_cpu) {
            return Decision::Pause(PauseReason::SystemLoad);
        }
        Decision::Run
    }

    #[must_use]
    pub fn snapshot(&self) -> ResourceSnapshot {
        let cpu = process_cpu().saturating_sub(self.cpu_at_start).as_secs_f64();
        let wall = self.started.elapsed().as_secs_f64();
        ResourceSnapshot {
            cpu_seconds: cpu,
            wall_seconds: wall,
            cpu_percent_avg: if wall > 0.0 { cpu / wall * 100.0 } else { 0.0 },
            rss_bytes: rss_bytes(),
            load_per_cpu: self.last_load_check.and_then(|(_, v)| v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn working_hours() {
        let p = ResourcePolicy {
            active_hours_utc: vec!["09:00-17:00".into()],
            ..ResourcePolicy::default()
        };
        assert!(p.within_hours(10 * 3600));
        assert!(!p.within_hours(8 * 3600));
        assert!(!p.within_hours(17 * 3600));
        let night = ResourcePolicy {
            active_hours_utc: vec!["22:00-06:00".into()],
            ..ResourcePolicy::default()
        };
        assert!(night.within_hours(23 * 3600));
        assert!(night.within_hours(3600));
        assert!(!night.within_hours(12 * 3600));
        assert!(ResourcePolicy::default().within_hours(86_399));
        let bad = ResourcePolicy {
            active_hours_utc: vec!["25:00-26:00".into()],
            ..ResourcePolicy::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn admin_controls() {
        let dir = tempfile::tempdir().unwrap();
        // Ignore real host load and memory so the test is deterministic.
        let mut g = Governor::new(
            ResourcePolicy {
                max_load_per_cpu: f64::MAX,
                memory_mb: 1 << 20,
                ..ResourcePolicy::default()
            },
            dir.path(),
        );
        assert_eq!(g.decide(12 * 3600), Decision::Run);
        std::fs::write(dir.path().join("PAUSE"), b"").unwrap();
        assert_eq!(g.decide(12 * 3600), Decision::Pause(PauseReason::Administrator));
        std::fs::write(dir.path().join("STOP"), b"").unwrap();
        assert_eq!(g.decide(12 * 3600), Decision::Stop);
    }

    #[test]
    fn memory_budget_pauses() {
        let dir = tempfile::tempdir().unwrap();
        let mut g = Governor::new(
            ResourcePolicy {
                memory_mb: 1,
                ..ResourcePolicy::default()
            },
            dir.path(),
        );
        assert_eq!(g.decide(0), Decision::Pause(PauseReason::MemoryBudget));
    }

    #[test]
    fn cpu_budget_throttles_busy_work() {
        let dir = tempfile::tempdir().unwrap();
        // 1% of a core with a 1 s window: 10 ms of credit.
        let mut g = Governor::new(
            ResourcePolicy {
                cpu_percent: 1.0,
                cpu_window_secs: 1,
                ..ResourcePolicy::default()
            },
            dir.path(),
        );
        // Burn ~60 ms of CPU.
        let start = Instant::now();
        let mut x = 0u64;
        while start.elapsed() < Duration::from_millis(60) {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        }
        std::hint::black_box(x);
        let wait = g.cpu_wait().expect("must throttle after exceeding budget");
        // ~50 ms over budget at 1% => ~5 s of wait.
        assert!(wait > Duration::from_secs(2), "{wait:?}");
    }
}
