//! Early warning that the signed trust manifest is about to expire.
//!
//! A node stops accepting work when its manifest expires (the worker's state becomes
//! `manifest-expired`; a verifier ignores tasks; a coordinator stops issuing them). Until now
//! nothing said so beforehand. [`ExpiryWatch`] decides, from the manifest's expiry and the clock
//! alone, when a node should log a reminder:
//!
//! * from 7 days before: a warning every 6 hours;
//! * from 1 day before: an error every hour;
//! * once expired: an error every hour.
//!
//! A change of level logs at once, and a renewed manifest (expiry far away again) resets it. A
//! renewal needs no restart: the node reloads the manifest file every minute and takes a valid
//! one with a higher sequence number.

use std::path::PathBuf;

use tracing::{error, warn};

/// A manifest with fewer seconds than this left earns a warning.
pub const WARN_WITHIN_SECS: u64 = 7 * 86_400;
/// With fewer than this left, the reminder is an error.
pub const URGENT_WITHIN_SECS: u64 = 86_400;
const WARN_EVERY_SECS: u64 = 6 * 3_600;
const URGENT_EVERY_SECS: u64 = 3_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Less than 7 days left.
    Warning,
    /// Less than 1 day left.
    Urgent,
    /// Past its expiry.
    Expired,
}

/// How close `expires_at` is to `now`, or `None` if it is more than 7 days away.
#[must_use]
pub fn level(expires_at: u64, now: u64) -> Option<Level> {
    if now >= expires_at {
        Some(Level::Expired)
    } else if expires_at - now < URGENT_WITHIN_SECS {
        Some(Level::Urgent)
    } else if expires_at - now < WARN_WITHIN_SECS {
        Some(Level::Warning)
    } else {
        None
    }
}

/// A duration as `3 day(s) 4 hour(s)`, `5 hour(s)` or `12 minute(s)`.
#[must_use]
pub fn duration_text(secs: u64) -> String {
    let (d, h) = (secs / 86_400, (secs % 86_400) / 3_600);
    match (d, h) {
        (0, 0) => format!("{} minute(s)", secs / 60),
        (0, h) => format!("{h} hour(s)"),
        (d, 0) => format!("{d} day(s)"),
        (d, h) => format!("{d} day(s) {h} hour(s)"),
    }
}

/// A reminder that is due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub level: Level,
    pub message: String,
}

impl Notice {
    /// Writes the reminder to the log: a warning, or an error when urgent or expired.
    pub fn log(&self) {
        match self.level {
            Level::Warning => warn!("{}", self.message),
            Level::Urgent | Level::Expired => error!("{}", self.message),
        }
    }
}

/// Remembers when the last reminder was logged, so reminders are neither missed nor repeated
/// on every tick.
#[derive(Debug, Default)]
pub struct ExpiryWatch {
    manifest_file: Option<PathBuf>,
    last: Option<(Level, u64)>,
}

impl ExpiryWatch {
    /// `manifest_file` is the file the node reloads its manifest from, named in the message.
    #[must_use]
    pub fn new(manifest_file: Option<PathBuf>) -> Self {
        Self {
            manifest_file,
            last: None,
        }
    }

    /// The reminder due at `now` for a manifest expiring at `expires_at`, if any.
    pub fn due(&mut self, expires_at: u64, now: u64) -> Option<Notice> {
        let Some(level) = level(expires_at, now) else {
            self.last = None;
            return None;
        };
        let every = match level {
            Level::Warning => WARN_EVERY_SECS,
            Level::Urgent | Level::Expired => URGENT_EVERY_SECS,
        };
        if let Some((last_level, at)) = self.last
            && last_level == level
            && now.saturating_sub(at) < every
        {
            return None;
        }
        self.last = Some((level, now));
        let file = self.manifest_file.as_ref().map_or_else(
            || "its manifest file".to_owned(),
            |p| p.display().to_string(),
        );
        let renew = format!(
            "ask governance for a renewed manifest (a higher sequence number) and replace {file}: \
             the node loads it within a minute, with no restart"
        );
        let message = match level {
            Level::Warning | Level::Urgent => format!(
                "the trust manifest expires in {}: {renew}. A node accepts no work once it has expired",
                duration_text(expires_at - now)
            ),
            Level::Expired => format!(
                "the trust manifest expired {} ago, so this node accepts no work: {renew}",
                duration_text(now - expires_at)
            ),
        };
        Some(Notice { level, message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPIRES: u64 = 1_800_000_000;
    const DAY: u64 = 86_400;

    fn watch() -> ExpiryWatch {
        ExpiryWatch::new(Some(PathBuf::from("/etc/cybermesh/manifest.json")))
    }

    #[test]
    fn the_level_follows_the_time_left() {
        assert_eq!(level(EXPIRES, EXPIRES - 30 * DAY), None);
        assert_eq!(
            level(EXPIRES, EXPIRES - 7 * DAY),
            None,
            "exactly 7 days is not yet a warning"
        );
        assert_eq!(level(EXPIRES, EXPIRES - 7 * DAY + 1), Some(Level::Warning));
        assert_eq!(
            level(EXPIRES, EXPIRES - DAY),
            Some(Level::Warning),
            "exactly 1 day is still a warning"
        );
        assert_eq!(level(EXPIRES, EXPIRES - DAY + 1), Some(Level::Urgent));
        assert_eq!(level(EXPIRES, EXPIRES - 1), Some(Level::Urgent));
        assert_eq!(level(EXPIRES, EXPIRES), Some(Level::Expired));
        assert_eq!(level(EXPIRES, EXPIRES + 50 * DAY), Some(Level::Expired));
    }

    #[test]
    fn a_healthy_manifest_is_never_mentioned() {
        let mut w = watch();
        for d in [365, 100, 30, 8] {
            assert_eq!(w.due(EXPIRES, EXPIRES - d * DAY), None);
        }
    }

    #[test]
    fn the_warning_comes_once_then_every_six_hours() {
        let mut w = watch();
        let start = EXPIRES - 6 * DAY;
        let first = w.due(EXPIRES, start).expect("a warning at once");
        assert_eq!(first.level, Level::Warning);
        // The next ticks, a minute apart, say nothing.
        for i in 1..=5 {
            assert_eq!(w.due(EXPIRES, start + 60 * i), None);
        }
        assert_eq!(w.due(EXPIRES, start + 6 * 3_600 - 1), None);
        assert_eq!(
            w.due(EXPIRES, start + 6 * 3_600).map(|n| n.level),
            Some(Level::Warning)
        );
        assert_eq!(w.due(EXPIRES, start + 6 * 3_600 + 60), None);
    }

    #[test]
    fn it_escalates_at_once_and_then_repeats_hourly() {
        let mut w = watch();
        // A warning a minute before it turns urgent.
        let urgent_at = EXPIRES - DAY + 1;
        assert_eq!(
            w.due(EXPIRES, urgent_at - 60).map(|n| n.level),
            Some(Level::Warning)
        );
        // The change of level is not held back by the six-hour interval.
        assert_eq!(
            w.due(EXPIRES, urgent_at).map(|n| n.level),
            Some(Level::Urgent)
        );
        assert_eq!(w.due(EXPIRES, urgent_at + 3_599), None);
        assert_eq!(
            w.due(EXPIRES, urgent_at + 3_600).map(|n| n.level),
            Some(Level::Urgent)
        );
        // An hour before the end, and a second before it: only the first is due.
        assert_eq!(
            w.due(EXPIRES, EXPIRES - 3_600).map(|n| n.level),
            Some(Level::Urgent)
        );
        assert_eq!(
            w.due(EXPIRES, EXPIRES - 1),
            None,
            "an hour has not passed since the last"
        );
        // The change to expired is reported at once; then hourly for as long as it stays so.
        assert_eq!(
            w.due(EXPIRES, EXPIRES).map(|n| n.level),
            Some(Level::Expired)
        );
        assert_eq!(w.due(EXPIRES, EXPIRES + 3_599), None);
        assert_eq!(
            w.due(EXPIRES, EXPIRES + 3_600).map(|n| n.level),
            Some(Level::Expired)
        );
    }

    #[test]
    fn a_renewed_manifest_resets_it() {
        let mut w = watch();
        let now = EXPIRES - 2 * DAY;
        assert!(w.due(EXPIRES, now).is_some());
        assert_eq!(w.due(EXPIRES, now + 60), None);
        // Governance renews: the new expiry is a year away, so nothing is said...
        let renewed = now + 365 * DAY;
        assert_eq!(w.due(renewed, now + 120), None);
        // ...and when that one nears its end, the warning comes at once, not after six hours.
        let later = renewed - 3 * DAY;
        assert_eq!(w.due(renewed, later).map(|n| n.level), Some(Level::Warning));
    }

    #[test]
    fn the_message_says_how_long_and_what_to_do() {
        let mut w = watch();
        let n = w.due(EXPIRES, EXPIRES - 3 * DAY - 4 * 3_600).unwrap();
        assert!(
            n.message.contains("expires in 3 day(s) 4 hour(s)"),
            "{}",
            n.message
        );
        assert!(
            n.message.contains("/etc/cybermesh/manifest.json"),
            "{}",
            n.message
        );
        assert!(
            n.message.contains("higher sequence number"),
            "{}",
            n.message
        );
        assert!(n.message.contains("no restart"), "{}", n.message);
        let n = ExpiryWatch::default()
            .due(EXPIRES, EXPIRES + 2 * 3_600)
            .unwrap();
        assert!(n.message.contains("expired 2 hour(s) ago"), "{}", n.message);
        assert!(n.message.contains("accepts no work"), "{}", n.message);
        assert!(n.message.contains("its manifest file"), "{}", n.message);
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(duration_text(30 * 60), "30 minute(s)");
        assert_eq!(duration_text(5 * 3_600), "5 hour(s)");
        assert_eq!(duration_text(2 * DAY), "2 day(s)");
        assert_eq!(duration_text(2 * DAY + 3_600), "2 day(s) 1 hour(s)");
    }
}
