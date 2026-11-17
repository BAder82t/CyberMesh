//! Following a CT log as it grows (`[ct] follow = true`).
//!
//! The coordinator polls the log's checkpoint, verified against the pinned key, fresh, and
//! proven to extend the last checkpoint it accepted. It schedules the newly completed full
//! tiles as shard tasks. Progress survives restarts: `ct-follow.json` stores the last
//! accepted signed head (so consistency is checked across restarts too) and a resume point,
//! the low-water mark below which every scheduled tile has been **verified**. Batches that
//! were given up (abandoned, or not verified after their attempts) are retried on later polls,
//! up to [`MAX_RETRIES`] times; tiles still unverified after that keep the resume point pinned,
//! so a restart scans them again. A restart therefore never skips tiles; at worst it re-scans
//! some that were already verified.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use cybermesh_crypto::Digest;
use cybermesh_ct::Checkpoint;
use serde::{Deserialize, Serialize};

use crate::NodeError;
use crate::files;

/// Times a given-up batch is scheduled again before it is left for a restart.
pub const MAX_RETRIES: u32 = 3;

/// A signed tree head accepted earlier (persisted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHead {
    pub size: u64,
    pub root: Digest,
    pub signed_at_ms: u64,
}

/// `ct-follow.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FollowState {
    pub log_id: String,
    /// Every tile below this one has been settled.
    pub resume_from: u64,
    pub head: Option<SignedHead>,
}

/// Scheduling state of one followed log.
#[derive(Debug)]
pub struct Follower {
    path: PathBuf,
    log_id: String,
    /// Next tile to schedule.
    next_tile: u64,
    /// Without saved state or an explicit start: start this many tiles before the end of the
    /// first accepted checkpoint.
    start_window: Option<u64>,
    /// Scheduled but not yet settled: first tile -> tile count.
    in_progress: BTreeMap<u64, u32>,
    /// Given up (not verified): first tile -> (tile count, times retried).
    failed: BTreeMap<u64, (u32, u32)>,
    head: Option<Checkpoint>,
    until_tile: Option<u64>,
    tiles_per_task: u32,
    max_tiles_per_poll: u64,
}

impl Follower {
    /// Resumes from `path` if it holds state for `log_id`; otherwise starts at `start`, or,
    /// if `None`, `window` tiles before the end of the first accepted checkpoint.
    pub fn load_or_start(
        path: &Path,
        log_id: &str,
        start: Option<u64>,
        window: u64,
        until_tile: Option<u64>,
        tiles_per_task: u32,
        max_tiles_per_poll: u64,
    ) -> Result<Self, NodeError> {
        let state: Option<FollowState> = if path.exists() {
            Some(files::read_json(path)?)
        } else {
            None
        };
        let state = state.filter(|s| s.log_id == log_id);
        let head = state
            .as_ref()
            .and_then(|s| s.head.as_ref())
            .map(|h| Checkpoint {
                origin: String::new(),
                size: h.size,
                root: h.root.0,
                signed_at_ms: h.signed_at_ms,
            });
        Ok(Self {
            path: path.to_path_buf(),
            log_id: log_id.to_owned(),
            next_tile: state.as_ref().map(|s| s.resume_from).or(start).unwrap_or(0),
            start_window: (state.is_none() && start.is_none()).then_some(window),
            in_progress: BTreeMap::new(),
            failed: BTreeMap::new(),
            head,
            until_tile,
            tiles_per_task: tiles_per_task.max(1),
            max_tiles_per_poll: max_tiles_per_poll.max(1),
        })
    }

    /// The last accepted checkpoint (the next one must provably extend it).
    #[must_use]
    pub fn head(&self) -> Option<&Checkpoint> {
        self.head.as_ref()
    }

    /// Records a newly accepted (verified, fresh, consistent) checkpoint.
    pub fn accept_head(&mut self, cp: Checkpoint) {
        if let Some(w) = self.start_window.take() {
            self.next_tile = cp.full_tiles().saturating_sub(w);
        }
        self.head = Some(cp);
    }

    /// Schedules newly completed tiles: at most `max_tiles_per_poll` per call, none while
    /// `pending` scheduled batches are waiting (backpressure), never beyond `until_tile`.
    /// Returns `(first_tile, tile_count)` batches.
    pub fn schedule(&mut self, pending: usize, max_pending: usize) -> Vec<(u64, u32)> {
        let Some(full) = self.head.as_ref().map(Checkpoint::full_tiles) else {
            return Vec::new();
        };
        let limit = self.until_tile.map_or(full, |u| u.min(full));
        let mut out = Vec::new();
        let mut budget = self.max_tiles_per_poll;
        let mut waiting = pending;
        while self.next_tile < limit && budget > 0 && waiting < max_pending {
            let n = u64::from(self.tiles_per_task)
                .min(limit - self.next_tile)
                .min(budget);
            let n32 = u32::try_from(n).unwrap_or(1);
            out.push((self.next_tile, n32));
            self.in_progress.insert(self.next_tile, n32);
            self.next_tile += n;
            budget -= n;
            waiting += 1;
        }
        out
    }

    /// A scheduled batch was verified.
    pub fn verified(&mut self, first_tile: u64) {
        self.in_progress.remove(&first_tile);
        self.failed.remove(&first_tile);
    }

    /// A scheduled batch was given up (abandoned, or not verified after its attempts).
    pub fn gave_up(&mut self, first_tile: u64, count: u32) {
        self.in_progress.remove(&first_tile);
        let retries = self.failed.get(&first_tile).map_or(0, |(_, r)| *r);
        self.failed.insert(first_tile, (count, retries));
    }

    /// Given-up batches to schedule again (each at most [`MAX_RETRIES`] times).
    pub fn retries(&mut self) -> Vec<(u64, u32)> {
        let mut out = Vec::new();
        for (first, (count, retries)) in &mut self.failed {
            if *retries < MAX_RETRIES && !self.in_progress.contains_key(first) {
                *retries += 1;
                out.push((*first, *count));
            }
        }
        for (first, count) in &out {
            self.in_progress.insert(*first, *count);
        }
        out
    }

    /// Tiles given up for good in this run (they stay below the resume point).
    #[must_use]
    pub fn unverified_tiles(&self) -> u64 {
        self.failed
            .iter()
            .filter(|(f, (_, r))| *r >= MAX_RETRIES && !self.in_progress.contains_key(f))
            .map(|(_, (c, _))| u64::from(*c))
            .sum()
    }

    /// Clears the accepted head (an operator reset after investigating an inconsistency);
    /// the resume point is kept.
    pub fn reset_head(&mut self) {
        self.head = None;
    }

    /// Every tile below this has been verified.
    #[must_use]
    pub fn resume_from(&self) -> u64 {
        let in_progress = self.in_progress.keys().next().copied();
        let failed = self.failed.keys().next().copied();
        [in_progress, failed]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(self.next_tile)
            .min(self.next_tile)
    }

    /// Full tiles in the log not yet scheduled.
    #[must_use]
    pub fn lag(&self) -> u64 {
        self.head
            .as_ref()
            .map_or(0, |h| h.full_tiles().saturating_sub(self.next_tile))
    }

    #[must_use]
    pub fn next_tile(&self) -> u64 {
        self.next_tile
    }

    /// With `until_tile`: everything below it was scheduled and is verified or given up for
    /// good (those tiles stay below the resume point for a later run).
    #[must_use]
    pub fn done(&self) -> bool {
        self.until_tile.is_some_and(|u| {
            self.next_tile >= u
                && self.in_progress.is_empty()
                && self.failed.values().all(|(_, r)| *r >= MAX_RETRIES)
        })
    }

    /// Writes `ct-follow.json` atomically.
    pub fn persist(&self) -> Result<(), NodeError> {
        let state = FollowState {
            log_id: self.log_id.clone(),
            resume_from: self.resume_from(),
            head: self.head.as_ref().map(|h| SignedHead {
                size: h.size,
                root: Digest(h.root),
                signed_at_ms: h.signed_at_ms,
            }),
        };
        files::write_json(&self.path, &state)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn cp(size: u64) -> Checkpoint {
        Checkpoint {
            origin: "o".into(),
            size,
            root: [size as u8; 32],
            signed_at_ms: 1,
        }
    }

    #[test]
    fn schedules_new_tiles_with_backpressure_and_resumes_at_the_low_water_mark() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ct-follow.json");
        let mut f = Follower::load_or_start(&path, "log", Some(10), 0, None, 4, 8).unwrap();
        assert!(f.schedule(0, 10).is_empty(), "nothing before a checkpoint");
        f.accept_head(cp(256 * 30)); // 30 full tiles
        // At most 8 tiles per poll.
        assert_eq!(f.schedule(0, 10), vec![(10, 4), (14, 4)]);
        assert_eq!(f.lag(), 30 - 18);
        // Backpressure: two batches already waiting with a cap of 3 allows one more.
        assert_eq!(f.schedule(2, 3), vec![(18, 4)]);
        // Out-of-order settlement: the resume point is the first unsettled batch.
        f.verified(14);
        assert_eq!(f.resume_from(), 10);
        f.persist().unwrap();
        // A restart resumes there and keeps the signed head for the consistency check.
        let r = Follower::load_or_start(&path, "log", Some(0), 0, None, 4, 8).unwrap();
        assert_eq!(r.next_tile(), 10);
        assert_eq!(r.head().map(|h| h.size), Some(256 * 30));
        // State for another log is ignored.
        let other = Follower::load_or_start(&path, "other", Some(3), 0, None, 4, 8).unwrap();
        assert_eq!((other.next_tile(), other.head().is_none()), (3, true));
        f.verified(10);
        f.verified(18);
        assert_eq!(f.resume_from(), 22);
    }

    #[test]
    fn given_up_batches_are_retried_and_never_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.json");
        let mut f = Follower::load_or_start(&path, "log", Some(0), 0, Some(8), 4, 100).unwrap();
        f.accept_head(cp(256 * 8));
        assert_eq!(f.schedule(0, 10), vec![(0, 4), (4, 4)]);
        // Tiles 0-3 were abandoned (no workers); 4-7 verified.
        f.gave_up(0, 4);
        f.verified(4);
        assert_eq!(f.resume_from(), 0, "unverified tiles keep the resume point");
        assert!(!f.done());
        // Retried on later polls, at most MAX_RETRIES times.
        for _ in 0..MAX_RETRIES {
            assert_eq!(f.retries(), vec![(0, 4)]);
            assert!(f.retries().is_empty(), "not while in progress");
            f.gave_up(0, 4);
        }
        assert!(f.retries().is_empty());
        assert_eq!(f.unverified_tiles(), 4);
        // A bounded run can end, but the state still points at the unverified tiles.
        assert!(f.done());
        f.persist().unwrap();
        let r = Follower::load_or_start(&path, "log", Some(0), 0, Some(8), 4, 100).unwrap();
        assert_eq!(r.next_tile(), 0);
        // A later verification clears it.
        f.retries();
        let mut f2 = r;
        f2.accept_head(cp(256 * 8));
        assert_eq!(f2.schedule(0, 10), vec![(0, 4), (4, 4)]);
        f2.verified(0);
        f2.verified(4);
        assert_eq!(f2.resume_from(), 8);
    }

    #[test]
    fn without_a_start_the_first_checkpoint_sets_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let mut f =
            Follower::load_or_start(&dir.path().join("w.json"), "log", None, 3, None, 2, 100)
                .unwrap();
        f.accept_head(cp(256 * 1000));
        assert_eq!(f.schedule(0, 10), vec![(997, 2), (999, 1)]);
        // Later checkpoints do not move the start.
        f.accept_head(cp(256 * 1001));
        assert_eq!(f.schedule(0, 10), vec![(1000, 1)]);
    }

    #[test]
    fn until_tile_bounds_scheduling_and_ends_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = Follower::load_or_start(
            &dir.path().join("s.json"),
            "log",
            Some(0),
            0,
            Some(6),
            4,
            100,
        )
        .unwrap();
        f.accept_head(cp(256 * 4));
        assert_eq!(f.schedule(0, 10), vec![(0, 4)]);
        assert!(!f.done());
        f.accept_head(cp(256 * 20));
        assert_eq!(f.schedule(0, 10), vec![(4, 2)]);
        f.verified(0);
        assert!(!f.done());
        f.verified(4);
        assert!(f.done());
        assert!(f.schedule(0, 10).is_empty());
    }
}
