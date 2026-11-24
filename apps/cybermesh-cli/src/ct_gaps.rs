//! Holes in the tile coverage that verification records show (`cybermesh ct report`).
//!
//! A signed CT verification record names the log and the tile range of its task. An issuer
//! (the coordinator) that never tasks some tiles leaves no record of them, and a task that was
//! abandoned or never verified leaves a record that is not `verified`: either way those tiles
//! are missing from the report, and a name that sits in them disappears from it without a
//! word. [`coverage_gaps`] finds the holes from the records alone, as interval arithmetic, so a
//! log of millions of tiles costs nothing.
//!
//! It finds holes *between* verified ranges of a log. Tiles after the last verified one are
//! not a hole: records do not say how large the log was.

use std::collections::BTreeMap;

use serde::Serialize;

/// A half-open range of tiles `[start, end)`.
type Range = (u64, u64);

/// One CT task as its record states it: log id, first tile, tile count, and whether the record
/// is `verified`.
pub type Task<'a> = (&'a str, u64, u32, bool);

/// Why a run of tiles has no verified record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GapState {
    /// No record of any status names these tiles: they were never tasked, or their records are
    /// not among those given.
    NoRecord,
    /// A record names them, but it is disputed or insufficient, not verified.
    AttemptedNotVerified,
}

/// A run of tiles of one log with no verified record, inside the span the verified records
/// of that log cover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Gap {
    pub log_id: String,
    pub first_tile: u64,
    pub tile_count: u64,
    pub state: GapState,
}

impl Gap {
    /// The last tile of the run.
    #[must_use]
    pub fn last_tile(&self) -> u64 {
        self.first_tile + self.tile_count.saturating_sub(1)
    }
}

/// Sorted, non-overlapping, non-empty ranges covering the same tiles as `v`.
fn merge(mut v: Vec<Range>) -> Vec<Range> {
    v.retain(|(a, b)| a < b);
    v.sort_unstable();
    let mut out: Vec<Range> = Vec::with_capacity(v.len());
    for (a, b) in v {
        match out.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out
}

/// The tiles in `a` that are not in `b` (both sorted and non-overlapping).
fn subtract(a: &[Range], b: &[Range]) -> Vec<Range> {
    let mut out = Vec::new();
    for &(start, end) in a {
        let mut at = start;
        for &(bs, be) in b {
            if be <= at || bs >= end {
                continue;
            }
            if bs > at {
                out.push((at, bs));
            }
            at = at.max(be);
            if at >= end {
                break;
            }
        }
        if at < end {
            out.push((at, end));
        }
    }
    out
}

/// The tiles in both `a` and `b` (both sorted and non-overlapping).
fn intersect(a: &[Range], b: &[Range]) -> Vec<Range> {
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    while i < a.len() && j < b.len() {
        let (lo, hi) = (a[i].0.max(b[j].0), a[i].1.min(b[j].1));
        if lo < hi {
            out.push((lo, hi));
        }
        if a[i].1 < b[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

fn range_of(first: u64, count: u32) -> Range {
    (first, first.saturating_add(u64::from(count)))
}

/// The holes in the tile coverage of each log, sorted by log and first tile.
///
/// For a log with verified tasks: the tiles between its first and last verified tile that no
/// verified task covers, split by whether a non-verified record names them. For a log with
/// none verified, every tile its non-verified records name.
#[must_use]
pub fn coverage_gaps(tasks: &[Task<'_>]) -> Vec<Gap> {
    let mut by_log: BTreeMap<&str, (Vec<Range>, Vec<Range>)> = BTreeMap::new();
    for &(log, first, count, verified) in tasks {
        let (ok, not_ok) = by_log.entry(log).or_default();
        if verified {
            ok.push(range_of(first, count));
        } else {
            not_ok.push(range_of(first, count));
        }
    }
    let mut gaps = Vec::new();
    for (log, (ok, not_ok)) in by_log {
        let (ok, attempted) = (merge(ok), merge(not_ok));
        let (Some(first), Some(last)) = (ok.first(), ok.last()) else {
            // Nothing verified for this log at all.
            for (a, b) in attempted {
                gaps.push(Gap {
                    log_id: log.to_owned(),
                    first_tile: a,
                    tile_count: b - a,
                    state: GapState::AttemptedNotVerified,
                });
            }
            continue;
        };
        let holes = subtract(&[(first.0, last.1)], &ok);
        let mut found: Vec<Gap> = intersect(&holes, &attempted)
            .into_iter()
            .map(|r| (r, GapState::AttemptedNotVerified))
            .chain(
                subtract(&holes, &attempted)
                    .into_iter()
                    .map(|r| (r, GapState::NoRecord)),
            )
            .map(|((a, b), state)| Gap {
                log_id: log.to_owned(),
                first_tile: a,
                tile_count: b - a,
                state,
            })
            .collect();
        found.sort_by_key(|g| g.first_tile);
        gaps.extend(found);
    }
    gaps
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "log-a";

    fn gap(log: &str, first: u64, count: u64, state: GapState) -> Gap {
        Gap {
            log_id: log.to_owned(),
            first_tile: first,
            tile_count: count,
            state,
        }
    }

    #[test]
    fn contiguous_coverage_has_no_gaps_even_with_duplicate_and_overlapping_records() {
        // Two verifiers each wrote a record for the same task; a later task overlaps by one.
        let tasks: Vec<Task> = vec![
            (LOG, 0, 2, true),
            (LOG, 0, 2, true),
            (LOG, 2, 2, true),
            (LOG, 3, 3, true),
        ];
        assert_eq!(coverage_gaps(&tasks), vec![]);
        assert_eq!(coverage_gaps(&[]), vec![]);
        assert_eq!(
            coverage_gaps(&[(LOG, 7, 4, true)]),
            vec![],
            "one task alone"
        );
    }

    #[test]
    fn a_range_nobody_tasked_is_a_gap_with_no_record() {
        // The demo's four tasks with the one for tiles 2 and 3 missing.
        let tasks: Vec<Task> = vec![(LOG, 0, 2, true), (LOG, 4, 2, true), (LOG, 6, 2, true)];
        let gaps = coverage_gaps(&tasks);
        assert_eq!(gaps, vec![gap(LOG, 2, 2, GapState::NoRecord)]);
        assert_eq!(gaps[0].last_tile(), 3);
    }

    #[test]
    fn a_task_that_was_not_verified_is_told_apart_from_one_never_issued() {
        // Tiles 2-3 were tasked but disputed. Tiles 6-7 were never tasked.
        let tasks: Vec<Task> = vec![
            (LOG, 0, 2, true),
            (LOG, 2, 2, false),
            (LOG, 4, 2, true),
            (LOG, 8, 2, true),
        ];
        assert_eq!(
            coverage_gaps(&tasks),
            vec![
                gap(LOG, 2, 2, GapState::AttemptedNotVerified),
                gap(LOG, 6, 2, GapState::NoRecord),
            ]
        );
        // A hole only partly named by an unverified record splits in two.
        let tasks: Vec<Task> = vec![(LOG, 0, 2, true), (LOG, 3, 1, false), (LOG, 8, 2, true)];
        assert_eq!(
            coverage_gaps(&tasks),
            vec![
                gap(LOG, 2, 1, GapState::NoRecord),
                gap(LOG, 3, 1, GapState::AttemptedNotVerified),
                gap(LOG, 4, 4, GapState::NoRecord),
            ]
        );
    }

    #[test]
    fn a_task_that_was_verified_by_one_verifier_but_not_another_is_not_a_gap() {
        // Verifier A verified tiles 2-3, verifier B's record is insufficient: still covered.
        let tasks: Vec<Task> = vec![
            (LOG, 0, 2, true),
            (LOG, 2, 2, true),
            (LOG, 2, 2, false),
            (LOG, 4, 2, true),
        ];
        assert_eq!(coverage_gaps(&tasks), vec![]);
    }

    #[test]
    fn logs_are_independent_and_a_log_with_nothing_verified_is_listed() {
        let tasks: Vec<Task> = vec![
            ("log-a", 0, 2, true),
            ("log-a", 4, 2, true),
            ("log-b", 100, 2, true),
            ("log-b", 102, 2, true),
            // Only unverified records for this one.
            ("log-c", 10, 2, false),
            ("log-c", 12, 2, false),
            ("log-c", 20, 1, false),
        ];
        assert_eq!(
            coverage_gaps(&tasks),
            vec![
                gap("log-a", 2, 2, GapState::NoRecord),
                gap("log-c", 10, 4, GapState::AttemptedNotVerified),
                gap("log-c", 20, 1, GapState::AttemptedNotVerified),
            ]
        );
    }

    #[test]
    fn the_end_of_the_log_is_not_a_gap() {
        // Nothing after the last verified tile can be called missing: the log's size is unknown.
        let tasks: Vec<Task> = vec![(LOG, 0, 2, true), (LOG, 2, 2, true)];
        assert_eq!(coverage_gaps(&tasks), vec![]);
    }

    #[test]
    fn huge_logs_cost_nothing_and_the_end_of_the_range_does_not_overflow() {
        let tasks: Vec<Task> = vec![
            (LOG, 0, u32::MAX, true),
            (LOG, 10_000_000_000, u32::MAX, true),
            (LOG, u64::MAX - 5, u32::MAX, true),
        ];
        let gaps = coverage_gaps(&tasks);
        assert_eq!(gaps.len(), 2, "{gaps:?}");
        assert_eq!(gaps[0].first_tile, u64::from(u32::MAX));
        assert_eq!(gaps[0].tile_count, 10_000_000_000 - u64::from(u32::MAX));
        assert!(gaps.iter().all(|g| g.state == GapState::NoRecord));
    }

    #[test]
    fn the_helpers_agree_with_a_tile_by_tile_count_on_small_cases() {
        // Every pair of ranges inside 0..8: the interval functions equal a per-tile set.
        let set = |r: &[Range]| -> std::collections::BTreeSet<u64> {
            r.iter().flat_map(|&(a, b)| a..b).collect()
        };
        let all: Vec<Range> = (0..8u64)
            .flat_map(|a| (a..=8).map(move |b| (a, b)))
            .collect();
        for x in &all {
            for y in &all {
                let (a, b) = (merge(vec![*x]), merge(vec![*y]));
                let (sa, sb) = (set(&a), set(&b));
                assert_eq!(
                    set(&subtract(&a, &b)),
                    sa.difference(&sb).copied().collect(),
                    "{x:?} - {y:?}"
                );
                assert_eq!(
                    set(&intersect(&a, &b)),
                    sa.intersection(&sb).copied().collect(),
                    "{x:?} & {y:?}"
                );
            }
        }
        assert_eq!(
            merge(vec![(5, 6), (0, 2), (2, 3), (9, 9)]),
            vec![(0, 3), (5, 6)]
        );
    }
}
