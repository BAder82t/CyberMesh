//! `cybermesh ct evaluate`: scores a `ct watch` run against independently confirmed phishing,
//! as fixed in `docs/ct-evaluation.md`.
//!
//! Inputs, all inside the run directory:
//! - what `ct watch` wrote (`runs.jsonl`, `polls.jsonl`, `matches.jsonl`, `names/`);
//! - `feeds/phishunt/<UTC>.csv.gz`: hourly phishunt snapshots (`scripts/ct-eval.sh`);
//! - `feeds/openphish/<UTC>.txt.gz`: OpenPhish community feed snapshots exported from its git
//!   history (`scripts/ct-eval.sh history`), named by commit time.
//!
//! Output: `report.json` (every number in the evaluation) and `fp-sample.csv` (unconfirmed
//! warn-level names, stratified by brand, for labelling by hand).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead as _, BufReader, Read as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use clap::Args;
use cybermesh_analysis::{EvidenceBundle, normalize_domain};
use cybermesh_protocol::Verdict;
use flate2::read::GzDecoder;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::ct_watch::{MatchRecord, PollRecord};
use crate::util::write_json;

const HOUR_MS: u64 = 3_600_000;
/// A pause between two polls of one log longer than this counts as downtime.
const GAP_MS: u64 = 120_000;

#[derive(Args, Debug, Clone)]
pub struct EvaluateArgs {
    /// Run directory (`ct watch --out`, with `feeds/` from `scripts/ct-eval.sh`).
    #[arg(long)]
    pub run: PathBuf,
    /// Evidence bundle of the run (protected brands, for the in-scope figures).
    #[arg(long)]
    pub evidence: PathBuf,
    /// Only certificates logged at or after this time (ms since the epoch). Default: the
    /// run's start. Use with `--to-ms` for the dev/test split.
    #[arg(long)]
    pub from_ms: Option<u64>,
    /// Only certificates logged before this time (ms). Default: the last poll.
    #[arg(long)]
    pub to_ms: Option<u64>,
    /// Hosts first confirmed within this long after `--from-ms` are left out of recall: their
    /// certificate most likely predates the window.
    #[arg(long, default_value_t = 24)]
    pub burn_in_hours: u64,
    /// Size of the false-alarm sample.
    #[arg(long, default_value_t = 200)]
    pub sample: usize,
    /// Output directory for `report.json` and `fp-sample.csv`.
    #[arg(long)]
    pub out: PathBuf,
}

// ---------------------------------------------------------------------------------------
// Small parsers (no external dependencies).

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn num(s: &str) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// (year, month, day), (hour, minute, second), milliseconds and UTC offset in minutes.
fn to_ms(
    (y, mo, d): (i64, i64, i64),
    (h, mi, s): (i64, i64, i64),
    frac_ms: i64,
    off_min: i64,
) -> Option<u64> {
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s - off_min * 60;
    u64::try_from(secs * 1000 + frac_ms).ok()
}

/// ISO 8601 / RFC 3339 timestamp (`2026-11-18T17:23:31.342658+00:00`, `...Z`) to ms.
pub fn parse_iso_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    let (date, rest) = s.split_at_checked(10)?;
    let mut dp = date.split('-');
    let (y, mo, d) = (num(dp.next()?)?, num(dp.next()?)?, num(dp.next()?)?);
    let rest = rest.strip_prefix('T').or_else(|| rest.strip_prefix(' '))?;
    let (time, zone) = match rest.find(['Z', 'z', '+', '-']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "Z"),
    };
    let (hms, frac) = time.split_once('.').unwrap_or((time, ""));
    let mut tp = hms.split(':');
    let (h, mi, sec) = (num(tp.next()?)?, num(tp.next()?)?, num(tp.next()?)?);
    let frac_ms = if frac.is_empty() {
        0
    } else {
        let f: String = frac.chars().chain("000".chars()).take(3).collect();
        num(&f)?
    };
    let off_min = if zone.eq_ignore_ascii_case("z") {
        0
    } else {
        let sign = if zone.starts_with('-') { -1 } else { 1 };
        let (oh, om) = zone[1..]
            .split_once(':')
            .unwrap_or((zone.get(1..3)?, zone.get(3..)?));
        sign * (num(oh)? * 60 + num(om)?)
    };
    to_ms((y, mo, d), (h, mi, sec), frac_ms, off_min)
}

/// Snapshot file name `20261118T173918Z...` to ms.
pub fn parse_snapshot_ms(name: &str) -> Option<u64> {
    let b = name.get(..16)?;
    if b.as_bytes().get(8) != Some(&b'T') || b.as_bytes().get(15) != Some(&b'Z') {
        return None;
    }
    to_ms(
        (num(&b[0..4])?, num(&b[4..6])?, num(&b[6..8])?),
        (num(&b[9..11])?, num(&b[11..13])?, num(&b[13..15])?),
        0,
        0,
    )
}

/// RFC 4180 CSV (quoted fields, doubled quotes, CRLF or LF).
pub fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    field.push('"');
                    chars.next();
                }
                '"' => quoted = false,
                _ => field.push(c),
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => quoted = true,
            ',' => row.push(std::mem::take(&mut field)),
            '\r' => {}
            '\n' => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// The host of a URL (scheme optional), normalised like certificate names. `None` for IP
/// literals and anything that is not a valid domain name.
pub fn url_host(url: &str) -> Option<String> {
    let u = url.trim();
    let u = u.split_once("://").map_or(u, |(_, r)| r);
    let auth = u.split(['/', '?', '#']).next()?;
    let auth = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    if auth.starts_with('[') {
        return None;
    }
    let host = auth.split(':').next()?;
    normalize_domain(host).ok()
}

/// 95 % Wilson score interval.
#[must_use]
pub fn wilson(k: u64, n: u64) -> Option<(f64, f64)> {
    if n == 0 {
        return None;
    }
    let (k, n, z) = (k as f64, n as f64, 1.96_f64);
    let p = k / n;
    let den = 1.0 + z * z / n;
    let mid = (p + z * z / (2.0 * n)) / den;
    let half = z * (p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt() / den;
    Some(((mid - half).max(0.0), (mid + half).min(1.0)))
}

fn parent(h: &str) -> Option<&str> {
    h.split_once('.')
        .map(|(_, p)| p)
        .filter(|p| p.contains('.'))
}

/// `h` and each of its parent domains (`a.b.c` → `a.b.c`, `b.c`, `c`).
fn suffixes(h: &str) -> impl Iterator<Item = &str> {
    std::iter::once(h).chain(h.match_indices('.').map(move |(i, _)| &h[i + 1..]))
}

fn min_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

fn set_min(slot: &mut Option<u64>, v: u64) {
    *slot = Some(slot.map_or(v, |x| x.min(v)));
}

// ---------------------------------------------------------------------------------------
// Ground truth.

/// What the feeds say about one host.
#[derive(Debug, Default, Clone)]
pub struct Truth {
    /// First OpenPhish community feed listing (commit time).
    pub openphish_ms: Option<u64>,
    /// First phishunt snapshot showing Google Safe Browsing or PhishTank.
    pub gsb_phishtank_ms: Option<u64>,
    /// First phishunt snapshot showing any third-party flag (also OpenPhish, urlscan,
    /// TweetFeed): the broader, secondary ground truth.
    pub any_flag_ms: Option<u64>,
    /// phishunt's own detection (`first_seen`) and first snapshot listing it.
    pub phishunt_first_seen_ms: Option<u64>,
    pub phishunt_listed_ms: Option<u64>,
    pub company: Option<String>,
}

impl Truth {
    /// Primary confirmation: OpenPhish, Google Safe Browsing or PhishTank.
    #[must_use]
    pub fn primary(&self) -> Option<u64> {
        min_opt(self.openphish_ms, self.gsb_phishtank_ms)
    }

    /// Secondary confirmation: the primary sources plus any other third-party flag.
    #[must_use]
    pub fn broad(&self) -> Option<u64> {
        min_opt(self.primary(), self.any_flag_ms)
    }
}

#[derive(Debug, Default, Serialize)]
pub struct FeedStats {
    pub phishunt_snapshots: usize,
    pub openphish_snapshots: usize,
    pub phishunt_rows: u64,
    pub openphish_urls: u64,
    /// Listed URLs whose host is an IP literal or not a valid domain name: never visible in
    /// CT, and left out of the host-level figures.
    pub not_a_domain: u64,
    pub first_snapshot_ms: Option<u64>,
    pub last_snapshot_ms: Option<u64>,
}

fn read_gz(path: &Path) -> Result<String> {
    let mut s = String::new();
    let mut d =
        GzDecoder::new(File::open(path).with_context(|| format!("open {}", path.display()))?);
    // A truncated stream (interrupted write) keeps what was decoded.
    let mut buf = Vec::new();
    let _ = d.read_to_end(&mut buf);
    s.push_str(&String::from_utf8_lossy(&buf));
    Ok(s)
}

fn snapshots(dir: &Path) -> Result<Vec<(u64, PathBuf)>> {
    let mut v = Vec::new();
    if !dir.is_dir() {
        return Ok(v);
    }
    for e in fs::read_dir(dir)? {
        let p = e?.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if let Some(t) = parse_snapshot_ms(name) {
            v.push((t, p));
        }
    }
    v.sort();
    Ok(v)
}

fn flag(row: &[String], col: Option<usize>) -> bool {
    col.and_then(|c| row.get(c))
        .is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

/// Reads every phishunt and OpenPhish snapshot of the run.
pub fn load_truth(run: &Path) -> Result<(HashMap<String, Truth>, FeedStats)> {
    let mut truth: HashMap<String, Truth> = HashMap::new();
    let mut st = FeedStats::default();
    let ph = snapshots(&run.join("feeds/phishunt"))?;
    let op = snapshots(&run.join("feeds/openphish"))?;
    st.phishunt_snapshots = ph.len();
    st.openphish_snapshots = op.len();
    for (t, p) in &ph {
        set_min(&mut st.first_snapshot_ms, *t);
        st.last_snapshot_ms = st.last_snapshot_ms.max(Some(*t));
        let rows = parse_csv(&read_gz(p)?);
        let Some((header, rows)) = rows.split_first() else {
            continue;
        };
        let col = |n: &str| header.iter().position(|h| h == n);
        let (c_url, c_dom, c_co, c_first) =
            (col("url"), col("domain"), col("company"), col("first_seen"));
        let (c_g, c_pt, c_op, c_us, c_tf) = (
            col("malicious_google"),
            col("malicious_phishtank"),
            col("malicious_openphish"),
            col("malicious_urlscan"),
            col("malicious_tweetfeed"),
        );
        for row in rows {
            if row.len() < header.len() {
                continue;
            }
            st.phishunt_rows += 1;
            let host = c_dom
                .and_then(|c| row.get(c))
                .and_then(|d| normalize_domain(d).ok())
                .or_else(|| c_url.and_then(|c| row.get(c)).and_then(|u| url_host(u)));
            let Some(host) = host else {
                st.not_a_domain += 1;
                continue;
            };
            let e = truth.entry(host).or_default();
            set_min(&mut e.phishunt_listed_ms, *t);
            if let Some(fs) = c_first
                .and_then(|c| row.get(c))
                .and_then(|s| parse_iso_ms(s))
            {
                set_min(&mut e.phishunt_first_seen_ms, fs);
            }
            if e.company.is_none() {
                e.company = c_co
                    .and_then(|c| row.get(c))
                    .filter(|c| !c.is_empty())
                    .cloned();
            }
            if flag(row, c_g) || flag(row, c_pt) {
                set_min(&mut e.gsb_phishtank_ms, *t);
            }
            if flag(row, c_g)
                || flag(row, c_pt)
                || flag(row, c_op)
                || flag(row, c_us)
                || flag(row, c_tf)
            {
                set_min(&mut e.any_flag_ms, *t);
            }
        }
    }
    for (t, p) in &op {
        set_min(&mut st.first_snapshot_ms, *t);
        st.last_snapshot_ms = st.last_snapshot_ms.max(Some(*t));
        for line in read_gz(p)?.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            st.openphish_urls += 1;
            match url_host(line) {
                Some(h) => set_min(&mut truth.entry(h).or_default().openphish_ms, *t),
                None => st.not_a_domain += 1,
            }
        }
    }
    Ok((truth, st))
}

// ---------------------------------------------------------------------------------------
// What the run saw and flagged.

/// One flagged name: its first occurrence in the window.
#[derive(Debug, Clone)]
pub struct Flag {
    pub first_ts: u64,
    pub first_seen_ms: u64,
    /// Earliest occurrence listed as `*.name` (covers `label.name`).
    pub wildcard_ts: Option<u64>,
    pub verdict: Verdict,
    pub risk_score_bp: u16,
    pub brands: BTreeSet<String>,
    pub codes: BTreeSet<String>,
}

fn is_warn(v: Verdict) -> bool {
    matches!(v, Verdict::Suspicious | Verdict::Malicious)
}

/// Flag levels, from broadest to strictest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Signal,
    Warn,
    Block,
}

impl Level {
    pub const ALL: [Level; 3] = [Level::Signal, Level::Warn, Level::Block];

    fn name(self) -> &'static str {
        match self {
            Level::Signal => "signal",
            Level::Warn => "warn",
            Level::Block => "block",
        }
    }

    fn admits(self, v: Verdict) -> bool {
        match self {
            Level::Signal => true,
            Level::Warn => is_warn(v),
            Level::Block => v == Verdict::Malicious,
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct RunStats {
    pub start_ms: u64,
    pub window_from_ms: u64,
    pub window_to_ms: u64,
    pub starts: usize,
    pub logs: Vec<String>,
    pub tiles_scanned: u64,
    pub entries_scanned: u64,
    pub unparsed_entries: u64,
    pub name_segments: usize,
    pub truncated_segments: usize,
    pub match_lines: u64,
    pub match_lines_unreadable: u64,
    pub flagged_names: usize,
    /// Pauses longer than two minutes between polls, per log: (from, to) in ms.
    pub downtime: BTreeMap<String, Vec<(u64, u64)>>,
    pub downtime_ms: BTreeMap<String, u64>,
    pub events: BTreeMap<String, u64>,
}

fn jsonl<T: serde::de::DeserializeOwned>(path: &Path, bad: &mut u64) -> Result<Vec<T>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str(&line) {
            Ok(v) => out.push(v),
            Err(_) => *bad += 1,
        }
    }
    Ok(out)
}

fn run_stats(run: &Path) -> Result<RunStats> {
    let mut bad = 0;
    let runs: Vec<serde_json::Value> = jsonl(&run.join("runs.jsonl"), &mut bad)?;
    let start = runs
        .iter()
        .filter_map(|r| r.get("started_ms").and_then(serde_json::Value::as_u64))
        .min()
        .context("runs.jsonl: no start")?;
    let polls: Vec<PollRecord> = jsonl(&run.join("polls.jsonl"), &mut bad)?;
    let mut st = RunStats {
        start_ms: start,
        starts: runs.len(),
        ..RunStats::default()
    };
    let mut by_log: BTreeMap<String, Vec<&PollRecord>> = BTreeMap::new();
    for p in &polls {
        st.tiles_scanned += p.tiles;
        st.entries_scanned += p.entries;
        st.unparsed_entries += p.unparsed;
        st.window_to_ms = st.window_to_ms.max(p.t_ms + p.elapsed_ms);
        by_log.entry(p.log.clone()).or_default().push(p);
    }
    for (log, ps) in &by_log {
        let mut gaps = Vec::new();
        for w in ps.windows(2) {
            let end = w[0].t_ms + w[0].elapsed_ms;
            if w[1].t_ms > end + GAP_MS {
                gaps.push((end, w[1].t_ms));
            }
        }
        st.downtime_ms
            .insert(log.clone(), gaps.iter().map(|(a, b)| b - a).sum());
        st.downtime.insert(log.clone(), gaps);
    }
    st.logs = by_log.keys().cloned().collect();
    let events: Vec<crate::ct_watch::EventRecord> = jsonl(&run.join("events.jsonl"), &mut bad)?;
    for e in events {
        *st.events.entry(e.kind).or_default() += 1;
    }
    Ok(st)
}

/// Earliest log timestamp at which each tracked host (or registrable domain) appeared in a
/// certificate, from the name segments.
#[derive(Debug, Default)]
struct Observed {
    host: HashMap<String, u64>,
    regdom: HashMap<String, u64>,
}

fn scan_names(
    run: &Path,
    hosts: &HashSet<&str>,
    by_parent: &HashMap<&str, Vec<&str>>,
    regdoms: &HashSet<&str>,
    window: (u64, u64),
    st: &mut RunStats,
) -> Result<Observed> {
    let mut obs = Observed::default();
    let root = run.join("names");
    let mut files = Vec::new();
    if root.is_dir() {
        for log in fs::read_dir(&root)? {
            let log = log?.path();
            if log.is_dir() {
                for f in fs::read_dir(&log)? {
                    files.push(f?.path());
                }
            }
        }
    }
    files.sort();
    st.name_segments = files.len();
    for f in files {
        let mut r = BufReader::with_capacity(1 << 20, GzDecoder::new(File::open(&f)?));
        let mut line = String::new();
        loop {
            line.clear();
            match r.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => {
                    st.truncated_segments += 1;
                    break;
                }
            }
            let mut c = line.trim_end_matches('\n').split('\t');
            let (Some(_), Some(ts), Some(names), Some(wild)) =
                (c.next(), c.next(), c.next(), c.next())
            else {
                continue;
            };
            if names == "!unparsed" {
                continue;
            }
            let Ok(ts) = ts.parse::<u64>() else { continue };
            if ts < window.0 || ts >= window.1 {
                continue;
            }
            for n in names.split(' ').filter(|n| !n.is_empty()) {
                if hosts.contains(n) {
                    let e = obs.host.entry(n.to_owned()).or_insert(ts);
                    *e = (*e).min(ts);
                }
                for s in suffixes(n) {
                    if regdoms.contains(s) {
                        let e = obs.regdom.entry(s.to_owned()).or_insert(ts);
                        *e = (*e).min(ts);
                    }
                }
            }
            for w in wild.split(' ').filter(|w| !w.is_empty()) {
                if let Some(hs) = by_parent.get(w) {
                    for h in hs {
                        let e = obs.host.entry((*h).to_owned()).or_insert(ts);
                        *e = (*e).min(ts);
                    }
                }
            }
        }
    }
    Ok(obs)
}

fn load_flags(run: &Path, window: (u64, u64), st: &mut RunStats) -> Result<HashMap<String, Flag>> {
    let mut flags: HashMap<String, Flag> = HashMap::new();
    let path = run.join("matches.jsonl");
    if !path.exists() {
        return Ok(flags);
    }
    for line in BufReader::with_capacity(1 << 20, File::open(&path)?).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        st.match_lines += 1;
        let Ok(m) = serde_json::from_str::<MatchRecord>(&line) else {
            st.match_lines_unreadable += 1;
            continue;
        };
        if m.ts_ms < window.0 || m.ts_ms >= window.1 {
            continue;
        }
        let f = flags.entry(m.name.clone()).or_insert_with(|| Flag {
            first_ts: m.ts_ms,
            first_seen_ms: m.seen_ms,
            wildcard_ts: None,
            verdict: m.verdict,
            risk_score_bp: m.risk_score_bp,
            brands: BTreeSet::new(),
            codes: BTreeSet::new(),
        });
        if m.ts_ms < f.first_ts {
            f.first_ts = m.ts_ms;
            f.first_seen_ms = m.seen_ms;
        }
        if m.wildcard {
            set_min(&mut f.wildcard_ts, m.ts_ms);
        }
        if m.risk_score_bp > f.risk_score_bp {
            f.risk_score_bp = m.risk_score_bp;
            f.verdict = m.verdict;
        }
        f.brands.extend(m.brands);
        // The engine's own (kebab-case) code names.
        f.codes.extend(m.codes.iter().filter_map(|c| {
            serde_json::to_value(c)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
        }));
    }
    st.flagged_names = flags.len();
    Ok(flags)
}

/// Earliest flag at `level` that covers host `h`: the name itself, or a wildcard
/// certificate for its parent.
fn flag_ts(flags: &HashMap<String, Flag>, h: &str, level: Level) -> Option<(u64, u64)> {
    let exact = flags
        .get(h)
        .filter(|f| level.admits(f.verdict))
        .map(|f| (f.first_ts, f.first_seen_ms));
    let wild = parent(h)
        .and_then(|p| flags.get(p))
        .filter(|f| level.admits(f.verdict))
        .and_then(|f| f.wildcard_ts.map(|t| (t, f.first_seen_ms.max(t))));
    match (exact, wild) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (a, None) => a,
        (None, b) => b,
    }
}

// ---------------------------------------------------------------------------------------
// The report.

#[derive(Debug, Default, Clone, Serialize)]
pub struct Proportion {
    pub k: u64,
    pub n: u64,
    pub p: Option<f64>,
    pub ci95: Option<(f64, f64)>,
}

impl Proportion {
    fn of(k: u64, n: u64) -> Self {
        Self {
            k,
            n,
            p: (n > 0).then(|| k as f64 / n as f64),
            ci95: wilson(k, n),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Quantiles {
    pub n: usize,
    pub p10: Option<f64>,
    pub p25: Option<f64>,
    pub median: Option<f64>,
    pub p75: Option<f64>,
    pub p90: Option<f64>,
}

fn quantiles(mut v: Vec<f64>) -> Quantiles {
    v.sort_by(f64::total_cmp);
    let q = |p: f64| {
        (!v.is_empty()).then(|| {
            let x = p * (v.len() - 1) as f64;
            let (lo, hi) = (x.floor() as usize, x.ceil() as usize);
            v[lo] + (v[hi] - v[lo]) * (x - lo as f64)
        })
    };
    Quantiles {
        n: v.len(),
        p10: q(0.10),
        p25: q(0.25),
        median: q(0.5),
        p75: q(0.75),
        p90: q(0.9),
    }
}

/// Recall and lead time against one definition of ground truth.
#[derive(Debug, Default, Serialize)]
pub struct Detection {
    /// Confirmed hosts in the recall window.
    pub confirmed: u64,
    /// ...with a certificate in the followed logs before confirmation.
    pub observability: Proportion,
    /// Flagged before confirmation, among observable hosts, per level.
    pub recall: BTreeMap<String, Proportion>,
    /// Flagged before confirmation, among all confirmed hosts (end to end), per level.
    pub recall_end_to_end: BTreeMap<String, Proportion>,
    /// Hours from the flagged certificate's log time to confirmation, per level.
    pub lead_hours: BTreeMap<String, Quantiles>,
    /// The same, by registrable domain.
    pub regdom_confirmed: u64,
    pub regdom_observability: Proportion,
    pub regdom_recall: BTreeMap<String, Proportion>,
}

#[derive(Debug, Default, Serialize)]
pub struct Precision {
    /// Distinct names flagged in the window, per level.
    pub flagged: BTreeMap<String, u64>,
    /// Share confirmed by the primary sources by the last snapshot: a lower bound.
    pub confirmed_primary: BTreeMap<String, Proportion>,
    pub confirmed_broad: BTreeMap<String, Proportion>,
    /// Warn-level names per brand: (flagged, confirmed by any source).
    pub warn_by_brand: BTreeMap<String, (u64, u64)>,
}

#[derive(Debug, Default, Serialize)]
pub struct PeerComparison {
    /// Hosts phishunt listed during the window.
    pub phishunt_listed: u64,
    /// ...that appeared in the followed logs before phishunt listed them.
    pub phishunt_listed_observable: u64,
    /// Of those, the share CyberMesh flagged (signal, warn).
    pub flagged_of_phishunt_observable: BTreeMap<String, Proportion>,
    /// Of CyberMesh's warn-level names, the share phishunt also listed.
    pub phishunt_of_warn: Proportion,
    /// Hosts both flagged: hours from CyberMesh's scan to phishunt's `first_seen`
    /// (positive: CyberMesh was earlier).
    pub cybermesh_earlier_hours: Quantiles,
    pub cybermesh_earlier: Proportion,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub method: &'static str,
    pub run: RunStats,
    pub feeds: FeedStats,
    pub recall_window_from_ms: u64,
    pub recall_window_to_ms: u64,
    pub primary: Detection,
    pub broad: Detection,
    /// Hosts whose phishunt `company` is a protected brand.
    pub in_scope_primary: Detection,
    pub per_source_lead_hours: BTreeMap<String, Quantiles>,
    /// Scan time minus log time of each flagged name's first certificate (seconds).
    pub detection_latency_secs: Quantiles,
    pub precision: Precision,
    pub phishunt: PeerComparison,
    pub fp_sample_size: usize,
}

fn detection(
    hosts: &[(&str, u64)],
    obs: &Observed,
    flags: &HashMap<String, Flag>,
    regdom_of: &HashMap<&str, String>,
    regflags: &HashMap<String, BTreeMap<&'static str, u64>>,
) -> Detection {
    let mut d = Detection {
        confirmed: hosts.len() as u64,
        ..Detection::default()
    };
    let observable: Vec<&(&str, u64)> = hosts
        .iter()
        .filter(|(h, c)| obs.host.get(*h).is_some_and(|t| t <= c))
        .collect();
    d.observability = Proportion::of(observable.len() as u64, d.confirmed);
    for level in Level::ALL {
        let mut hit = 0u64;
        let mut lead = Vec::new();
        for (h, c) in &observable {
            if let Some((t, _)) = flag_ts(flags, h, level).filter(|(t, _)| t <= c) {
                hit += 1;
                lead.push((c - t) as f64 / HOUR_MS as f64);
            }
        }
        d.recall.insert(
            level.name().into(),
            Proportion::of(hit, observable.len() as u64),
        );
        d.recall_end_to_end
            .insert(level.name().into(), Proportion::of(hit, d.confirmed));
        d.lead_hours.insert(level.name().into(), quantiles(lead));
    }
    // By registrable domain: confirmed at its earliest host's confirmation.
    let mut reg: HashMap<&str, u64> = HashMap::new();
    for (h, c) in hosts {
        if let Some(r) = regdom_of.get(h) {
            let e = reg.entry(r.as_str()).or_insert(*c);
            *e = (*e).min(*c);
        }
    }
    d.regdom_confirmed = reg.len() as u64;
    let reg_obs: Vec<(&str, u64)> = reg
        .iter()
        .filter(|(r, c)| obs.regdom.get(**r).is_some_and(|t| t <= *c))
        .map(|(r, c)| (*r, *c))
        .collect();
    d.regdom_observability = Proportion::of(reg_obs.len() as u64, d.regdom_confirmed);
    for level in Level::ALL {
        let hit = reg_obs
            .iter()
            .filter(|(r, c)| {
                regflags
                    .get(*r)
                    .and_then(|m| m.get(level.name()))
                    .is_some_and(|t| t <= c)
            })
            .count() as u64;
        d.regdom_recall.insert(
            level.name().into(),
            Proportion::of(hit, reg_obs.len() as u64),
        );
    }
    d
}

fn slug(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Deterministic rank for sampling.
fn rank(name: &str) -> [u8; 32] {
    Sha256::digest(format!("cybermesh/fp-sample/v1\0{name}")).into()
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

fn utc(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Inverse of days_from_civil.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// Runs the evaluation and writes `report.json` and `fp-sample.csv` to `a.out`.
pub fn run(a: &EvaluateArgs) -> Result<Report> {
    let ev = EvidenceBundle::load(&a.evidence)?;
    let brands: HashSet<String> = ev.brands.iter().map(|b| slug(&b.name)).collect();
    let mut st = run_stats(&a.run)?;
    let from = a.from_ms.unwrap_or(st.start_ms);
    let to = a.to_ms.unwrap_or(st.window_to_ms);
    if to <= from {
        bail!("empty window: --to-ms must be after --from-ms (and the run must have polls)");
    }
    st.window_from_ms = from;
    st.window_to_ms = to;
    let (truth, feeds) = load_truth(&a.run)?;
    let confirmed_until = feeds.last_snapshot_ms.unwrap_or(to);
    let recall_from = from + a.burn_in_hours * HOUR_MS;

    // Everything the name scan must look up.
    let host_list: Vec<&str> = truth.keys().map(String::as_str).collect();
    let hosts: HashSet<&str> = host_list.iter().copied().collect();
    let mut by_parent: HashMap<&str, Vec<&str>> = HashMap::new();
    for h in &host_list {
        if let Some(p) = parent(h) {
            by_parent.entry(p).or_default().push(h);
        }
    }
    let regdom_of: HashMap<&str, String> = host_list
        .iter()
        .filter_map(|h| psl::domain_str(h).map(|r| (*h, r.to_owned())))
        .collect();
    let regdoms: HashSet<&str> = regdom_of.values().map(String::as_str).collect();
    let obs = scan_names(&a.run, &hosts, &by_parent, &regdoms, (from, to), &mut st)?;
    let flags = load_flags(&a.run, (from, to), &mut st)?;
    let mut regflags: HashMap<String, BTreeMap<&'static str, u64>> = HashMap::new();
    for (name, f) in &flags {
        for s in suffixes(name) {
            if regdoms.contains(s) {
                let m = regflags.entry(s.to_owned()).or_default();
                for level in Level::ALL.into_iter().filter(|l| l.admits(f.verdict)) {
                    let e = m.entry(level.name()).or_insert(f.first_ts);
                    *e = (*e).min(f.first_ts);
                }
            }
        }
    }

    let in_window = |c: Option<u64>| c.filter(|c| *c >= recall_from && *c <= confirmed_until);
    let primary: Vec<(&str, u64)> = truth
        .iter()
        .filter_map(|(h, t)| in_window(t.primary()).map(|c| (h.as_str(), c)))
        .collect();
    let broad: Vec<(&str, u64)> = truth
        .iter()
        .filter_map(|(h, t)| in_window(t.broad()).map(|c| (h.as_str(), c)))
        .collect();
    let in_scope: Vec<(&str, u64)> = primary
        .iter()
        .filter(|(h, _)| {
            truth[*h]
                .company
                .as_deref()
                .is_some_and(|c| brands.contains(&slug(c)))
        })
        .copied()
        .collect();
    let mut rep = Report {
        method: "docs/ct-evaluation.md",
        recall_window_from_ms: recall_from,
        recall_window_to_ms: confirmed_until,
        primary: detection(&primary, &obs, &flags, &regdom_of, &regflags),
        broad: detection(&broad, &obs, &flags, &regdom_of, &regflags),
        in_scope_primary: detection(&in_scope, &obs, &flags, &regdom_of, &regflags),
        ..Report::default()
    };

    // Lead time against each primary source separately (warn level).
    for (src, pick) in [
        (
            "openphish",
            (|t: &Truth| t.openphish_ms) as fn(&Truth) -> Option<u64>,
        ),
        ("gsb_phishtank", |t: &Truth| t.gsb_phishtank_ms),
    ] {
        let lead = truth
            .iter()
            .filter_map(|(h, t)| {
                let c = in_window(pick(t))?;
                obs.host.get(h.as_str()).filter(|o| **o <= c)?;
                let (ts, _) = flag_ts(&flags, h, Level::Warn).filter(|(ts, _)| *ts <= c)?;
                Some((c - ts) as f64 / HOUR_MS as f64)
            })
            .collect();
        rep.per_source_lead_hours
            .insert(src.into(), quantiles(lead));
    }
    rep.detection_latency_secs = quantiles(
        flags
            .values()
            .map(|f| f.first_seen_ms.saturating_sub(f.first_ts) as f64 / 1000.0)
            .collect(),
    );

    // Precision (lower bound): flagged names later confirmed (any time up to the last
    // snapshot), directly or as the parent of a confirmed host under a wildcard.
    let mut confirmed_children: HashMap<&str, (bool, bool)> = HashMap::new();
    for (h, t) in &truth {
        if let Some(p) = parent(h) {
            let e = confirmed_children.entry(p).or_default();
            e.0 |= t.primary().is_some_and(|c| c <= confirmed_until);
            e.1 |= t.broad().is_some_and(|c| c <= confirmed_until);
        }
    }
    let confirmed_as = |name: &str, f: &Flag| -> (bool, bool) {
        let direct = truth.get(name).map_or((false, false), |t| {
            (
                t.primary().is_some_and(|c| c <= confirmed_until),
                t.broad().is_some_and(|c| c <= confirmed_until),
            )
        });
        let child = if f.wildcard_ts.is_some() {
            confirmed_children.get(name).copied().unwrap_or_default()
        } else {
            (false, false)
        };
        (direct.0 || child.0, direct.1 || child.1)
    };
    for level in Level::ALL {
        let (mut n, mut kp, mut kb) = (0u64, 0u64, 0u64);
        for (name, f) in flags.iter().filter(|(_, f)| level.admits(f.verdict)) {
            n += 1;
            let (p, b) = confirmed_as(name, f);
            kp += u64::from(p);
            kb += u64::from(b);
            if level == Level::Warn {
                for brand in if f.brands.is_empty() {
                    vec!["(none)".to_owned()]
                } else {
                    f.brands.iter().cloned().collect()
                } {
                    let e = rep.precision.warn_by_brand.entry(brand).or_default();
                    e.0 += 1;
                    e.1 += u64::from(b);
                }
            }
        }
        rep.precision.flagged.insert(level.name().into(), n);
        rep.precision
            .confirmed_primary
            .insert(level.name().into(), Proportion::of(kp, n));
        rep.precision
            .confirmed_broad
            .insert(level.name().into(), Proportion::of(kb, n));
    }

    // phishunt as a peer CT detector.
    let listed: Vec<(&str, &Truth, u64)> = truth
        .iter()
        .filter_map(|(h, t)| {
            t.phishunt_listed_ms
                .filter(|l| *l >= from && *l <= confirmed_until)
                .map(|l| (h.as_str(), t, l))
        })
        .collect();
    rep.phishunt.phishunt_listed = listed.len() as u64;
    let observable: Vec<&(&str, &Truth, u64)> = listed
        .iter()
        .filter(|(h, _, l)| obs.host.get(*h).is_some_and(|o| o <= l))
        .collect();
    rep.phishunt.phishunt_listed_observable = observable.len() as u64;
    for level in [Level::Signal, Level::Warn] {
        let k = observable
            .iter()
            .filter(|(h, _, _)| flag_ts(&flags, h, level).is_some())
            .count() as u64;
        rep.phishunt.flagged_of_phishunt_observable.insert(
            level.name().into(),
            Proportion::of(k, observable.len() as u64),
        );
    }
    let warn: Vec<&String> = flags
        .iter()
        .filter(|(_, f)| is_warn(f.verdict))
        .map(|(n, _)| n)
        .collect();
    let in_ph = warn
        .iter()
        .filter(|n| {
            truth
                .get(n.as_str())
                .is_some_and(|t| t.phishunt_listed_ms.is_some())
        })
        .count() as u64;
    rep.phishunt.phishunt_of_warn = Proportion::of(in_ph, warn.len() as u64);
    let mut diffs = Vec::new();
    for (h, t, _) in &listed {
        if let (Some(first), Some((_, seen))) =
            (t.phishunt_first_seen_ms, flag_ts(&flags, h, Level::Signal))
        {
            diffs.push((first as f64 - seen as f64) / HOUR_MS as f64);
        }
    }
    let earlier = diffs.iter().filter(|d| **d > 0.0).count() as u64;
    rep.phishunt.cybermesh_earlier = Proportion::of(earlier, diffs.len() as u64);
    rep.phishunt.cybermesh_earlier_hours = quantiles(diffs);

    // False-alarm sample: unconfirmed warn-level names, stratified by first brand.
    let mut strata: BTreeMap<String, Vec<(&String, &Flag)>> = BTreeMap::new();
    for (name, f) in flags.iter().filter(|(_, f)| is_warn(f.verdict)) {
        if confirmed_as(name, f).1 {
            continue;
        }
        let b = f
            .brands
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| "(none)".into());
        strata.entry(b).or_default().push((name, f));
    }
    let total: usize = strata.values().map(Vec::len).sum();
    let mut sample = Vec::new();
    for items in strata.values_mut() {
        items.sort_by_key(|(n, _)| rank(n));
        let quota = if total == 0 {
            0
        } else {
            (a.sample * items.len()).div_ceil(total).max(1)
        };
        sample.extend(items.iter().take(quota).copied());
    }
    sample.sort_by_key(|(n, _)| rank(n));
    sample.truncate(a.sample);
    sample.sort_by(|x, y| x.1.brands.cmp(&y.1.brands).then(x.0.cmp(y.0)));
    rep.fp_sample_size = sample.len();
    fs::create_dir_all(&a.out)?;
    let mut csv = String::from(
        "name,brands,verdict,risk_score_bp,codes,first_logged_utc,wildcard,phishunt_listed,label\n",
    );
    for (name, f) in &sample {
        let row = [
            csv_field(name),
            csv_field(&f.brands.iter().cloned().collect::<Vec<_>>().join(" ")),
            format!("{:?}", f.verdict).to_lowercase(),
            f.risk_score_bp.to_string(),
            csv_field(&f.codes.iter().cloned().collect::<Vec<_>>().join(" ")),
            utc(f.first_ts),
            f.wildcard_ts.is_some().to_string(),
            truth
                .get(name.as_str())
                .is_some_and(|t| t.phishunt_listed_ms.is_some())
                .to_string(),
            String::new(),
        ];
        csv.push_str(&row.join(","));
        csv.push('\n');
    }
    crate::util::write(&a.out.join("fp-sample.csv"), csv.as_bytes())?;
    rep.run = st;
    rep.feeds = feeds;
    write_json(&a.out.join("report.json"), &rep)?;
    Ok(rep)
}

fn pct(p: &Proportion) -> String {
    match (p.p, p.ci95) {
        (Some(x), Some((lo, hi))) => format!(
            "{:.1} % ({}/{}; 95 % CI {:.1}–{:.1} %)",
            x * 100.0,
            p.k,
            p.n,
            lo * 100.0,
            hi * 100.0
        ),
        _ => format!("n/a ({}/{})", p.k, p.n),
    }
}

fn hours(q: &Quantiles) -> String {
    match (q.p25, q.median, q.p75) {
        (Some(a), Some(m), Some(b)) => format!("median {m:.1} h (IQR {a:.1}–{b:.1} h, n={})", q.n),
        _ => "n/a".into(),
    }
}

/// Prints the main figures.
pub fn print(rep: &Report) {
    let r = &rep.run;
    println!(
        "window {} .. {}: {} tiles, {} entries from {} log(s); {} flagged names; downtime {:?} ms",
        utc(r.window_from_ms),
        utc(r.window_to_ms),
        r.tiles_scanned,
        r.entries_scanned,
        r.logs.len(),
        r.flagged_names,
        r.downtime_ms
    );
    println!(
        "feeds: {} phishunt and {} OpenPhish snapshots; {} listed URLs not on a domain name",
        rep.feeds.phishunt_snapshots, rep.feeds.openphish_snapshots, rep.feeds.not_a_domain
    );
    for (label, d) in [
        (
            "primary (OpenPhish, Safe Browsing, PhishTank)",
            &rep.primary,
        ),
        ("broad (any third-party flag)", &rep.broad),
        ("primary, protected brands only", &rep.in_scope_primary),
    ] {
        println!("{label}: {} confirmed hosts", d.confirmed);
        println!(
            "  visible in the followed logs before confirmation: {}",
            pct(&d.observability)
        );
        for l in ["signal", "warn", "block"] {
            println!(
                "  recall [{l}]: {} of visible, {} end to end; lead {}",
                pct(&d.recall[l]),
                pct(&d.recall_end_to_end[l]),
                hours(&d.lead_hours[l])
            );
        }
    }
    for (s, q) in &rep.per_source_lead_hours {
        println!("lead time vs {s} [warn]: {}", hours(q));
    }
    println!(
        "detection latency (scan - log time): median {:.0} s, p90 {:.0} s",
        rep.detection_latency_secs.median.unwrap_or(0.0),
        rep.detection_latency_secs.p90.unwrap_or(0.0)
    );
    for l in ["signal", "warn", "block"] {
        println!(
            "precision floor [{l}]: {} flagged; confirmed {} (primary), {} (broad)",
            rep.precision.flagged[l],
            pct(&rep.precision.confirmed_primary[l]),
            pct(&rep.precision.confirmed_broad[l])
        );
    }
    let p = &rep.phishunt;
    println!(
        "phishunt: {} listed, {} visible in our logs first; we flagged {} [signal], {} [warn]; phishunt listed {} of our warn names; we were earlier for {}: {}",
        p.phishunt_listed,
        p.phishunt_listed_observable,
        pct(&p.flagged_of_phishunt_observable["signal"]),
        pct(&p.flagged_of_phishunt_observable["warn"]),
        pct(&p.phishunt_of_warn),
        pct(&p.cybermesh_earlier),
        hours(&p.cybermesh_earlier_hours)
    );
    println!(
        "false-alarm sample: {} names in fp-sample.csv",
        rep.fp_sample_size
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]
    use std::io::Write as _;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    #[test]
    fn timestamps_parse() {
        assert_eq!(parse_iso_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_iso_ms("2026-11-18T17:23:31.342658+00:00"),
            Some(1_795_022_611_342)
        );
        assert_eq!(
            parse_iso_ms("2026-11-18T18:23:31+01:00"),
            parse_iso_ms("2026-11-18T17:23:31Z")
        );
        assert_eq!(parse_iso_ms("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_iso_ms("garbage"), None);
        assert_eq!(
            parse_snapshot_ms("20261118T172331Z.csv.gz"),
            parse_iso_ms("2026-11-18T17:23:31Z")
        );
        assert_eq!(parse_snapshot_ms("notes.txt"), None);
        assert_eq!(utc(1_795_022_611_342), "2026-11-18T17:23:31Z");
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn csv_hosts_and_intervals() {
        let rows = parse_csv("a,b,c\n\"x, y\",\"say \"\"hi\"\"\",3\r\nlast,,\n");
        assert_eq!(rows[1], vec!["x, y", "say \"hi\"", "3"]);
        assert_eq!(rows[2], vec!["last", "", ""]);
        assert_eq!(
            url_host("https://User@Login.Example.COM:8443/x?y#z").as_deref(),
            Some("login.example.com")
        );
        assert_eq!(url_host("example.org/path").as_deref(), Some("example.org"));
        assert_eq!(url_host("http://192.0.2.7/login"), None);
        assert_eq!(url_host("http://[2001:db8::1]/"), None);
        let (lo, hi) = wilson(5, 106).unwrap();
        assert!(
            (lo - 0.0203).abs() < 0.001 && (hi - 0.1056).abs() < 0.001,
            "{lo} {hi}"
        );
        assert_eq!(wilson(0, 0), None);
        assert_eq!(
            suffixes("a.b.c").collect::<Vec<_>>(),
            vec!["a.b.c", "b.c", "c"]
        );
        assert_eq!(parent("a.b.c"), Some("b.c"));
        assert_eq!(parent("b.c"), None);
    }

    fn gz(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut e = GzEncoder::new(File::create(path).unwrap(), Compression::default());
        e.write_all(text.as_bytes()).unwrap();
        e.finish().unwrap();
    }

    fn line<T: Serialize>(v: &T) -> String {
        serde_json::to_string(v).unwrap() + "\n"
    }

    /// A small synthetic run with known answers.
    #[test]
    fn scores_a_synthetic_run() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path();
        let h = HOUR_MS;
        let t0 = parse_iso_ms("2026-11-18T00:00:00Z").unwrap();
        fs::write(run.join("runs.jsonl"), format!("{{\"started_ms\":{t0}}}\n")).unwrap();
        // One poll an hour for 10 days.
        let mut polls = String::new();
        for i in 0..=240u64 {
            polls.push_str(&line(&PollRecord {
                log: "log-a".into(),
                t_ms: t0 + i * h,
                tiles: 1,
                entries: 256,
                elapsed_ms: 1000,
                ..PollRecord::default()
            }));
        }
        fs::write(run.join("polls.jsonl"), polls).unwrap();
        // Certificates (log time):
        //  phish-paypal-login.com      day 2  -> flagged warn; confirmed by OpenPhish day 3
        //  secure.paypa1-verify.net     day 2  -> via *.paypa1-verify.net, flagged warn (wildcard);
        //                                         confirmed by Safe Browsing day 2 + 6 h
        //  plain-unflagged.example      day 2  -> not flagged; confirmed day 4
        //  amazon-infra.amazonaws.example day 3 -> flagged warn, never confirmed (false alarm)
        //  late-phish.com               day 5  -> flagged warn, but confirmed earlier (day 4.5):
        //                                         counts as visible? no (cert after confirmation)
        //  invisible.example (no cert)         -> confirmed day 3, not visible
        let names = [
            (1u64, t0 + 48 * h, "phish-paypal-login.com", ""),
            (2, t0 + 48 * h, "paypa1-verify.net", "paypa1-verify.net"),
            (3, t0 + 49 * h, "plain-unflagged.example", ""),
            (4, t0 + 72 * h, "amazon-infra.amazonaws.example", ""),
            (5, t0 + 120 * h, "late-phish.com", ""),
        ];
        let mut seg = String::new();
        for (i, ts, n, w) in names {
            seg.push_str(&format!("{i}\t{ts}\t{n}\t{w}\n"));
        }
        seg.push_str(&format!("6\t{}\t!unparsed\t\n", t0 + 50 * h));
        gz(&run.join("names/log-a/000000000000.tsv.gz"), &seg);
        let m = |index: u64, ts: u64, name: &str, wildcard: bool, verdict: Verdict| MatchRecord {
            log: "log-a".into(),
            tile: 0,
            index,
            precert: true,
            ts_ms: ts,
            seen_ms: ts + 20_000,
            name: name.into(),
            wildcard,
            risk_score_bp: 5000,
            verdict,
            codes: vec![cybermesh_protocol::FindingCode::BrandImpersonation],
            brands: vec![
                if name.contains("amazon") {
                    "amazon"
                } else {
                    "paypal"
                }
                .into(),
            ],
        };
        let mut matches = String::new();
        matches.push_str(&line(&m(
            1,
            t0 + 48 * h,
            "phish-paypal-login.com",
            false,
            Verdict::Suspicious,
        )));
        matches.push_str(&line(&m(
            1,
            t0 + 48 * h,
            "phish-paypal-login.com",
            false,
            Verdict::Suspicious,
        )));
        matches.push_str(&line(&m(
            2,
            t0 + 48 * h,
            "paypa1-verify.net",
            true,
            Verdict::Malicious,
        )));
        matches.push_str(&line(&m(
            4,
            t0 + 72 * h,
            "amazon-infra.amazonaws.example",
            false,
            Verdict::Suspicious,
        )));
        matches.push_str(&line(&m(
            5,
            t0 + 120 * h,
            "late-phish.com",
            false,
            Verdict::Suspicious,
        )));
        matches.push_str("{\"torn\":");
        fs::write(run.join("matches.jsonl"), matches).unwrap();
        // Feeds.
        let snap = |t: u64| {
            let s = utc(t);
            format!(
                "{}{}{}T{}{}{}Z",
                &s[0..4],
                &s[5..7],
                &s[8..10],
                &s[11..13],
                &s[14..16],
                &s[17..19]
            )
        };
        let header = "url,domain,company,date,first_seen,malicious_google,malicious_phishtank,malicious_openphish,malicious_urlscan,malicious_tweetfeed\n";
        gz(
            &run.join(format!("feeds/phishunt/{}.csv.gz", snap(t0 + 54 * h))),
            &format!(
                "{header}https://secure.paypa1-verify.net/x,secure.paypa1-verify.net,paypal,{d},{fs},true,false,false,false,false\nhttps://phish-paypal-login.com/,phish-paypal-login.com,paypal,{d},{fs2},false,false,false,true,false\n",
                d = "2026-11-20T06:00:00Z",
                fs = "2026-11-20T03:00:00Z",
                fs2 = "2026-11-19T23:00:00Z"
            ),
        );
        gz(
            &run.join(format!("feeds/phishunt/{}.csv.gz", snap(t0 + 239 * h))),
            &format!("{header}http://198.51.100.9/x,,other,x,x,true,false,false,false,false\n"),
        );
        gz(
            &run.join(format!("feeds/openphish/{}.txt.gz", snap(t0 + 72 * h))),
            "https://phish-paypal-login.com/login\nhttp://invisible.example/a\n",
        );
        gz(
            &run.join(format!("feeds/openphish/{}.txt.gz", snap(t0 + 96 * h))),
            "https://plain-unflagged.example/\nhttps://phish-paypal-login.com/login\n",
        );
        gz(
            &run.join(format!("feeds/openphish/{}.txt.gz", snap(t0 + 108 * h))),
            "http://late-phish.com/\n",
        );
        let out = run.join("eval");
        let ev = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../datasets/demo/evidence");
        let rep = super::run(&EvaluateArgs {
            run: run.to_owned(),
            evidence: ev,
            from_ms: None,
            to_ms: None,
            burn_in_hours: 24,
            sample: 10,
            out: out.clone(),
        })
        .unwrap();

        // Primary ground truth: OpenPhish (phish-paypal-login day 3, invisible day 3,
        // plain-unflagged day 4, late-phish day 4.5) and Safe Browsing (secure.paypa1-verify
        // day 2.25).
        let p = &rep.primary;
        assert_eq!(p.confirmed, 5);
        // Visible before confirmation: phish-paypal-login, secure.paypa1-verify (wildcard),
        // plain-unflagged. Not: invisible (no cert), late-phish (cert after confirmation).
        assert_eq!((p.observability.k, p.observability.n), (3, 5));
        assert_eq!((p.recall["warn"].k, p.recall["warn"].n), (2, 3));
        assert_eq!((p.recall["block"].k, p.recall["block"].n), (1, 3));
        assert_eq!(p.recall_end_to_end["warn"].n, 5);
        // Lead: 24 h (OpenPhish day 3 - cert day 2) and 6 h (Safe Browsing).
        assert_eq!(p.lead_hours["warn"].n, 2);
        assert!((p.lead_hours["warn"].median.unwrap() - 15.0).abs() < 1e-9);
        assert!((rep.per_source_lead_hours["openphish"].median.unwrap() - 24.0).abs() < 1e-9);
        assert!((rep.per_source_lead_hours["gsb_phishtank"].median.unwrap() - 6.0).abs() < 1e-9);
        // The broad truth adds urlscan's flag on phish-paypal-login at day 2.25 (earlier).
        assert!((rep.broad.lead_hours["warn"].median.unwrap() - 6.0).abs() < 1e-9);
        // Protected brands only: the two phishunt rows whose company is paypal.
        assert_eq!(rep.in_scope_primary.confirmed, 2);

        // Precision floor at warn level: 4 names flagged; phish-paypal-login, the wildcard
        // parent paypa1-verify.net and late-phish are confirmed; the amazon one is not.
        assert_eq!(rep.precision.flagged["warn"], 4);
        assert_eq!(rep.precision.confirmed_primary["warn"].k, 3);
        assert_eq!(rep.precision.warn_by_brand["amazon"], (1, 0));

        // phishunt listed two hosts, both visible first, both flagged. CyberMesh scanned both at
        // day 2 + 20 s (t0 + 48 h); phishunt's first_seen is t0 + 47 h for phish-paypal-login
        // (phishunt earlier by 1 h) and t0 + 51 h for secure.paypa1-verify (CyberMesh earlier
        // by 3 h).
        assert_eq!(rep.phishunt.phishunt_listed, 2);
        assert_eq!(rep.phishunt.phishunt_listed_observable, 2);
        assert_eq!(rep.phishunt.flagged_of_phishunt_observable["warn"].k, 2);
        assert_eq!(
            (
                rep.phishunt.cybermesh_earlier.k,
                rep.phishunt.cybermesh_earlier.n
            ),
            (1, 2)
        );
        let d = &rep.phishunt.cybermesh_earlier_hours;
        let secs = 20.0 / 3600.0;
        // Two values, -1 h and +3 h (less the 20 s scan delay): linear interpolation.
        assert_eq!(d.n, 2);
        assert!((d.median.unwrap() - (1.0 - secs)).abs() < 1e-9, "{d:?}");
        assert!((d.p25.unwrap() - (0.0 - secs)).abs() < 1e-9, "{d:?}");

        // Bookkeeping. The window runs to the latest snapshot of either feed.
        assert_eq!(rep.recall_window_to_ms, t0 + 239 * h);
        assert_eq!(rep.feeds.first_snapshot_ms, Some(t0 + 54 * h));
        assert_eq!(rep.feeds.not_a_domain, 1);
        assert_eq!(rep.run.match_lines_unreadable, 1);
        assert_eq!(rep.run.flagged_names, 4);
        // Polls an hour apart (1 s each): every pause is longer than two minutes.
        assert_eq!(rep.run.downtime["log-a"].len(), 240);
        assert_eq!(rep.run.downtime_ms["log-a"], 240 * (h - 1000));
        let sample = fs::read_to_string(out.join("fp-sample.csv")).unwrap();
        assert_eq!(sample.lines().count(), 2, "{sample}");
        assert!(
            sample.contains(
                "amazon-infra.amazonaws.example,amazon,suspicious,5000,brand-impersonation,"
            ),
            "{sample}"
        );
        assert!(out.join("report.json").exists());
    }
}
