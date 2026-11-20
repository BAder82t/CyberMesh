//! `cybermesh ct evaluate`: scores a `ct watch` run against independently confirmed phishing,
//! as fixed in `docs/ct-evaluation.md`.
//!
//! Inputs, all inside the run directory:
//! - what `ct watch` wrote (`runs.jsonl`, `polls.jsonl`, `matches.jsonl`, `names/`);
//! - `feeds/phishunt/<UTC>.csv.gz`: hourly phishunt snapshots (`scripts/ct-eval.sh`);
//! - `feeds/openphish/<UTC>.txt.gz`: OpenPhish community feed snapshots exported from its git
//!   history (`scripts/ct-eval.sh history`), named by commit time.
//!
//! With `--rescore-evidence`, the flags come from re-assessing every stored name with that
//! evidence (a revised engine, `docs/ct-evaluation.md` §5) instead of from `matches.jsonl`.
//!
//! Output: `report.json` (every number in the evaluation) and `fp-sample.csv` (unconfirmed
//! warn-level names, stratified by their alphabetically first brand, for labelling by hand).
//!
//! Memory grows with the number of distinct flagged names (about 250 bytes each): run it on a
//! machine with a few GB free for a week of data.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context as _, Result, bail};
use clap::Args;
use cybermesh_analysis::{Engine, EvidenceBundle, normalize_domain};
use cybermesh_protocol::Verdict;
use flate2::read::GzDecoder;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::ct_watch::{EventRecord, MatchRecord, PollRecord};
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
    /// Re-assess every stored name with this evidence bundle (a revised engine) instead of
    /// reading the run's own flags. Detection latency is then not reported.
    #[arg(long)]
    pub rescore_evidence: Option<PathBuf>,
    /// Only certificates logged at or after this time (ms since the epoch). Default: the
    /// run's start. Use with `--to-ms` for the dev/test split.
    #[arg(long)]
    pub from_ms: Option<u64>,
    /// Only certificates logged before this time (ms). Default: the end of the last poll.
    #[arg(long)]
    pub to_ms: Option<u64>,
    /// Hosts first confirmed within this long after the window's start are left out of
    /// recall: their certificate most likely predates the window. Applies to any `--from-ms`.
    #[arg(long, default_value_t = 24)]
    pub burn_in_hours: u64,
    /// Size of the false-alarm sample.
    #[arg(long, default_value_t = 200)]
    pub sample: usize,
    /// Threads for reading the name segments.
    #[arg(long, default_value_t = 4)]
    pub threads: usize,
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

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
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
    if !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s - off_min * 60;
    u64::try_from(secs * 1000 + frac_ms).ok()
}

/// ISO 8601 / RFC 3339 timestamp (`2026-11-18T17:23:31.342658+00:00`, `...Z`, `...+00`)
/// to ms. A timestamp without a zone is read as UTC.
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
        let z = zone.get(1..)?;
        let (oh, om) = match z.split_once(':') {
            Some((h, m)) => (h, m),
            None if z.len() == 4 => (&z[..2], &z[2..]),
            None => (z, "00"),
        };
        if oh.len() != 2 || om.len() != 2 {
            return None;
        }
        sign * (num(oh)? * 60 + num(om)?)
    };
    to_ms((y, mo, d), (h, mi, sec), frac_ms, off_min)
}

/// Snapshot file name `20261118T173918Z<suffix>` to ms; `None` for any other name
/// (including interrupted writes such as `...csv.gz.tmp`).
pub fn parse_snapshot_ms(name: &str, suffix: &str) -> Option<u64> {
    let stem = name.strip_suffix(suffix)?;
    if stem.len() != 16 {
        return None;
    }
    let b = stem.as_bytes();
    if b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    to_ms(
        (num(&stem[0..4])?, num(&stem[4..6])?, num(&stem[6..8])?),
        (num(&stem[9..11])?, num(&stem[11..13])?, num(&stem[13..15])?),
        0,
        0,
    )
}

/// RFC 4180 CSV (quoted fields, doubled quotes, CRLF or LF, optional UTF-8 BOM).
pub fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
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
    // A scheme only at the start (`http://`), not one inside a query string.
    let u = match u.split_once("://") {
        Some((scheme, rest))
            if scheme
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) =>
        {
            rest
        }
        _ => u,
    };
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

/// Reads lines as bytes, so a torn multi-byte character costs one line, not the whole file.
/// Returns the lines and whether the stream ended in an error (a truncated gzip).
fn read_lines(mut r: impl BufRead, mut f: impl FnMut(&str)) -> bool {
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match r.read_until(b'\n', &mut buf) {
            Ok(0) => return false,
            Ok(_) => {
                if buf.last() != Some(&b'\n') {
                    // A last line without its newline: complete only if the stream is.
                    let mut probe = [0u8; 1];
                    if r.read(&mut probe).is_err() {
                        return true;
                    }
                }
                f(String::from_utf8_lossy(&buf).trim_end_matches(['\n', '\r']));
            }
            Err(_) => return true,
        }
    }
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

    /// When phishunt knew of the host: its `first_seen`, else its first listing.
    #[must_use]
    pub fn phishunt_ms(&self) -> Option<u64> {
        self.phishunt_first_seen_ms.or(self.phishunt_listed_ms)
    }
}

#[derive(Debug, Default, Serialize)]
pub struct FeedStats {
    pub phishunt_snapshots: usize,
    pub openphish_snapshots: usize,
    /// Snapshots whose gzip stream was cut short (their partial last line is dropped).
    pub truncated_snapshots: usize,
    pub phishunt_rows: u64,
    pub openphish_urls: u64,
    /// Listed URLs whose host is an IP literal or not a valid domain name: never visible in
    /// CT, and left out of the host-level figures.
    pub not_a_domain: u64,
    /// phishunt rows whose `first_seen` did not parse (their first listing is used instead).
    pub phishunt_first_seen_unparsed: u64,
    pub first_snapshot_ms: Option<u64>,
    pub last_snapshot_ms: Option<u64>,
}

/// A whole gzip file as text, and whether it was truncated (then without its last line).
fn read_gz(path: &Path) -> Result<(String, bool)> {
    let mut d =
        GzDecoder::new(File::open(path).with_context(|| format!("open {}", path.display()))?);
    let mut buf = Vec::new();
    let truncated = d.read_to_end(&mut buf).is_err();
    if truncated {
        let keep = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        buf.truncate(keep);
    }
    Ok((String::from_utf8_lossy(&buf).into_owned(), truncated))
}

fn snapshots(dir: &Path, suffix: &str) -> Result<Vec<(u64, PathBuf)>> {
    let mut v = Vec::new();
    if !dir.is_dir() {
        return Ok(v);
    }
    for e in fs::read_dir(dir)? {
        let p = e?.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if let Some(t) = parse_snapshot_ms(name, suffix) {
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
    let ph = snapshots(&run.join("feeds/phishunt"), ".csv.gz")?;
    let op = snapshots(&run.join("feeds/openphish"), ".txt.gz")?;
    st.phishunt_snapshots = ph.len();
    st.openphish_snapshots = op.len();
    for (t, _) in ph.iter().chain(&op) {
        set_min(&mut st.first_snapshot_ms, *t);
        st.last_snapshot_ms = st.last_snapshot_ms.max(Some(*t));
    }
    for (t, p) in &ph {
        let (text, truncated) = read_gz(p)?;
        st.truncated_snapshots += usize::from(truncated);
        let rows = parse_csv(&text);
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
            match c_first.and_then(|c| row.get(c)).map(|s| parse_iso_ms(s)) {
                Some(Some(fs)) => set_min(&mut e.phishunt_first_seen_ms, fs),
                _ => st.phishunt_first_seen_unparsed += 1,
            }
            if e.company.is_none() {
                e.company = c_co
                    .and_then(|c| row.get(c))
                    .filter(|c| !c.is_empty())
                    .cloned();
            }
            let primary = flag(row, c_g) || flag(row, c_pt);
            if primary {
                set_min(&mut e.gsb_phishtank_ms, *t);
            }
            if primary || flag(row, c_op) || flag(row, c_us) || flag(row, c_tf) {
                set_min(&mut e.any_flag_ms, *t);
            }
        }
    }
    for (t, p) in &op {
        let (text, truncated) = read_gz(p)?;
        st.truncated_snapshots += usize::from(truncated);
        for line in text.lines() {
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
            Level::Warn => matches!(v, Verdict::Suspicious | Verdict::Malicious),
            Level::Block => v == Verdict::Malicious,
        }
    }

    fn ix(self) -> usize {
        self as usize
    }
}

/// One occurrence: the certificate's log time and when it was scanned (ms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Occ {
    pub ts: u64,
    pub seen: u64,
}

fn earliest(slot: &mut Option<Occ>, o: Occ) {
    if slot.is_none_or(|s| o.ts < s.ts) {
        *slot = Some(o);
    }
}

/// One flagged name: its earliest occurrence per level, as listed and as a wildcard
/// (`*.name`, which covers `label.name`).
#[derive(Debug, Clone, Default)]
pub struct Flag {
    pub exact: [Option<Occ>; 3],
    pub wild: [Option<Occ>; 3],
    /// The most severe assessment seen.
    pub verdict: Option<Verdict>,
    pub risk_score_bp: u16,
    /// Indices into [`Flags::brands`] and bits of [`Flags::codes`].
    pub brands: Vec<u16>,
    pub codes: u64,
}

impl Flag {
    fn at(&self, level: Level) -> bool {
        self.exact[level.ix()].is_some() || self.wild[level.ix()].is_some()
    }
}

/// Flagged names with interned brand and code names.
#[derive(Debug, Default)]
pub struct Flags {
    pub names: HashMap<String, Flag>,
    pub brands: Vec<String>,
    brand_ix: HashMap<String, u16>,
    pub codes: Vec<String>,
    code_ix: HashMap<String, u8>,
}

impl Flags {
    fn add(
        &mut self,
        name: &str,
        occ: Occ,
        wildcard: bool,
        (verdict, risk): (Verdict, u16),
        brands: &[String],
        codes: &[String],
    ) {
        let f = self.names.entry(name.to_owned()).or_default();
        for level in Level::ALL.into_iter().filter(|l| l.admits(verdict)) {
            earliest(&mut f.exact[level.ix()], occ);
            if wildcard {
                earliest(&mut f.wild[level.ix()], occ);
            }
        }
        if f.verdict.is_none() || risk > f.risk_score_bp {
            f.risk_score_bp = risk;
            f.verdict = Some(verdict);
        }
        self.add_labels(name, brands, codes);
    }

    fn merge(&mut self, mut other: Flags) {
        for (name, f) in std::mem::take(&mut other.names) {
            let brands = other.brand_names(&f);
            let codes = other.code_names(&f);
            let g = self.names.entry(name.clone()).or_default();
            for i in 0..3 {
                if let Some(o) = f.exact[i] {
                    earliest(&mut g.exact[i], o);
                }
                if let Some(o) = f.wild[i] {
                    earliest(&mut g.wild[i], o);
                }
            }
            if let Some(v) = f.verdict
                && (g.verdict.is_none() || f.risk_score_bp > g.risk_score_bp)
            {
                g.risk_score_bp = f.risk_score_bp;
                g.verdict = Some(v);
            }
            self.add_labels(&name, &brands, &codes);
        }
    }

    fn add_labels(&mut self, name: &str, brands: &[String], codes: &[String]) {
        let bix: Vec<u16> = brands
            .iter()
            .map(|b| {
                *self.brand_ix.entry(b.clone()).or_insert_with(|| {
                    self.brands.push(b.clone());
                    u16::try_from(self.brands.len() - 1).unwrap_or(u16::MAX)
                })
            })
            .collect();
        let mut cbits = 0u64;
        for c in codes {
            let i = *self.code_ix.entry(c.clone()).or_insert_with(|| {
                self.codes.push(c.clone());
                // More than 64 distinct codes share the last bit (the engine has fewer).
                u8::try_from(self.codes.len() - 1).unwrap_or(63).min(63)
            });
            cbits |= 1 << i;
        }
        let f = self.names.entry(name.to_owned()).or_default();
        for b in bix {
            if !f.brands.contains(&b) {
                f.brands.push(b);
            }
        }
        f.brands.sort_unstable();
        f.codes |= cbits;
    }

    fn brand_names(&self, f: &Flag) -> Vec<String> {
        let mut v: Vec<String> = f
            .brands
            .iter()
            .map(|b| self.brands[usize::from(*b)].clone())
            .collect();
        v.sort();
        v
    }

    fn code_names(&self, f: &Flag) -> Vec<String> {
        let mut v: Vec<String> = (0..self.codes.len())
            .filter(|i| f.codes & (1 << i) != 0)
            .map(|i| self.codes[i].clone())
            .collect();
        v.sort();
        v
    }

    /// Earliest flag at `level` that covers host `h`: the name itself, or a wildcard
    /// certificate for its parent.
    fn covering(&self, h: &str, level: Level) -> Option<Occ> {
        let exact = self.names.get(h).and_then(|f| f.exact[level.ix()]);
        let wild = parent(h)
            .and_then(|p| self.names.get(p))
            .and_then(|f| f.wild[level.ix()]);
        match (exact, wild) {
            (Some(a), Some(b)) => Some(if a.ts <= b.ts { a } else { b }),
            (a, None) => a,
            (None, b) => b,
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
    /// Tiles, entries and unparsed entries scanned by the polls inside the window.
    pub tiles_scanned: u64,
    pub entries_scanned: u64,
    pub unparsed_entries: u64,
    /// The same for the whole run so far.
    pub tiles_scanned_run: u64,
    pub entries_scanned_run: u64,
    pub name_segments: usize,
    pub truncated_segments: usize,
    pub name_lines_unreadable: u64,
    pub match_lines: u64,
    /// Lines that did not parse (torn by a crash, or not valid JSON): never silently lost.
    pub match_lines_unreadable: u64,
    pub poll_lines_unreadable: u64,
    pub event_lines_unreadable: u64,
    pub run_lines_unreadable: u64,
    pub flagged_names: usize,
    /// Names re-assessed with `--rescore-evidence` (0 when the run's own flags are used).
    pub names_rescored: u64,
    /// Pauses longer than two minutes without a poll, per log, clipped to the window,
    /// including before a log's first poll and after its last: (from, to) in ms.
    pub downtime: BTreeMap<String, Vec<(u64, u64)>>,
    pub downtime_ms: BTreeMap<String, u64>,
    pub events: BTreeMap<String, u64>,
}

fn jsonl<T: serde::de::DeserializeOwned>(path: &Path, bad: &mut u64) -> Result<Vec<T>> {
    let mut out = Vec::new();
    if !path.exists() {
        return Ok(out);
    }
    let r = BufReader::with_capacity(1 << 20, File::open(path)?);
    read_lines(r, |line| {
        if line.trim().is_empty() {
            return;
        }
        match serde_json::from_str(line) {
            Ok(v) => out.push(v),
            Err(_) => *bad += 1,
        }
    });
    Ok(out)
}

/// Gaps of more than [`GAP_MS`] without a poll, clipped to `[from, to)`.
fn gaps(intervals: &[(u64, u64)], from: u64, to: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut covered = from;
    for &(a, b) in intervals {
        if b <= from {
            continue;
        }
        if a >= to {
            break;
        }
        if a > covered + GAP_MS {
            out.push((covered, a.min(to)));
        }
        covered = covered.max(b);
    }
    if to > covered + GAP_MS {
        out.push((covered, to));
    }
    out
}

struct Polls {
    by_log: BTreeMap<String, Vec<(u64, u64)>>,
    /// (poll time, tiles, entries, unparsed) of every poll, for the window's totals.
    counts: Vec<(u64, u64, u64, u64)>,
}

fn run_stats(run: &Path) -> Result<(RunStats, Polls)> {
    let mut st = RunStats::default();
    let runs: Vec<serde_json::Value> =
        jsonl(&run.join("runs.jsonl"), &mut st.run_lines_unreadable)?;
    st.start_ms = runs
        .iter()
        .filter_map(|r| r.get("started_ms").and_then(serde_json::Value::as_u64))
        .min()
        .context("runs.jsonl: no start")?;
    st.starts = runs.len();
    let polls: Vec<PollRecord> = jsonl(&run.join("polls.jsonl"), &mut st.poll_lines_unreadable)?;
    let mut by_log: BTreeMap<String, Vec<(u64, u64)>> = BTreeMap::new();
    let mut counts = Vec::with_capacity(polls.len());
    for p in &polls {
        st.tiles_scanned_run += p.tiles;
        st.entries_scanned_run += p.entries;
        counts.push((p.t_ms, p.tiles, p.entries, p.unparsed));
        st.window_to_ms = st.window_to_ms.max(p.t_ms + p.elapsed_ms);
        by_log
            .entry(p.log.clone())
            .or_default()
            .push((p.t_ms, p.t_ms + p.elapsed_ms));
    }
    for v in by_log.values_mut() {
        v.sort_unstable();
    }
    st.logs = by_log.keys().cloned().collect();
    let events: Vec<EventRecord> =
        jsonl(&run.join("events.jsonl"), &mut st.event_lines_unreadable)?;
    for e in events {
        *st.events.entry(e.kind).or_default() += 1;
    }
    Ok((st, Polls { by_log, counts }))
}

/// Earliest log timestamp at which each tracked host (or registrable domain) appeared in a
/// certificate, from the name segments.
#[derive(Debug, Default)]
struct Observed {
    /// Seen under its own name or under a wildcard for its parent.
    host: HashMap<String, u64>,
    /// Seen under its own name: a wildcard certificate for a parent does not reveal the
    /// host's name, so no name-based CT monitor can flag the host from it.
    host_own_name: HashMap<String, u64>,
    regdom: HashMap<String, u64>,
}

impl Observed {
    fn see_host(&mut self, h: &str, ts: u64) {
        let e = self.host.entry(h.to_owned()).or_insert(ts);
        *e = (*e).min(ts);
    }

    fn see_own_name(&mut self, h: &str, ts: u64) {
        self.see_host(h, ts);
        let e = self.host_own_name.entry(h.to_owned()).or_insert(ts);
        *e = (*e).min(ts);
    }

    fn see_regdom(&mut self, r: &str, ts: u64) {
        let e = self.regdom.entry(r.to_owned()).or_insert(ts);
        *e = (*e).min(ts);
    }

    fn merge(&mut self, o: Observed) {
        for (h, t) in o.host {
            self.see_host(&h, t);
        }
        for (h, t) in o.host_own_name {
            self.see_own_name(&h, t);
        }
        for (r, t) in o.regdom {
            self.see_regdom(&r, t);
        }
    }
}

struct Lookups<'a> {
    hosts: HashSet<&'a str>,
    by_parent: HashMap<&'a str, Vec<&'a str>>,
    regdoms: HashSet<&'a str>,
}

#[derive(Default)]
struct SegmentScan {
    obs: Observed,
    flags: Flags,
    segments: usize,
    truncated: usize,
    unreadable: u64,
    rescored: u64,
}

fn scan_segment(
    path: &Path,
    lk: &Lookups<'_>,
    window: (u64, u64),
    rescore: Option<&Engine>,
    acc: &mut SegmentScan,
) -> Result<()> {
    acc.segments += 1;
    let r = BufReader::with_capacity(1 << 20, GzDecoder::new(File::open(path)?));
    let mut err: Option<anyhow::Error> = None;
    let truncated = read_lines(r, |line| {
        if err.is_some() {
            return;
        }
        let mut c = line.split('\t');
        let (Some(_), Some(ts), Some(names), Some(wild)) = (c.next(), c.next(), c.next(), c.next())
        else {
            acc.unreadable += 1;
            return;
        };
        if names == "!unparsed" {
            return;
        }
        let Ok(ts) = ts.parse::<u64>() else {
            acc.unreadable += 1;
            return;
        };
        if ts < window.0 || ts >= window.1 {
            return;
        }
        for n in names.split(' ').filter(|n| !n.is_empty()) {
            if lk.hosts.contains(n) {
                acc.obs.see_own_name(n, ts);
            }
            for s in suffixes(n) {
                if lk.regdoms.contains(s) {
                    acc.obs.see_regdom(s, ts);
                }
            }
        }
        let wild_set: Vec<&str> = wild.split(' ').filter(|w| !w.is_empty()).collect();
        for w in &wild_set {
            if let Some(hs) = lk.by_parent.get(w) {
                for h in hs {
                    acc.obs.see_host(h, ts);
                }
            }
        }
        if let Some(engine) = rescore {
            for n in names.split(' ').filter(|n| !n.is_empty()) {
                acc.rescored += 1;
                let a = match engine.assess(n) {
                    Ok(a) => a,
                    Err(e) => {
                        err = Some(anyhow::anyhow!("assess {n}: {e}"));
                        return;
                    }
                };
                if !a
                    .findings
                    .iter()
                    .any(|f| cybermesh_ct::is_brand_signal(f.code))
                {
                    continue;
                }
                let codes: Vec<String> = a
                    .findings
                    .iter()
                    .filter_map(|f| {
                        serde_json::to_value(f.code)
                            .ok()
                            .and_then(|v| v.as_str().map(str::to_owned))
                    })
                    .collect();
                // Offline: the scan time is the log time (no operational delay).
                acc.flags.add(
                    n,
                    Occ { ts, seen: ts },
                    wild_set.contains(&n),
                    (a.verdict, a.risk_score_bp),
                    &crate::ct_cmd::brand_names(&a),
                    &codes,
                );
            }
        }
    });
    acc.truncated += usize::from(truncated);
    err.map_or(Ok(()), Err)
}

/// Reads every name segment, in parallel.
fn scan_names(
    run: &Path,
    lk: &Lookups<'_>,
    window: (u64, u64),
    rescore: Option<&Engine>,
    threads: usize,
) -> Result<SegmentScan> {
    let root = run.join("names");
    let mut files = Vec::new();
    if root.is_dir() {
        for log in fs::read_dir(&root)? {
            let log = log?.path();
            if log.is_dir() {
                for f in fs::read_dir(&log)? {
                    let f = f?.path();
                    if f.to_string_lossy().ends_with(".tsv.gz") {
                        files.push(f);
                    }
                }
            }
        }
    }
    files.sort();
    let queue = Mutex::new(files);
    let results: Vec<Result<SegmentScan>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads.max(1))
            .map(|_| {
                s.spawn(|| -> Result<SegmentScan> {
                    let mut acc = SegmentScan::default();
                    loop {
                        let next = queue
                            .lock()
                            .map_err(|_| anyhow::anyhow!("queue poisoned"))?
                            .pop();
                        let Some(f) = next else { break };
                        scan_segment(&f, lk, window, rescore, &mut acc)?;
                    }
                    Ok(acc)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("a reader thread panicked")))
            })
            .collect()
    });
    let mut all = SegmentScan::default();
    for r in results {
        let r = r?;
        all.obs.merge(r.obs);
        all.flags.merge(r.flags);
        all.segments += r.segments;
        all.truncated += r.truncated;
        all.unreadable += r.unreadable;
        all.rescored += r.rescored;
    }
    Ok(all)
}

fn load_flags(run: &Path, window: (u64, u64), st: &mut RunStats) -> Result<Flags> {
    let mut flags = Flags::default();
    let path = run.join("matches.jsonl");
    if !path.exists() {
        return Ok(flags);
    }
    let r = BufReader::with_capacity(1 << 20, File::open(&path)?);
    read_lines(r, |line| {
        if line.trim().is_empty() {
            return;
        }
        st.match_lines += 1;
        let Ok(m) = serde_json::from_str::<MatchRecord>(line) else {
            st.match_lines_unreadable += 1;
            return;
        };
        if m.ts_ms < window.0 || m.ts_ms >= window.1 {
            return;
        }
        // The engine's own (kebab-case) code names.
        let codes: Vec<String> = m
            .codes
            .iter()
            .filter_map(|c| {
                serde_json::to_value(c)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
            })
            .collect();
        flags.add(
            &m.name,
            Occ {
                ts: m.ts_ms,
                seen: m.seen_ms,
            },
            m.wildcard,
            (m.verdict, m.risk_score_bp),
            &m.brands,
            &codes,
        );
    });
    Ok(flags)
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
    /// ...with a certificate naming the host itself before confirmation, and recall among
    /// those, per level. Added on 2026-11-20 after the dev-window analysis: a host covered
    /// only by a wildcard certificate for its parent is counted as visible above, but its
    /// name never appears in CT (docs/ct-evaluation.md 4).
    pub observability_own_name: Proportion,
    pub recall_own_name: BTreeMap<String, Proportion>,
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

/// Visible, primary-confirmed hosts by who caught them before confirmation.
#[derive(Debug, Default, Serialize)]
pub struct CaughtBy {
    pub both: u64,
    pub cybermesh_only: u64,
    pub phishunt_only: u64,
    pub neither: u64,
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
    /// Hosts both flagged (signal level): hours from the log time of CyberMesh's first
    /// flagged certificate to phishunt's `first_seen` (positive: CyberMesh was earlier).
    /// This is the pre-registered comparison.
    pub cybermesh_earlier_hours: Quantiles,
    pub cybermesh_earlier: Proportion,
    /// The same from the time CyberMesh scanned it (includes its operational delay).
    pub cybermesh_scan_earlier_hours: Quantiles,
    pub cybermesh_scan_earlier: Proportion,
    /// Primary-confirmed, visible hosts in the recall window by who caught them first.
    pub caught_by: BTreeMap<String, CaughtBy>,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub method: &'static str,
    /// Engine and evidence of `--rescore-evidence`, when used.
    pub rescored_with: Option<BTreeMap<String, String>>,
    pub run: RunStats,
    pub feeds: FeedStats,
    pub recall_window_from_ms: u64,
    pub recall_window_to_ms: u64,
    pub primary: Detection,
    pub broad: Detection,
    /// Hosts whose phishunt `company` is a protected brand.
    pub in_scope_primary: Detection,
    pub per_source_lead_hours: BTreeMap<String, Quantiles>,
    /// Scan time minus log time of each flagged name's first certificate (seconds); empty
    /// when re-scored offline.
    pub detection_latency_secs: Quantiles,
    pub precision: Precision,
    pub phishunt: PeerComparison,
    pub fp_sample_size: usize,
}

fn detection(
    hosts: &[(&str, u64)],
    obs: &Observed,
    flags: &Flags,
    regdom_of: &HashMap<&str, String>,
    regflags: &HashMap<String, [Option<u64>; 3]>,
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
    let own: Vec<&(&str, u64)> = hosts
        .iter()
        .filter(|(h, c)| obs.host_own_name.get(*h).is_some_and(|t| t <= c))
        .collect();
    d.observability_own_name = Proportion::of(own.len() as u64, d.confirmed);
    for level in Level::ALL {
        let hit = own
            .iter()
            .filter(|(h, c)| flags.covering(h, level).is_some_and(|o| o.ts <= *c))
            .count() as u64;
        d.recall_own_name
            .insert(level.name().into(), Proportion::of(hit, own.len() as u64));
    }
    for level in Level::ALL {
        let mut hit = 0u64;
        let mut lead = Vec::new();
        for (h, c) in &observable {
            if let Some(o) = flags.covering(h, level).filter(|o| o.ts <= *c) {
                hit += 1;
                lead.push((c - o.ts) as f64 / HOUR_MS as f64);
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
                    .and_then(|m| m[level.ix()])
                    .is_some_and(|t| t <= *c)
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

fn lead_vs(c: u64, t: u64) -> f64 {
    (c as f64 - t as f64) / HOUR_MS as f64
}

/// Runs the evaluation and writes `report.json` and `fp-sample.csv` to `a.out`.
#[allow(clippy::too_many_lines)]
pub fn run(a: &EvaluateArgs) -> Result<Report> {
    let ev = EvidenceBundle::load(&a.evidence)?;
    let brands: HashSet<String> = ev.brands.iter().map(|b| slug(&b.name)).collect();
    let rescore = a
        .rescore_evidence
        .as_ref()
        .map(|p| EvidenceBundle::load(p).map(Engine::new))
        .transpose()?;
    let (mut st, polls) = run_stats(&a.run)?;
    let from = a.from_ms.unwrap_or(st.start_ms);
    let to = a.to_ms.unwrap_or(st.window_to_ms);
    if to <= from {
        bail!("empty window: --to-ms must be after --from-ms (and the run must have polls)");
    }
    st.window_from_ms = from;
    st.window_to_ms = to;
    for &(t, tiles, entries, unparsed) in &polls.counts {
        if t >= from && t < to {
            st.tiles_scanned += tiles;
            st.entries_scanned += entries;
            st.unparsed_entries += unparsed;
        }
    }
    for (log, iv) in &polls.by_log {
        let g = gaps(iv, from, to);
        st.downtime_ms
            .insert(log.clone(), g.iter().map(|(x, y)| y - x).sum());
        st.downtime.insert(log.clone(), g);
    }
    let (truth, feeds) = load_truth(&a.run)?;
    let confirmed_until = feeds.last_snapshot_ms.unwrap_or(to);
    let recall_from = from + a.burn_in_hours * HOUR_MS;

    // Everything the name scan must look up.
    let host_list: Vec<&str> = truth.keys().map(String::as_str).collect();
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
    let lk = Lookups {
        hosts: host_list.iter().copied().collect(),
        by_parent,
        regdoms: regdom_of.values().map(String::as_str).collect(),
    };
    let scan = scan_names(&a.run, &lk, (from, to), rescore.as_ref(), a.threads)?;
    st.name_segments = scan.segments;
    st.truncated_segments = scan.truncated;
    st.name_lines_unreadable = scan.unreadable;
    st.names_rescored = scan.rescored;
    let obs = scan.obs;
    let flags = if rescore.is_some() {
        scan.flags
    } else {
        load_flags(&a.run, (from, to), &mut st)?
    };
    st.flagged_names = flags.names.len();
    let mut regflags: HashMap<String, [Option<u64>; 3]> = HashMap::new();
    for (name, f) in &flags.names {
        for s in suffixes(name) {
            if lk.regdoms.contains(s) {
                let m = regflags.entry(s.to_owned()).or_default();
                for level in Level::ALL {
                    if let Some(o) = f.exact[level.ix()] {
                        set_min(&mut m[level.ix()], o.ts);
                    }
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
        rescored_with: rescore.as_ref().map(|e| {
            let mut m: BTreeMap<String, String> = e
                .evidence()
                .pins
                .iter()
                .map(|(k, v)| (k.clone(), v.to_string()))
                .collect();
            m.insert("engine".into(), cybermesh_analysis::ENGINE_VERSION.into());
            m
        }),
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
                let o = flags.covering(h, Level::Warn).filter(|o| o.ts <= c)?;
                Some(lead_vs(c, o.ts))
            })
            .collect();
        rep.per_source_lead_hours
            .insert(src.into(), quantiles(lead));
    }
    if rescore.is_none() {
        rep.detection_latency_secs = quantiles(
            flags
                .names
                .values()
                .filter_map(|f| f.exact[Level::Signal.ix()])
                .map(|o| o.seen.saturating_sub(o.ts) as f64 / 1000.0)
                .collect(),
        );
    }

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
    let confirmed_as = |name: &str, f: &Flag, level: Level| -> (bool, bool) {
        let direct = truth.get(name).map_or((false, false), |t| {
            (
                t.primary().is_some_and(|c| c <= confirmed_until),
                t.broad().is_some_and(|c| c <= confirmed_until),
            )
        });
        let child = if f.wild[level.ix()].is_some() {
            confirmed_children.get(name).copied().unwrap_or_default()
        } else {
            (false, false)
        };
        (direct.0 || child.0, direct.1 || child.1)
    };
    for level in Level::ALL {
        let (mut n, mut kp, mut kb) = (0u64, 0u64, 0u64);
        for (name, f) in flags.names.iter().filter(|(_, f)| f.at(level)) {
            n += 1;
            let (p, b) = confirmed_as(name, f, level);
            kp += u64::from(p);
            kb += u64::from(b);
            if level == Level::Warn {
                let names = flags.brand_names(f);
                for brand in if names.is_empty() {
                    vec!["(none)".to_owned()]
                } else {
                    names
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
            .filter(|(h, _, _)| flags.covering(h, level).is_some())
            .count() as u64;
        rep.phishunt.flagged_of_phishunt_observable.insert(
            level.name().into(),
            Proportion::of(k, observable.len() as u64),
        );
    }
    let warn: Vec<&String> = flags
        .names
        .iter()
        .filter(|(_, f)| f.at(Level::Warn))
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
    let (mut by_log, mut by_scan) = (Vec::new(), Vec::new());
    for (h, t, _) in &listed {
        if let (Some(first), Some(o)) = (t.phishunt_first_seen_ms, flags.covering(h, Level::Signal))
        {
            by_log.push(lead_vs(first, o.ts));
            by_scan.push(lead_vs(first, o.seen));
        }
    }
    let pos = |v: &[f64]| v.iter().filter(|d| **d > 0.0).count() as u64;
    rep.phishunt.cybermesh_earlier = Proportion::of(pos(&by_log), by_log.len() as u64);
    rep.phishunt.cybermesh_scan_earlier = Proportion::of(pos(&by_scan), by_scan.len() as u64);
    rep.phishunt.cybermesh_earlier_hours = quantiles(by_log);
    rep.phishunt.cybermesh_scan_earlier_hours = quantiles(by_scan);
    for level in [Level::Signal, Level::Warn] {
        let mut cb = CaughtBy::default();
        for (h, c) in &primary {
            if !obs.host.get(*h).is_some_and(|o| o <= c) {
                continue;
            }
            let ours = flags.covering(h, level).is_some_and(|o| o.ts <= *c);
            let theirs = truth[*h].phishunt_ms().is_some_and(|p| p <= *c);
            match (ours, theirs) {
                (true, true) => cb.both += 1,
                (true, false) => cb.cybermesh_only += 1,
                (false, true) => cb.phishunt_only += 1,
                (false, false) => cb.neither += 1,
            }
        }
        rep.phishunt.caught_by.insert(level.name().into(), cb);
    }

    // False-alarm sample: unconfirmed warn-level names, stratified by their alphabetically
    // first brand, proportionally (at least one per brand), ranked by a fixed hash.
    let mut strata: BTreeMap<String, Vec<(&String, &Flag)>> = BTreeMap::new();
    for (name, f) in flags.names.iter().filter(|(_, f)| f.at(Level::Warn)) {
        if confirmed_as(name, f, Level::Warn).1 {
            continue;
        }
        let b = flags
            .brand_names(f)
            .into_iter()
            .next()
            .unwrap_or_else(|| "(none)".into());
        strata.entry(b).or_default().push((name, f));
    }
    let total: usize = strata.values().map(Vec::len).sum();
    let mut sample = Vec::new();
    for items in strata.values_mut() {
        items.sort_by_cached_key(|(n, _)| rank(n));
        let quota = if total == 0 {
            0
        } else {
            (a.sample * items.len()).div_ceil(total).max(1)
        };
        sample.extend(items.iter().take(quota).copied());
    }
    sample.sort_by_cached_key(|(n, _)| rank(n));
    sample.truncate(a.sample);
    sample.sort_by(|x, y| {
        flags
            .brand_names(x.1)
            .cmp(&flags.brand_names(y.1))
            .then(x.0.cmp(y.0))
    });
    rep.fp_sample_size = sample.len();
    fs::create_dir_all(&a.out)?;
    let mut csv = String::from(
        "name,brands,verdict,risk_score_bp,codes,first_logged_utc,wildcard,phishunt_listed,label\n",
    );
    for (name, f) in &sample {
        let first = f.exact[Level::Warn.ix()]
            .or(f.wild[Level::Warn.ix()])
            .map_or(0, |o| o.ts);
        let verdict = f
            .verdict
            .and_then(|v| serde_json::to_value(v).ok())
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let row = [
            csv_field(name),
            csv_field(&flags.brand_names(f).join(" ")),
            verdict,
            f.risk_score_bp.to_string(),
            csv_field(&flags.code_names(f).join(" ")),
            utc(first),
            f.wild[Level::Warn.ix()].is_some().to_string(),
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
        (Some(a), Some(m), Some(b)) => {
            format!("median {m:.1} h (IQR {a:.1}–{b:.1} h, n={})", q.n)
        }
        _ => "n/a".into(),
    }
}

/// Prints the main figures.
pub fn print(rep: &Report) {
    let r = &rep.run;
    println!(
        "window {} .. {}: {} tiles, {} entries from {} log(s) in polls inside the window ({} tiles in the whole run); {} flagged names{}; downtime {:?} ms",
        utc(r.window_from_ms),
        utc(r.window_to_ms),
        r.tiles_scanned,
        r.entries_scanned,
        r.logs.len(),
        r.tiles_scanned_run,
        r.flagged_names,
        if rep.rescored_with.is_some() {
            format!(" (re-scored: {} names assessed)", r.names_rescored)
        } else {
            String::new()
        },
        r.downtime_ms
    );
    println!(
        "unreadable lines: matches {}, polls {}, events {}, runs {}, names {}; truncated name segments {}, feed snapshots {}",
        r.match_lines_unreadable,
        r.poll_lines_unreadable,
        r.event_lines_unreadable,
        r.run_lines_unreadable,
        r.name_lines_unreadable,
        r.truncated_segments,
        rep.feeds.truncated_snapshots
    );
    println!(
        "feeds: {} phishunt and {} OpenPhish snapshots; {} listed URLs not on a domain name; {} phishunt first_seen unparsed",
        rep.feeds.phishunt_snapshots,
        rep.feeds.openphish_snapshots,
        rep.feeds.not_a_domain,
        rep.feeds.phishunt_first_seen_unparsed
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
            "  visible in the followed logs before confirmation: {}; under its own name: {}",
            pct(&d.observability),
            pct(&d.observability_own_name)
        );
        for l in ["signal", "warn", "block"] {
            println!(
                "  recall [{l}]: {} of visible, {} of visible under its own name, {} end to end; lead {}",
                pct(&d.recall[l]),
                pct(&d.recall_own_name[l]),
                pct(&d.recall_end_to_end[l]),
                hours(&d.lead_hours[l])
            );
        }
    }
    for (s, q) in &rep.per_source_lead_hours {
        println!("lead time vs {s} [warn]: {}", hours(q));
    }
    if rep.rescored_with.is_none() {
        println!(
            "detection latency (scan - log time): median {:.0} s, p90 {:.0} s",
            rep.detection_latency_secs.median.unwrap_or(0.0),
            rep.detection_latency_secs.p90.unwrap_or(0.0)
        );
    }
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
        "phishunt: {} listed, {} visible in our logs first; we flagged {} [signal], {} [warn]; phishunt listed {} of our warn names",
        p.phishunt_listed,
        p.phishunt_listed_observable,
        pct(&p.flagged_of_phishunt_observable["signal"]),
        pct(&p.flagged_of_phishunt_observable["warn"]),
        pct(&p.phishunt_of_warn)
    );
    println!(
        "  CyberMesh earlier (log time) for {}: {}; by scan time {}: {}",
        pct(&p.cybermesh_earlier),
        hours(&p.cybermesh_earlier_hours),
        pct(&p.cybermesh_scan_earlier),
        hours(&p.cybermesh_scan_earlier_hours)
    );
    for (l, c) in &p.caught_by {
        println!(
            "  confirmed and visible, caught before confirmation [{l}]: both {}, CyberMesh only {}, phishunt only {}, neither {}",
            c.both, c.cybermesh_only, c.phishunt_only, c.neither
        );
    }
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
        let z = parse_iso_ms("2026-11-18T17:23:31Z");
        assert_eq!(parse_iso_ms("2026-11-18T18:23:31+01:00"), z);
        assert_eq!(parse_iso_ms("2026-11-18T17:23:31+00"), z);
        assert_eq!(parse_iso_ms("2026-11-18T19:23:31+0200"), z);
        assert_eq!(parse_iso_ms("2026-11-18T17:23:31"), z);
        assert_eq!(parse_iso_ms("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_iso_ms("2026-02-30T00:00:00Z"), None);
        assert!(parse_iso_ms("2028-02-29T00:00:00Z").is_some());
        assert_eq!(parse_iso_ms("garbage"), None);
        assert_eq!(parse_snapshot_ms("20261118T172331Z.csv.gz", ".csv.gz"), z);
        assert_eq!(
            parse_snapshot_ms("20261118T172331Z.csv.gz.tmp", ".csv.gz"),
            None
        );
        assert_eq!(
            parse_snapshot_ms("20261118T172331Z.txt.gz", ".csv.gz"),
            None
        );
        assert_eq!(parse_snapshot_ms("notes.csv.gz", ".csv.gz"), None);
        assert_eq!(utc(1_795_022_611_342), "2026-11-18T17:23:31Z");
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn csv_hosts_and_intervals() {
        let rows = parse_csv("\u{feff}a,b,c\n\"x, y\",\"say \"\"hi\"\"\",3\r\nlast,,");
        assert_eq!(rows[0], vec!["a", "b", "c"]);
        assert_eq!(rows[1], vec!["x, y", "say \"hi\"", "3"]);
        assert_eq!(rows[2], vec!["last", "", ""]);
        assert_eq!(
            url_host("https://User@Login.Example.COM:8443/x?y#z").as_deref(),
            Some("login.example.com")
        );
        assert_eq!(url_host("example.org/path").as_deref(), Some("example.org"));
        assert_eq!(
            url_host("evil.example.net/r?u=http://good.example.com/").as_deref(),
            Some("evil.example.net")
        );
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

    #[test]
    fn downtime_includes_the_start_the_end_and_is_clipped() {
        let m = 60_000;
        // Polls every minute from 10 to 20 min, then from 30 to 40 min; window 0..60 min.
        let mut iv: Vec<(u64, u64)> = (10..=20).map(|i| (i * m, i * m + 1000)).collect();
        iv.extend((30..=40).map(|i| (i * m, i * m + 1000)));
        assert_eq!(
            gaps(&iv, 0, 60 * m),
            vec![
                (0, 10 * m),
                (20 * m + 1000, 30 * m),
                (40 * m + 1000, 60 * m)
            ]
        );
        // A window inside the second stretch has no downtime; one that starts mid-gap clips.
        assert!(gaps(&iv, 31 * m, 39 * m).is_empty());
        assert_eq!(gaps(&iv, 25 * m, 35 * m), vec![(25 * m, 30 * m)]);
        // A log that never polled is down for the whole window.
        assert_eq!(gaps(&[], 0, 10 * m), vec![(0, 10 * m)]);
    }

    #[test]
    fn levels_keep_their_own_earliest_time_and_merge() {
        let mut f = Flags::default();
        let b = vec!["paypal".to_owned()];
        let c = vec!["brand-impersonation".to_owned()];
        f.add(
            "x.example",
            Occ { ts: 10, seen: 11 },
            false,
            (Verdict::NoSignal, 3000),
            &b,
            &c,
        );
        f.add(
            "x.example",
            Occ { ts: 20, seen: 21 },
            true,
            (Verdict::Suspicious, 5000),
            &b,
            &c,
        );
        let x = &f.names["x.example"];
        assert_eq!(x.exact[0], Some(Occ { ts: 10, seen: 11 }));
        assert_eq!(x.exact[1], Some(Occ { ts: 20, seen: 21 }));
        assert_eq!(x.exact[2], None);
        assert_eq!(
            (x.wild[0], x.wild[1]),
            (
                Some(Occ { ts: 20, seen: 21 }),
                Some(Occ { ts: 20, seen: 21 })
            )
        );
        assert_eq!(x.verdict, Some(Verdict::Suspicious));
        assert_eq!(f.covering("x.example", Level::Warn).unwrap().ts, 20);
        assert_eq!(f.covering("login.x.example", Level::Signal).unwrap().ts, 20);
        let mut g = Flags::default();
        g.add(
            "x.example",
            Occ { ts: 5, seen: 6 },
            false,
            (Verdict::Malicious, 9000),
            &["amazon".to_owned()],
            &c,
        );
        f.merge(g);
        let x = &f.names["x.example"];
        assert_eq!(
            x.exact.map(|o| o.map(|o| o.ts)),
            [Some(5), Some(5), Some(5)]
        );
        assert_eq!(x.verdict, Some(Verdict::Malicious));
        assert_eq!(f.brand_names(x), vec!["amazon", "paypal"]);
        assert_eq!(f.code_names(x), vec!["brand-impersonation"]);
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

    fn snap(t: u64) -> String {
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
    }

    fn args(run: &Path, out: &Path, rescore: bool) -> EvaluateArgs {
        let ev = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../datasets/demo/evidence");
        EvaluateArgs {
            run: run.to_owned(),
            evidence: ev.clone(),
            rescore_evidence: rescore.then_some(ev),
            from_ms: None,
            to_ms: None,
            burn_in_hours: 24,
            sample: 10,
            threads: 2,
            out: out.to_owned(),
        }
    }

    /// A small synthetic run with known answers.
    #[test]
    fn scores_a_synthetic_run() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path();
        let h = HOUR_MS;
        let t0 = parse_iso_ms("2026-11-18T00:00:00Z").unwrap();
        fs::write(run.join("runs.jsonl"), format!("{{\"started_ms\":{t0}}}\n")).unwrap();
        // One poll an hour for 10 days, plus a torn and an invalid UTF-8 line.
        let mut polls = Vec::new();
        for i in 0..=240u64 {
            polls.extend_from_slice(
                line(&PollRecord {
                    log: "log-a".into(),
                    t_ms: t0 + i * h,
                    tiles: 1,
                    entries: 256,
                    elapsed_ms: 1000,
                    ..PollRecord::default()
                })
                .as_bytes(),
            );
        }
        polls.extend_from_slice(b"{\"log\":\"log-a\",\xff\xfe}\n{\"torn");
        fs::write(run.join("polls.jsonl"), polls).unwrap();
        // Certificates (log time):
        //  phish-paypal-login.com          day 2: flagged warn; confirmed by OpenPhish day 3
        //  secure.paypa1-verify.net        day 2: covered by *.paypa1-verify.net, flagged
        //                                         block; confirmed by Safe Browsing day 2 + 6 h
        //  plain-unflagged.example         day 2: not flagged; confirmed day 4
        //  amazon-infra.amazonaws.example  day 3: flagged warn, never confirmed (false alarm)
        //  late-phish.com                  day 5: flagged warn, but confirmed before (day 4.5)
        //  invisible.example (no cert)            confirmed day 3, not visible
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
        for r in [
            m(
                1,
                t0 + 48 * h,
                "phish-paypal-login.com",
                false,
                Verdict::Suspicious,
            ),
            m(
                1,
                t0 + 48 * h,
                "phish-paypal-login.com",
                false,
                Verdict::Suspicious,
            ),
            m(
                2,
                t0 + 48 * h,
                "paypa1-verify.net",
                true,
                Verdict::Malicious,
            ),
            m(
                4,
                t0 + 72 * h,
                "amazon-infra.amazonaws.example",
                false,
                Verdict::Suspicious,
            ),
            m(
                5,
                t0 + 120 * h,
                "late-phish.com",
                false,
                Verdict::Suspicious,
            ),
        ] {
            matches.push_str(&line(&r));
        }
        matches.push_str("{\"torn\":");
        fs::write(run.join("matches.jsonl"), matches).unwrap();
        // Feeds.
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
            &format!(
                "{header}http://198.51.100.9/x,,other,x,x,true,false,false,false,false\nhttps://bad-date.example/,bad-date.example,other,x,not-a-date,false,false,false,false,false\n"
            ),
        );
        // An interrupted export is ignored.
        fs::write(
            run.join(format!("feeds/phishunt/{}.csv.gz.tmp", snap(t0 + 100 * h))),
            b"partial",
        )
        .unwrap();
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
        let rep = super::run(&args(run, &out, false)).unwrap();

        // Primary ground truth: OpenPhish (phish-paypal-login day 3, invisible day 3,
        // plain-unflagged day 4, late-phish day 4.5) and Safe Browsing (secure.paypa1-verify
        // day 2.25).
        let p = &rep.primary;
        assert_eq!(p.confirmed, 5);
        // Visible before confirmation: phish-paypal-login, secure.paypa1-verify (wildcard),
        // plain-unflagged. Not: invisible (no cert), late-phish (cert after confirmation).
        assert_eq!((p.observability.k, p.observability.n), (3, 5));
        // secure.paypa1-verify.net was visible only through *.paypa1-verify.net.
        assert_eq!(
            (p.observability_own_name.k, p.observability_own_name.n),
            (2, 5)
        );
        assert_eq!(
            (p.recall_own_name["warn"].k, p.recall_own_name["warn"].n),
            (1, 2)
        );
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
        // By registrable domain: paypa1-verify.net is flagged itself.
        assert_eq!(p.regdom_recall["warn"].k, 2);

        // Precision floor at warn level: 4 names flagged; phish-paypal-login, the wildcard
        // parent paypa1-verify.net and late-phish are confirmed; the amazon one is not.
        assert_eq!(rep.precision.flagged["warn"], 4);
        assert_eq!(rep.precision.flagged["block"], 1);
        assert_eq!(rep.precision.confirmed_primary["warn"].k, 3);
        assert_eq!(rep.precision.warn_by_brand["amazon"], (1, 0));

        // phishunt listed two hosts, both visible first, both flagged. CyberMesh's
        // certificates were logged at t0 + 48 h (scanned 20 s later); phishunt's first_seen
        // is t0 + 47 h for phish-paypal-login (phishunt earlier by 1 h) and t0 + 51 h for
        // secure.paypa1-verify (CyberMesh earlier by 3 h).
        let ph = &rep.phishunt;
        // A third listing (bad-date.example, with an unparseable first_seen) has no cert.
        assert_eq!(ph.phishunt_listed, 3);
        assert_eq!(ph.phishunt_listed_observable, 2);
        assert_eq!(ph.flagged_of_phishunt_observable["warn"].k, 2);
        assert_eq!((ph.cybermesh_earlier.k, ph.cybermesh_earlier.n), (1, 2));
        // By log time (pre-registered): exactly -1 h and +3 h.
        assert!((ph.cybermesh_earlier_hours.median.unwrap() - 1.0).abs() < 1e-9);
        assert!((ph.cybermesh_earlier_hours.p25.unwrap() - 0.0).abs() < 1e-9);
        // By scan time: 20 s less.
        let secs = 20.0 / 3600.0;
        assert!((ph.cybermesh_scan_earlier_hours.median.unwrap() - (1.0 - secs)).abs() < 1e-9);
        // Primary-confirmed, visible hosts: phish-paypal-login (both flagged it, phishunt
        // 23:00 before OpenPhish's day 3), secure.paypa1-verify (CyberMesh at warn: no, it
        // is block, so warn too; phishunt first_seen day 2 + 3 h before Safe Browsing day
        // 2 + 6 h: both), plain-unflagged (neither).
        assert_eq!(ph.caught_by["warn"].both, 2);
        assert_eq!(ph.caught_by["warn"].neither, 1);
        assert_eq!(
            ph.caught_by["warn"].cybermesh_only + ph.caught_by["warn"].phishunt_only,
            0
        );

        // Bookkeeping. The window runs to the latest snapshot of either feed.
        assert_eq!(rep.recall_window_to_ms, t0 + 239 * h);
        assert_eq!(rep.feeds.first_snapshot_ms, Some(t0 + 54 * h));
        assert_eq!(rep.feeds.phishunt_snapshots, 2);
        assert_eq!(rep.feeds.not_a_domain, 1);
        assert_eq!(rep.feeds.phishunt_first_seen_unparsed, 1);
        assert_eq!(rep.run.match_lines_unreadable, 1);
        assert_eq!(rep.run.poll_lines_unreadable, 2);
        assert_eq!(rep.run.flagged_names, 4);
        assert_eq!(
            (rep.run.tiles_scanned, rep.run.tiles_scanned_run),
            (241, 241)
        );
        // A shorter window counts only the polls inside it (hourly polls, t0 .. t0 + 47 h).
        let mut short = args(run, &run.join("eval-short"), false);
        short.to_ms = Some(t0 + 48 * h);
        let r2 = super::run(&short).unwrap();
        assert_eq!((r2.run.tiles_scanned, r2.run.tiles_scanned_run), (48, 241));
        assert_eq!(r2.run.entries_scanned, 48 * 256);
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

    #[test]
    fn rescoring_reassesses_stored_names_and_tolerates_a_truncated_segment() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path();
        let t0 = parse_iso_ms("2026-11-18T00:00:00Z").unwrap();
        fs::write(run.join("runs.jsonl"), format!("{{\"started_ms\":{t0}}}\n")).unwrap();
        fs::write(
            run.join("polls.jsonl"),
            line(&PollRecord {
                log: "log-a".into(),
                t_ms: t0 + HOUR_MS,
                elapsed_ms: 1000,
                ..PollRecord::default()
            }),
        )
        .unwrap();
        // One complete segment and one cut in the middle of its gzip stream.
        let mut seg = String::new();
        seg.push_str(&format!(
            "1\t{}\texamplebank-secure-login.example.net\t\n",
            t0 + 10
        ));
        seg.push_str(&format!("2\t{}\twww.example.org example.org\t\n", t0 + 11));
        gz(&run.join("names/log-a/000000000000.tsv.gz"), &seg);
        let mut big = String::new();
        for i in 0..20_000u64 {
            big.push_str(&format!(
                "{}\t{}\thost-{i}.example.org\t\n",
                100 + i,
                t0 + 20
            ));
        }
        let p = run.join("names/log-a/000000000256.tsv.gz");
        gz(&p, &big);
        let bytes = fs::read(&p).unwrap();
        fs::write(&p, &bytes[..bytes.len() / 2]).unwrap();
        let rep = super::run(&args(run, &run.join("eval"), true)).unwrap();
        assert!(rep.rescored_with.is_some());
        assert_eq!(rep.run.name_segments, 2);
        assert_eq!(rep.run.truncated_segments, 1);
        assert!(rep.run.names_rescored > 3 && rep.run.names_rescored < 20_003);
        assert!(rep.run.flagged_names >= 1, "{:?}", rep.run);
        assert_eq!(rep.detection_latency_secs.n, 0);
        assert_eq!(
            rep.precision.flagged["signal"],
            rep.run.flagged_names as u64
        );
    }
}
