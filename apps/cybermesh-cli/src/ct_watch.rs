//! `cybermesh ct watch`: a single-process follower of live CT logs, for evaluations.
//!
//! It records what CyberMesh's CT scan flags, when, and every certificate name it saw, so
//! detections can later be compared with independently confirmed phishing
//! (`cybermesh ct evaluate`). It is also the single-server baseline for measuring what
//! decentralisation costs.
//!
//! Each log has its own thread. A poll fetches the checkpoint, verifies it against the pinned
//! key, requires it to be fresh and (after the first) to extend the previously accepted one by
//! a consistency proof. It then fetches each new full tile, proves the tile's root against the
//! signed checkpoint and scans it. No tile is skipped: one whose root cannot be proven stops the
//! poll and is retried on the next.
//!
//! Output directory:
//! - `runs.jsonl`: one line per start (versions, evidence pins, logs, settings).
//! - `state/<log>.json`: resume point (first tile of the open name segment) and accepted head.
//! - `matches.jsonl`: one line per name with a brand signal: the same names the shipped scan
//!   flags, without its per-tile caps. `wildcard` marks names listed as `*.name`. After a
//!   restart a segment is rescanned, so lines can repeat: dedupe by (log, index, name).
//! - `names/<log>/<first tile>.tsv.gz`: every entry, as `index \t timestamp_ms \t names \t
//!   wildcards` (space-separated, normalised; wildcards are the names listed as `*.name`).
//!   An entry whose certificate does not parse has `!unparsed` as its names. After a hard
//!   kill the open segment's gzip stream is truncated: read it up to the error.
//! - `polls.jsonl`, `events.jsonl` (refused checkpoints, unproven tiles, fetch errors) and
//!   `process.jsonl` (process CPU and memory every minute).
//!
//! Stop with Ctrl-C, SIGTERM, a `STOP` file in the output directory, or `--duration-secs`.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use clap::Args;
use cybermesh_analysis::{CtLogInfo, Engine, EvidenceBundle, normalize_domain};
use cybermesh_ct::checkpoint::{MAX_CHECKPOINT_AGE_SECS, check_fresh, fetch_verified_checkpoint};
use cybermesh_ct::names::certificate_dns_names;
use cybermesh_ct::proof::TileAuthenticator;
use cybermesh_ct::tile::{parse_data_tile, tile_root};
use cybermesh_ct::{Checkpoint, CtError, EntryKind, TileSource, is_brand_signal};
use cybermesh_protocol::{FindingCode, Verdict};
use flate2::Compression;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};

use crate::ct_cmd::brand_names;
use crate::util::{read_json, write_json};

/// Tiles per name segment. A restart rescans at most one segment per log.
pub const SEGMENT_TILES: u64 = 256;

#[derive(Args, Debug, Clone)]
pub struct WatchArgs {
    /// Evidence bundle with a `ct-logs` source and the protected-brand table.
    #[arg(long)]
    pub evidence: PathBuf,
    /// Log id from the `ct-logs` evidence; repeat for several logs.
    #[arg(long = "log", required = true)]
    pub logs: Vec<String>,
    /// Output directory (created; an existing one is resumed).
    #[arg(long)]
    pub out: PathBuf,
    #[arg(long, default_value_t = 15)]
    pub poll_secs: u64,
    #[arg(long, default_value_t = 256)]
    pub max_tiles_per_poll: u64,
    /// First tile of a new run (one log only). Default: the log's current end.
    #[arg(long)]
    pub start_tile: Option<u64>,
    /// Stop after this many seconds. Default: run until stopped.
    #[arg(long)]
    pub duration_secs: Option<u64>,
    /// Stop once every tile below this one is scanned (one log only): a fixed range, as the
    /// single-process baseline for cost comparisons.
    #[arg(long)]
    pub end_tile: Option<u64>,
}

/// One flagged name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchRecord {
    pub log: String,
    pub tile: u64,
    pub index: u64,
    pub precert: bool,
    /// The log's timestamp for the entry (ms): when the certificate was logged.
    pub ts_ms: u64,
    /// When this process scanned it (ms).
    pub seen_ms: u64,
    pub name: String,
    /// The certificate listed it as a wildcard (`*.name`).
    pub wildcard: bool,
    pub risk_score_bp: u16,
    pub verdict: Verdict,
    pub codes: Vec<FindingCode>,
    pub brands: Vec<String>,
}

/// One poll of one log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollRecord {
    pub log: String,
    pub t_ms: u64,
    pub checkpoint_size: u64,
    pub checkpoint_signed_ms: u64,
    /// Next tile to scan after this poll, and how many full tiles it is behind the log.
    pub next_tile: u64,
    pub lag_tiles: u64,
    pub tiles: u64,
    pub entries: u64,
    pub names: u64,
    pub wildcard_names: u64,
    pub unparsed: u64,
    pub matches: u64,
    /// Bytes received from the log (decoded) and requests made, including proofs.
    pub bytes: u64,
    pub requests: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRecord {
    pub log: String,
    pub t_ms: u64,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    origin: String,
    size: u64,
    root: String,
    signed_at_ms: u64,
}

impl Head {
    fn of(cp: &Checkpoint) -> Self {
        Self {
            origin: cp.origin.clone(),
            size: cp.size,
            root: hex::encode(cp.root),
            signed_at_ms: cp.signed_at_ms,
        }
    }

    fn checkpoint(&self) -> Result<Checkpoint> {
        let mut root = [0u8; 32];
        hex::decode_to_slice(&self.root, &mut root).context("state: bad root")?;
        Ok(Checkpoint {
            origin: self.origin.clone(),
            size: self.size,
            root,
            signed_at_ms: self.signed_at_ms,
        })
    }
}

/// `state/<log>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchState {
    log_id: String,
    /// Every tile below this one is in a closed name segment.
    committed: u64,
    head: Option<Head>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// An append-only JSON-lines file, flushed after every line.
#[derive(Debug)]
pub struct Jsonl(Mutex<BufWriter<File>>);

impl Jsonl {
    /// Opens for appending. A last line torn by a crash is terminated first, so it cannot
    /// swallow the next record (readers skip lines that do not parse).
    pub fn open(path: &Path) -> Result<Self> {
        let mut f = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        let len = f.metadata()?.len();
        if len > 0 {
            use std::io::{Read as _, Seek as _, SeekFrom};
            let mut last = [0u8; 1];
            f.seek(SeekFrom::Start(len - 1))?;
            f.read_exact(&mut last)?;
            if last[0] != b'\n' {
                f.write_all(b"\n")?;
            }
        }
        Ok(Self(Mutex::new(BufWriter::new(f))))
    }

    /// Flushes and syncs the file to disk.
    pub fn sync(&self) -> Result<()> {
        let mut w = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("writer poisoned"))?;
        w.flush()?;
        w.get_ref().sync_data()?;
        Ok(())
    }

    pub fn write<T: Serialize>(&self, v: &T) -> Result<()> {
        let mut line = serde_json::to_vec(v)?;
        line.push(b'\n');
        let mut w = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("writer poisoned"))?;
        w.write_all(&line)?;
        w.flush()?;
        Ok(())
    }
}

/// Shared output files.
#[derive(Debug)]
pub struct Outputs {
    pub dir: PathBuf,
    pub matches: Jsonl,
    pub polls: Jsonl,
    pub events: Jsonl,
}

impl Outputs {
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir.join("state"))?;
        fs::create_dir_all(dir.join("names"))?;
        Ok(Self {
            dir: dir.to_owned(),
            matches: Jsonl::open(&dir.join("matches.jsonl"))?,
            polls: Jsonl::open(&dir.join("polls.jsonl"))?,
            events: Jsonl::open(&dir.join("events.jsonl"))?,
        })
    }
}

/// Counts bytes and requests made through a tile source.
struct Counting<'a> {
    inner: &'a dyn TileSource,
    bytes: AtomicU64,
    requests: AtomicU64,
}

impl<'a> Counting<'a> {
    fn new(inner: &'a dyn TileSource) -> Self {
        Self {
            inner,
            bytes: AtomicU64::new(0),
            requests: AtomicU64::new(0),
        }
    }

    fn count(&self, n: usize) {
        self.bytes.fetch_add(n as u64, Ordering::Relaxed);
        self.requests.fetch_add(1, Ordering::Relaxed);
    }
}

impl TileSource for Counting<'_> {
    fn data_tile(&self, n: u64) -> Result<Vec<u8>, CtError> {
        let r = self.inner.data_tile(n);
        self.count(r.as_ref().map_or(0, Vec::len));
        r
    }

    fn hash_tile(&self, level: u8, n: u64, width: Option<u8>) -> Result<Vec<u8>, CtError> {
        let r = self.inner.hash_tile(level, n, width);
        self.count(r.as_ref().map_or(0, Vec::len));
        r
    }

    fn checkpoint(&self) -> Result<String, CtError> {
        let r = self.inner.checkpoint();
        self.count(r.as_ref().map_or(0, String::len));
        r
    }
}

/// An open name segment.
struct Segment {
    first: u64,
    path: PathBuf,
    enc: GzEncoder<BufWriter<File>>,
}

impl Segment {
    fn create(dir: &Path, first: u64) -> Result<Self> {
        let path = dir.join(format!("{first:012}.tsv.gz"));
        let f = File::create(&path).with_context(|| format!("create {}", path.display()))?;
        Ok(Self {
            first,
            path,
            enc: GzEncoder::new(BufWriter::new(f), Compression::default()),
        })
    }

    /// Finishes the gzip stream and syncs it to disk.
    fn close(self) -> Result<()> {
        let w = self.enc.finish()?;
        let f = w.into_inner().map_err(|e| anyhow::anyhow!("{e}"))?;
        f.sync_all()
            .with_context(|| format!("sync {}", self.path.display()))?;
        Ok(())
    }
}

/// What one poll did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PollOutcome {
    pub tiles: u64,
    pub caught_up: bool,
}

/// Follows one log.
pub struct Watcher<'a> {
    info: CtLogInfo,
    src: &'a dyn TileSource,
    engine: &'a Engine,
    out: &'a Outputs,
    names_dir: PathBuf,
    state_path: PathBuf,
    state: Option<WatchState>,
    next: u64,
    start_tile: Option<u64>,
    end_tile: Option<u64>,
    max_tiles_per_poll: u64,
    seg: Option<Segment>,
}

impl<'a> Watcher<'a> {
    pub fn new(
        info: CtLogInfo,
        src: &'a dyn TileSource,
        engine: &'a Engine,
        out: &'a Outputs,
        start_tile: Option<u64>,
        max_tiles_per_poll: u64,
    ) -> Result<Self> {
        let names_dir = out.dir.join("names").join(&info.log_id);
        fs::create_dir_all(&names_dir)?;
        let state_path = out.dir.join("state").join(format!("{}.json", info.log_id));
        let state: Option<WatchState> = if state_path.exists() {
            let s: WatchState = read_json(&state_path)?;
            if s.log_id != info.log_id {
                bail!("{}: state is for log {}", state_path.display(), s.log_id);
            }
            Some(s)
        } else {
            None
        };
        if let (Some(s), Some(t)) = (&state, start_tile)
            && s.committed != t
        {
            eprintln!(
                "{}: resuming at tile {} (--start-tile {t} applies only to a new run)",
                info.log_id, s.committed
            );
        }
        let next = state.as_ref().map_or(0, |s| s.committed);
        Ok(Self {
            info,
            src,
            engine,
            out,
            names_dir,
            state_path,
            state,
            next,
            start_tile,
            end_tile: None,
            max_tiles_per_poll: max_tiles_per_poll.max(1),
            seg: None,
        })
    }

    /// Stops after tile `end - 1` (see [`WatchArgs::end_tile`]).
    #[must_use]
    pub fn with_end_tile(mut self, end: Option<u64>) -> Self {
        self.end_tile = end;
        self
    }

    fn finished(&self) -> bool {
        self.end_tile.is_some_and(|e| self.next >= e)
    }

    #[cfg(test)]
    fn next_tile(&self) -> u64 {
        self.next
    }

    fn event(&self, kind: &str, detail: String) -> Result<()> {
        self.out.events.write(&EventRecord {
            log: self.info.log_id.clone(),
            t_ms: now_ms(),
            kind: kind.to_owned(),
            detail,
        })
    }

    fn persist(&self) -> Result<()> {
        if let Some(s) = &self.state {
            write_json(&self.state_path, s)?;
        }
        Ok(())
    }

    /// One poll: accept a new checkpoint and scan the new full tiles (at most
    /// `max_tiles_per_poll`). Network and log failures are recorded as events, not errors;
    /// errors are local (disk) failures.
    pub fn poll_once(&mut self, stop: &AtomicBool) -> Result<PollOutcome> {
        let t0 = Instant::now();
        let src = Counting::new(self.src);
        let mut rec = PollRecord {
            log: self.info.log_id.clone(),
            t_ms: now_ms(),
            ..PollRecord::default()
        };
        let cp = match fetch_verified_checkpoint(&src, &self.info)
            .and_then(|cp| check_fresh(&cp, now_ms() / 1000, MAX_CHECKPOINT_AGE_SECS).map(|()| cp))
        {
            Ok(cp) => cp,
            Err(e) => {
                self.event("checkpoint_refused", e.to_string())?;
                return Ok(PollOutcome::default());
            }
        };
        rec.checkpoint_size = cp.size;
        rec.checkpoint_signed_ms = cp.signed_at_ms;
        let auth = TileAuthenticator::new(&src, cp.clone());
        if let Some(head) = self.state.as_ref().and_then(|s| s.head.as_ref()) {
            let older = head.checkpoint()?;
            if cp.size < older.size {
                self.event(
                    "stale_checkpoint",
                    format!("size {} < accepted {}", cp.size, older.size),
                )?;
                return Ok(PollOutcome::default());
            }
            if let Err(e) = auth.prove_extends(&older) {
                let kind = if matches!(e, CtError::Unauthenticated(_)) {
                    "inconsistent_checkpoint"
                } else {
                    "consistency_unavailable"
                };
                self.event(kind, format!("size {} vs {}: {e}", cp.size, older.size))?;
                return Ok(PollOutcome::default());
            }
        }
        let st = self.state.get_or_insert_with(|| WatchState {
            log_id: self.info.log_id.clone(),
            committed: self.start_tile.unwrap_or(cp.full_tiles()),
            head: None,
        });
        if self.next < st.committed {
            self.next = st.committed;
        }
        st.head = Some(Head::of(&cp));
        self.persist()?;
        let end = cp
            .full_tiles()
            .min(self.next.saturating_add(self.max_tiles_per_poll))
            .min(self.end_tile.unwrap_or(u64::MAX));
        while self.next < end && !stop.load(Ordering::Relaxed) {
            let n = self.next;
            let bytes = match src.data_tile(n) {
                Ok(b) => b,
                Err(e) => {
                    self.event("fetch_error", format!("data tile {n}: {e}"))?;
                    break;
                }
            };
            let entries = match parse_data_tile(&bytes, n) {
                Ok(e) => e,
                Err(e) => {
                    self.event("tile_unparsed", format!("data tile {n}: {e}"))?;
                    break;
                }
            };
            match auth.tile_root(n) {
                Ok(proven) if proven == tile_root(&entries) => {}
                Ok(_) => {
                    self.event(
                        "tile_root_mismatch",
                        format!("data tile {n} does not match the signed tree"),
                    )?;
                    break;
                }
                Err(e) => {
                    self.event("tile_unproven", format!("data tile {n}: {e}"))?;
                    break;
                }
            }
            self.scan(n, &entries, &mut rec)?;
            rec.tiles += 1;
            self.next = n + 1;
            if self.next.is_multiple_of(SEGMENT_TILES) {
                self.close_segment(true)?;
            }
        }
        rec.next_tile = self.next;
        rec.lag_tiles = cp.full_tiles().saturating_sub(self.next);
        rec.bytes = src.bytes.load(Ordering::Relaxed);
        rec.requests = src.requests.load(Ordering::Relaxed);
        rec.elapsed_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.out.polls.write(&rec)?;
        Ok(PollOutcome {
            tiles: rec.tiles,
            caught_up: rec.lag_tiles == 0,
        })
    }

    fn scan(
        &mut self,
        tile: u64,
        entries: &[cybermesh_ct::Entry],
        rec: &mut PollRecord,
    ) -> Result<()> {
        if self.seg.is_none() {
            self.seg = Some(Segment::create(&self.names_dir, tile)?);
        }
        let seen_ms = now_ms();
        let mut lines = String::new();
        for e in entries {
            rec.entries += 1;
            let Ok(raw) = certificate_dns_names(e) else {
                rec.unparsed += 1;
                // `!` cannot occur in a name: marks an entry whose certificate did not parse.
                let _ = writeln!(lines, "{}\t{}\t!unparsed\t", e.index, e.timestamp);
                continue;
            };
            // Exactly the names the shipped scan assesses (wildcard prefix already removed),
            // plus which of them the certificate listed as `*.name`.
            let mut names = BTreeSet::new();
            let mut wild = BTreeSet::new();
            for (r, wildcard) in &raw {
                if let Ok(n) = normalize_domain(r) {
                    if *wildcard {
                        wild.insert(n.clone());
                    }
                    names.insert(n);
                }
            }
            rec.names += names.len() as u64;
            rec.wildcard_names += wild.len() as u64;
            let _ = writeln!(
                lines,
                "{}\t{}\t{}\t{}",
                e.index,
                e.timestamp,
                names
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(" "),
                wild.iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            for name in &names {
                let a = self
                    .engine
                    .assess(name)
                    .map_err(|err| anyhow::anyhow!("assess {name}: {err}"))?;
                if !a.findings.iter().any(|f| is_brand_signal(f.code)) {
                    continue;
                }
                let mut codes: Vec<FindingCode> = a.findings.iter().map(|f| f.code).collect();
                codes.sort();
                codes.dedup();
                rec.matches += 1;
                self.out.matches.write(&MatchRecord {
                    log: self.info.log_id.clone(),
                    tile,
                    index: e.index,
                    precert: e.kind == EntryKind::Precert,
                    ts_ms: e.timestamp,
                    seen_ms,
                    name: name.clone(),
                    wildcard: wild.contains(name),
                    risk_score_bp: a.risk_score_bp,
                    verdict: a.verdict,
                    codes,
                    brands: brand_names(&a),
                })?;
            }
        }
        if let Some(s) = self.seg.as_mut() {
            s.enc.write_all(lines.as_bytes())?;
        }
        Ok(())
    }

    /// Closes the open name segment. At a segment boundary the resume point moves past it;
    /// otherwise (shutdown) the file is left complete but is rewritten on resume.
    fn close_segment(&mut self, boundary: bool) -> Result<()> {
        if let Some(s) = self.seg.take() {
            let first = s.first;
            s.close()?;
            if boundary && let Some(st) = self.state.as_mut() {
                debug_assert!(first >= st.committed);
                st.committed = self.next;
                // The segment's matches and events must be on disk before the resume point
                // moves past it, or a power loss would lose them for good.
                self.out.matches.sync()?;
                self.out.events.sync()?;
                self.persist()?;
            }
        }
        Ok(())
    }

    /// Polls until `stop` is set or the end tile is reached, then closes the open segment.
    pub fn run(&mut self, stop: &AtomicBool, poll: Duration) -> Result<()> {
        while !stop.load(Ordering::Relaxed) && !self.finished() {
            let t = Instant::now();
            let o = self.poll_once(stop)?;
            if (o.caught_up || o.tiles == 0) && !self.finished() {
                while t.elapsed() < poll && !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(200).min(poll));
                }
            }
        }
        self.close_segment(false)
    }
}

#[derive(Serialize)]
struct RunRecord<'a> {
    started_ms: u64,
    cybermesh_version: &'a str,
    engine_version: &'a str,
    evidence_pins: std::collections::BTreeMap<String, String>,
    logs: &'a [String],
    poll_secs: u64,
    max_tiles_per_poll: u64,
    start_tile: Option<u64>,
    end_tile: Option<u64>,
    duration_secs: Option<u64>,
    segment_tiles: u64,
}

#[derive(Serialize)]
struct ProcessRecord {
    t_ms: u64,
    cpu_ms: u64,
    rss_bytes: u64,
}

/// Sets the stop flag if the owning thread panics, so the other logs stop too.
struct StopOnPanic<'a>(&'a AtomicBool);

impl Drop for StopOnPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.store(true, Ordering::Relaxed);
        }
    }
}

pub fn run(a: &WatchArgs) -> Result<()> {
    if (a.start_tile.is_some() || a.end_tile.is_some()) && a.logs.len() != 1 {
        bail!("--start-tile and --end-tile need exactly one --log");
    }
    if let (Some(s), Some(e)) = (a.start_tile, a.end_tile)
        && e <= s
    {
        bail!("--end-tile must be greater than --start-tile");
    }
    let ev = EvidenceBundle::load(&a.evidence)?;
    let infos: Vec<CtLogInfo> = a
        .logs
        .iter()
        .map(|l| crate::ct_cmd::log_info(&ev, l))
        .collect::<Result<_>>()?;
    let pins = ev
        .pins
        .iter()
        .map(|(k, v)| (k.clone(), v.to_string()))
        .collect();
    let engine = Engine::new(ev);
    let out = Outputs::open(&a.out)?;
    if a.out.join("STOP").exists() {
        // Honoured, not cleared: a stop requested while starting must not be lost.
        eprintln!("{}: STOP file present; exiting", a.out.display());
        return Ok(());
    }
    Jsonl::open(&a.out.join("runs.jsonl"))?.write(&RunRecord {
        started_ms: now_ms(),
        cybermesh_version: env!("CARGO_PKG_VERSION"),
        engine_version: cybermesh_analysis::ENGINE_VERSION,
        evidence_pins: pins,
        logs: &a.logs,
        poll_secs: a.poll_secs,
        max_tiles_per_poll: a.max_tiles_per_poll,
        start_tile: a.start_tile,
        end_tile: a.end_tile,
        duration_secs: a.duration_secs,
        segment_tiles: SEGMENT_TILES,
    })?;
    let stop = Arc::new(AtomicBool::new(false));
    if let Ok(h) = tokio::runtime::Handle::try_current() {
        let s = stop.clone();
        h.spawn(async move {
            #[cfg(unix)]
            {
                let Ok(mut term) =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                else {
                    return;
                };
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            #[cfg(not(unix))]
            let _ = tokio::signal::ctrl_c().await;
            s.store(true, Ordering::Relaxed);
        });
    }
    let sources: Vec<cybermesh_ct::http::HttpTileSource> = infos
        .iter()
        .map(|i| cybermesh_ct::http::HttpTileSource::new(i, Duration::from_secs(30)))
        .collect::<Result<_, _>>()?;
    let poll = Duration::from_secs(a.poll_secs.max(1));
    let process = Jsonl::open(&a.out.join("process.jsonl"))?;
    let t0 = Instant::now();
    let result = std::thread::scope(|scope| -> Result<()> {
        let mut handles = Vec::new();
        for (info, src) in infos.iter().zip(&sources) {
            let (engine, out, stop) = (&engine, &out, &stop);
            let (start, end, max) = (a.start_tile, a.end_tile, a.max_tiles_per_poll);
            let info = info.clone();
            handles.push(scope.spawn(move || -> Result<()> {
                let _guard = StopOnPanic(stop);
                let id = info.log_id.clone();
                let r = Watcher::new(info, src, engine, out, start, max)
                    .and_then(|w| w.with_end_tile(end).run(stop, poll));
                if r.is_err() {
                    // A local failure stops every log so the run ends in a consistent state.
                    stop.store(true, Ordering::Relaxed);
                }
                r.with_context(|| format!("log {id}"))
            }));
        }
        let mut last_sample = Instant::now();
        let mut sample_err = None;
        while handles.iter().any(|h| !h.is_finished()) {
            std::thread::sleep(Duration::from_millis(500));
            if a.out.join("STOP").exists()
                || a.duration_secs
                    .is_some_and(|d| t0.elapsed() >= Duration::from_secs(d))
            {
                stop.store(true, Ordering::Relaxed);
            }
            if sample_err.is_none() && last_sample.elapsed() >= Duration::from_secs(60) {
                last_sample = Instant::now();
                if let Err(e) = process.write(&process_record()) {
                    // Stop the log threads first: returning now would wait on them forever.
                    stop.store(true, Ordering::Relaxed);
                    sample_err = Some(e);
                }
            }
        }
        let mut first_err = sample_err;
        for h in handles {
            match h.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    first_err.get_or_insert(e);
                }
                Err(_) => {
                    first_err.get_or_insert(anyhow::anyhow!("a log thread panicked"));
                }
            }
        }
        first_err.map_or(Ok(()), Err)
    });
    process.write(&process_record())?;
    result
}

fn process_record() -> ProcessRecord {
    ProcessRecord {
        t_ms: now_ms(),
        cpu_ms: cybermesh_node::governor::process_cpu_ms(),
        rss_bytes: cybermesh_node::governor::rss_bytes(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::io::Read as _;
    use std::sync::RwLock;

    use cybermesh_ct::mock::{MockEntry, MockLog, demo_entries};

    use super::*;

    /// A mock log that tests can grow or replace between polls.
    struct Shared(Arc<RwLock<MockLog>>);

    impl TileSource for Shared {
        fn data_tile(&self, n: u64) -> Result<Vec<u8>, CtError> {
            self.0.read().unwrap().data_tile(n)
        }
        fn hash_tile(&self, level: u8, n: u64, width: Option<u8>) -> Result<Vec<u8>, CtError> {
            self.0.read().unwrap().hash_tile(level, n, width)
        }
        fn checkpoint(&self) -> Result<String, CtError> {
            self.0.read().unwrap().checkpoint()
        }
    }

    fn engine() -> Engine {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../datasets/demo/evidence");
        Engine::new(EvidenceBundle::load(&dir).unwrap())
    }

    fn entries(tiles: usize, extra: &[(usize, &str)]) -> Vec<MockEntry> {
        let mut e = demo_entries(tiles);
        for (i, name) in extra {
            e[*i] = MockEntry {
                names: vec![(*name).to_owned()],
                precert: false,
            };
        }
        e
    }

    fn names_in(dir: &Path) -> Vec<(u64, String, String)> {
        let mut out = Vec::new();
        let mut files: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        for f in files {
            let mut s = String::new();
            flate2::read::GzDecoder::new(File::open(&f).unwrap())
                .read_to_string(&mut s)
                .unwrap();
            for line in s.lines() {
                let c: Vec<&str> = line.split('\t').collect();
                assert_eq!(c.len(), 4, "{line}");
                out.push((c[0].parse().unwrap(), c[2].to_owned(), c[3].to_owned()));
            }
        }
        out.sort();
        out.dedup();
        out
    }

    fn matches(dir: &Path) -> BTreeSet<(u64, String, bool)> {
        fs::read_to_string(dir.join("matches.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str::<MatchRecord>(l).unwrap())
            .map(|m| (m.index, m.name, m.wildcard))
            .collect()
    }

    fn events(dir: &Path) -> Vec<EventRecord> {
        fs::read_to_string(dir.join("events.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn a_line_torn_by_a_crash_does_not_swallow_the_next_record() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.jsonl");
        fs::write(&p, b"{\"a\":1}\n{\"a\":").unwrap();
        let j = Jsonl::open(&p).unwrap();
        j.write(&serde_json::json!({"a": 2})).unwrap();
        j.sync().unwrap();
        let text = fs::read_to_string(&p).unwrap();
        let parsed: Vec<serde_json::Value> = text
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        assert_eq!(
            parsed,
            vec![serde_json::json!({"a": 1}), serde_json::json!({"a": 2})]
        );
        assert_eq!(text.lines().count(), 3);
    }

    #[test]
    fn records_every_name_and_the_same_matches_as_the_shipped_scan() {
        let log = MockLog::build(
            "mock.example/watch",
            &entries(2, &[(7, "*.examplebank-secure-login.example.net")]),
        )
        .unwrap();
        let info = log.log_info("mock", "http://127.0.0.1:1/");
        let src = Shared(Arc::new(RwLock::new(log.clone())));
        let dir = tempfile::tempdir().unwrap();
        let out = Outputs::open(dir.path()).unwrap();
        let eng = engine();
        let stop = AtomicBool::new(false);
        let mut w = Watcher::new(info, &src, &eng, &out, Some(0), 256).unwrap();
        let o = w.poll_once(&stop).unwrap();
        assert_eq!(o.tiles, 2);
        assert!(o.caught_up);
        w.close_segment(false).unwrap();

        // Every entry's names are recorded with the log's timestamp.
        let names = names_in(&dir.path().join("names/mock"));
        assert_eq!(names.len(), 512);
        assert_eq!(names[7].1, "examplebank-secure-login.example.net");
        assert_eq!(names[7].2, "examplebank-secure-login.example.net");

        // The matches equal the shipped (network) scan's, including the wildcard one.
        let mut shipped = BTreeSet::new();
        for n in 0..2 {
            for m in cybermesh_ct::scan_tile(&log.data_tile(n).unwrap(), n, &eng)
                .unwrap()
                .matches
            {
                shipped.insert((m.index, m.name));
            }
        }
        let got = matches(dir.path());
        assert!(!shipped.is_empty());
        assert_eq!(
            got.iter()
                .map(|m| (m.0, m.1.clone()))
                .collect::<BTreeSet<_>>(),
            shipped
        );
        assert!(got.contains(&(7, "examplebank-secure-login.example.net".into(), true)));
        assert_eq!(got.iter().filter(|m| m.2).count(), 1);
    }

    #[test]
    fn follows_growth_and_resumes_without_losing_a_tile() {
        let log = Arc::new(RwLock::new(
            MockLog::build("mock.example/grow", &entries(2, &[])).unwrap(),
        ));
        let info = log.read().unwrap().log_info("mock", "http://127.0.0.1:1/");
        let src = Shared(log.clone());
        let dir = tempfile::tempdir().unwrap();
        let eng = engine();
        let stop = AtomicBool::new(false);
        {
            let out = Outputs::open(dir.path()).unwrap();
            let mut w = Watcher::new(info.clone(), &src, &eng, &out, Some(0), 256).unwrap();
            assert_eq!(w.poll_once(&stop).unwrap().tiles, 2);
            // Simulated crash: the open segment is dropped without being finished.
            drop(w);
        }
        log.write().unwrap().extend(&demo_entries(3)).unwrap();
        {
            let out = Outputs::open(dir.path()).unwrap();
            let mut w = Watcher::new(info, &src, &eng, &out, None, 2).unwrap();
            // Resumes at the committed point (tile 0), two tiles per poll, consistency-checked.
            assert_eq!(w.next_tile(), 0);
            while !w.poll_once(&stop).unwrap().caught_up {}
            assert_eq!(w.next_tile(), 5);
            w.close_segment(false).unwrap();
        }
        let names = names_in(&dir.path().join("names/mock"));
        assert_eq!(names.len(), 5 * 256);
        assert_eq!(
            names.iter().map(|n| n.0).collect::<Vec<_>>(),
            (0..5 * 256).collect::<Vec<_>>()
        );
        assert!(events(dir.path()).is_empty(), "{:?}", events(dir.path()));
    }

    #[test]
    fn a_fixed_range_stops_at_the_end_tile() {
        let log = MockLog::build("mock.example/range", &entries(4, &[])).unwrap();
        let info = log.log_info("mock", "http://127.0.0.1:1/");
        let src = Shared(Arc::new(RwLock::new(log)));
        let dir = tempfile::tempdir().unwrap();
        let out = Outputs::open(dir.path()).unwrap();
        let eng = engine();
        let stop = AtomicBool::new(false);
        let mut w = Watcher::new(info, &src, &eng, &out, Some(1), 256)
            .unwrap()
            .with_end_tile(Some(3));
        w.run(&stop, Duration::from_secs(60)).unwrap();
        assert_eq!(w.next_tile(), 3);
        let names = names_in(&dir.path().join("names/mock"));
        assert_eq!(names.first().unwrap().0, 256);
        assert_eq!(names.last().unwrap().0, 3 * 256 - 1);
    }

    #[test]
    fn a_rewritten_history_or_a_bad_tile_is_recorded_and_never_scanned() {
        let original = MockLog::build("mock.example/fork", &entries(1, &[])).unwrap();
        let log = Arc::new(RwLock::new(original.clone()));
        let info = log.read().unwrap().log_info("mock", "http://127.0.0.1:1/");
        let src = Shared(log.clone());
        let dir = tempfile::tempdir().unwrap();
        let out = Outputs::open(dir.path()).unwrap();
        let eng = engine();
        let stop = AtomicBool::new(false);
        let mut w = Watcher::new(info, &src, &eng, &out, Some(0), 256).unwrap();
        assert_eq!(w.poll_once(&stop).unwrap().tiles, 1);

        // A different tree under the same key (mock certificates differ per build), larger
        // than the accepted head.
        *log.write().unwrap() = MockLog::build(
            "mock.example/fork",
            &entries(2, &[(3, "rewritten.example.com")]),
        )
        .unwrap();
        assert_eq!(w.poll_once(&stop).unwrap().tiles, 0);
        assert_eq!(w.next_tile(), 1);
        assert_eq!(events(dir.path())[0].kind, "inconsistent_checkpoint");

        // A genuine extension whose next data tile was tampered with.
        let mut grown = original;
        grown.extend(&demo_entries(1)).unwrap();
        let tampered = grown.data_tile(0).unwrap();
        grown.replace_file(&cybermesh_ct::tile::data_tile_path(1), tampered);
        *log.write().unwrap() = grown;
        assert_eq!(w.poll_once(&stop).unwrap().tiles, 0);
        assert_eq!(w.next_tile(), 1);
        let ev = events(dir.path());
        assert!(
            ev.iter()
                .any(|e| e.kind == "tile_root_mismatch" || e.kind == "tile_unparsed"),
            "{ev:?}"
        );
    }
}
