//! `cybermesh evidence suggest-owned-domains`: finds domains a brand owner runs itself among
//! the names a CT run flagged, so they can be added to the brand's `legitimate` list.
//!
//! On real CT data most brand signals are the brand owners' own infrastructure (for example
//! `amazonaws.com.cn` or `microsoft-int.com`). A domain is suggested for a brand only if
//! certificates in the run also name a domain already on that brand's list, or one suggested
//! this way. A CA validates every name on a certificate, so one that names both domains was
//! requested by someone who controls both. This is the rule of revision 1 of the CT
//! evaluation (`docs/ct-evaluation.md` §5.1).
//!
//! Certificates are counted once each: a certificate logged as a precertificate and as a
//! certificate, or in several logs, is one certificate. They are told apart by their set of
//! names, so two certificates for exactly the same names also count once.
//!
//! The command only reports. With `--write-brands` it also writes an updated brand list for a
//! maintainer to review; it refuses to write into the evidence or run directory.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context as _, Result, bail};
use clap::Args;
use cybermesh_analysis::EvidenceBundle;
use flate2::read::GzDecoder;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::ct_evaluate::read_lines;
use crate::ct_watch::MatchRecord;
use crate::util::write_json;

#[derive(Args, Debug, Clone)]
pub struct SuggestArgs {
    /// Run directory of `cybermesh ct watch` (matches.jsonl and names/).
    #[arg(long)]
    pub run: PathBuf,
    /// Evidence bundle whose brand list is extended.
    #[arg(long)]
    pub evidence: PathBuf,
    /// Only certificates logged at or after this time (ms since the epoch).
    #[arg(long)]
    pub from_ms: Option<u64>,
    /// Only certificates logged before this time (ms since the epoch).
    #[arg(long)]
    pub to_ms: Option<u64>,
    /// Consider a registrable domain for a brand only if at least this many distinct names
    /// under it were flagged for that brand.
    #[arg(long, default_value_t = 10)]
    pub min_flagged: usize,
    /// Never suggest a domain whose certificates also name more than this many distinct
    /// domains not owned by the brand: that is a multi-tenant service where anyone can get
    /// names (as under `sslip.io`), not one owner's infrastructure. Domains on the evidence's
    /// hosting-platform list are never suggested either.
    #[arg(long, default_value_t = 100)]
    pub max_co_domains: usize,
    /// Require at least this many certificates that also name one of the brand's domains.
    /// One is the rule of revision 1: a CA validated control of both domains. Reissues with
    /// the same names count once, so a higher value asks for certificates with different
    /// names, which many genuine links do not have.
    #[arg(long, default_value_t = 1)]
    pub min_shared: u64,
    /// Report file (JSON).
    #[arg(long)]
    pub out: PathBuf,
    /// Also write the brand list with the suggested domains added, for review.
    #[arg(long)]
    pub write_brands: Option<PathBuf>,
    /// Threads for reading the name segments.
    #[arg(long, default_value_t = 4)]
    pub threads: usize,
}

pub const HOSTING: &str = "hosting platform: names under it belong to customers";
pub const NO_DATA: &str = "no certificate data: no certificate in the window names it";
pub const NO_SHARED: &str = "no certificate shared with the brand's domains";
pub const MULTI_TENANT: &str = "multi-tenant: shares certificates with too many unrelated domains";
pub const TOO_LITTLE: &str =
    "too little evidence: too few certificates shared with the brand's domains";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Shared {
    pub domain: String,
    pub certificates: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Suggestion {
    pub domain: String,
    /// Distinct flagged names under it, for this brand.
    pub flagged_names: usize,
    /// Certificates naming it, and the distinct other domains they name.
    pub certificates: u64,
    pub co_domains: usize,
    /// Certificates that also name at least one of the brand's domains (including domains
    /// suggested before it).
    pub shared_certificates: u64,
    /// The brand's domains on those certificates, with the certificates naming each.
    pub evidence: Vec<Shared>,
    /// Admitted only through another suggested domain: the brand's original domains alone
    /// share fewer than `min_shared` certificates with it.
    pub transitive: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Rejected {
    pub domain: String,
    pub flagged_names: usize,
    pub certificates: u64,
    pub co_domains: usize,
    pub shared_certificates: u64,
    pub reason: &'static str,
    /// The domains its certificates name most often.
    pub shares_with: Vec<Shared>,
}

/// What was read, and what could not be.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct InputStats {
    pub match_lines: u64,
    pub match_lines_unreadable: u64,
    pub segments: u64,
    /// Segments whose gzip stream ended early or failed; lines after the damage are missing.
    pub segments_truncated: u64,
    /// Segment lines without an index, a timestamp and names.
    pub lines_malformed: u64,
    /// Entries in the window that `ct watch` could not parse (no names).
    pub lines_unparsed: u64,
    /// Lines in the window naming a candidate, and the distinct certificates among them.
    pub lines_with_candidates: u64,
    pub certificates_with_candidates: u64,
}

impl InputStats {
    fn add(&mut self, o: &Self) {
        self.match_lines += o.match_lines;
        self.match_lines_unreadable += o.match_lines_unreadable;
        self.segments += o.segments;
        self.segments_truncated += o.segments_truncated;
        self.lines_malformed += o.lines_malformed;
        self.lines_unparsed += o.lines_unparsed;
        self.lines_with_candidates += o.lines_with_candidates;
        self.certificates_with_candidates += o.certificates_with_candidates;
    }

    /// Input that was skipped, which makes the report incomplete.
    pub fn damaged(&self) -> bool {
        self.match_lines_unreadable > 0 || self.segments_truncated > 0 || self.lines_malformed > 0
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub window_from_ms: Option<u64>,
    pub window_to_ms: Option<u64>,
    pub min_flagged: usize,
    pub max_co_domains: usize,
    pub min_shared: u64,
    pub candidates: usize,
    pub input: InputStats,
    pub suggested: BTreeMap<String, Vec<Suggestion>>,
    pub rejected: BTreeMap<String, Vec<Rejected>>,
}

fn registrable(name: &str) -> Option<&str> {
    psl::domain_str(name)
}

type Window = (u64, u64);

/// Distinct flagged names per (registrable domain, brand), for domains not already owned by
/// that brand.
fn candidates(
    run: &Path,
    window: Window,
    owned: &HashMap<String, BTreeSet<String>>,
    stats: &mut InputStats,
) -> Result<HashMap<(String, String), HashSet<String>>> {
    let mut out: HashMap<(String, String), HashSet<String>> = HashMap::new();
    let path = run.join("matches.jsonl");
    if !path.exists() {
        bail!("{}: no matches.jsonl", run.display());
    }
    let truncated = read_lines(
        BufReader::with_capacity(1 << 20, File::open(&path)?),
        |line| {
            if line.is_empty() {
                return;
            }
            stats.match_lines += 1;
            let Ok(m) = serde_json::from_str::<MatchRecord>(line) else {
                stats.match_lines_unreadable += 1;
                return;
            };
            if m.ts_ms < window.0 || m.ts_ms >= window.1 {
                return;
            }
            let Some(reg) = registrable(&m.name) else {
                return;
            };
            for b in &m.brands {
                if owned.get(b).is_some_and(|o| o.contains(reg)) {
                    continue;
                }
                out.entry((reg.to_owned(), b.clone()))
                    .or_default()
                    .insert(m.name.clone());
            }
        },
    );
    if truncated {
        bail!("{}: read error", path.display());
    }
    if stats.match_lines > 0 && stats.match_lines == stats.match_lines_unreadable {
        bail!(
            "{}: no line could be read (written by a different version of `ct watch`?)",
            path.display()
        );
    }
    Ok(out)
}

/// The certificates naming one candidate domain.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Certs {
    /// For each set of other registrable domains (sorted), the number of distinct
    /// certificates that name the candidate together with exactly that set.
    pub sets: HashMap<Vec<String>, u64>,
}

impl Certs {
    pub fn total(&self) -> u64 {
        self.sets.values().sum()
    }

    /// Certificates naming each other domain.
    pub fn per_domain(&self) -> HashMap<&str, u64> {
        let mut m: HashMap<&str, u64> = HashMap::new();
        for (set, k) in &self.sets {
            for d in set {
                *m.entry(d.as_str()).or_default() += k;
            }
        }
        m
    }

    /// Certificates that also name at least one domain of `of`.
    pub fn sharing(&self, of: &BTreeSet<String>) -> u64 {
        self.sets
            .iter()
            .filter(|(set, _)| set.iter().any(|d| of.contains(d)))
            .map(|(_, k)| *k)
            .sum()
    }
}

/// Per candidate domain, the certificates naming it.
pub type Cooc = HashMap<String, Certs>;

/// Identifies a certificate by its set of names.
fn certificate_key(names: &str) -> u128 {
    let mut ns: Vec<&str> = names.split(' ').filter(|n| !n.is_empty()).collect();
    ns.sort_unstable();
    ns.dedup();
    let d = Sha256::digest(ns.join(" ").as_bytes());
    let mut k = [0u8; 16];
    k.copy_from_slice(&d[..16]);
    u128::from_be_bytes(k)
}

fn segment_files(run: &Path) -> Result<Vec<PathBuf>> {
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
    if files.is_empty() {
        bail!(
            "{}: no name segments (names/<log>/*.tsv.gz); run `ct watch` first",
            root.display()
        );
    }
    files.sort();
    Ok(files)
}

/// For every candidate domain, the distinct certificates in the window that name it, and
/// the other registrable domains on each.
fn co_occurrence(
    run: &Path,
    window: Window,
    cands: &HashSet<String>,
    threads: usize,
) -> Result<(Cooc, InputStats)> {
    let queue = Mutex::new(segment_files(run)?);
    let seen: Mutex<HashSet<u128>> = Mutex::new(HashSet::new());
    type Acc = (Cooc, InputStats);
    let parts: Vec<Result<Acc>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads.max(1))
            .map(|_| {
                s.spawn(|| -> Result<Acc> {
                    let (mut cooc, mut st): Acc = (HashMap::new(), InputStats::default());
                    let mut poisoned = false;
                    loop {
                        let next = queue
                            .lock()
                            .map_err(|_| anyhow::anyhow!("queue poisoned"))?
                            .pop();
                        let Some(f) = next else { break };
                        st.segments += 1;
                        let r = BufReader::with_capacity(1 << 20, GzDecoder::new(File::open(&f)?));
                        let truncated = read_lines(r, |line| {
                            if line.is_empty() {
                                return;
                            }
                            let mut c = line.split('\t');
                            let (Some(_), Some(ts), Some(names)) = (c.next(), c.next(), c.next())
                            else {
                                st.lines_malformed += 1;
                                return;
                            };
                            let Ok(ts) = ts.parse::<u64>() else {
                                st.lines_malformed += 1;
                                return;
                            };
                            if ts < window.0 || ts >= window.1 {
                                return;
                            }
                            if names == "!unparsed" {
                                st.lines_unparsed += 1;
                                return;
                            }
                            // Fast path: does any name end in a candidate domain?
                            let hit = names.split(' ').any(|n| {
                                std::iter::once(n)
                                    .chain(n.match_indices('.').map(|(i, _)| &n[i + 1..]))
                                    .any(|s| cands.contains(s))
                            });
                            if !hit {
                                return;
                            }
                            let regs: BTreeSet<&str> =
                                names.split(' ').filter_map(registrable).collect();
                            let here: Vec<&str> = regs
                                .iter()
                                .copied()
                                .filter(|r| cands.contains(*r))
                                .collect();
                            if here.is_empty() {
                                return;
                            }
                            st.lines_with_candidates += 1;
                            let Ok(mut seen) = seen.lock() else {
                                poisoned = true;
                                return;
                            };
                            if !seen.insert(certificate_key(names)) {
                                return;
                            }
                            drop(seen);
                            st.certificates_with_candidates += 1;
                            for c in here {
                                let others: Vec<String> = regs
                                    .iter()
                                    .filter(|r| **r != c)
                                    .map(|r| (*r).to_owned())
                                    .collect();
                                *cooc
                                    .entry(c.to_owned())
                                    .or_default()
                                    .sets
                                    .entry(others)
                                    .or_default() += 1;
                            }
                        });
                        if truncated {
                            st.segments_truncated += 1;
                        }
                        if poisoned {
                            bail!("certificate set poisoned");
                        }
                    }
                    Ok((cooc, st))
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
    let (mut all, mut stats): Acc = (HashMap::new(), InputStats::default());
    for p in parts {
        let (m, st) = p?;
        stats.add(&st);
        for (c, certs) in m {
            let e = all.entry(c).or_default();
            for (set, k) in certs.sets {
                *e.sets.entry(set).or_default() += k;
            }
        }
    }
    Ok((all, stats))
}

/// What a suggestion must satisfy beyond sharing a certificate with the brand.
#[derive(Debug, Clone)]
pub struct Limits<'a> {
    /// At most this many distinct domains not owned by the brand on its certificates (else
    /// multi-tenant).
    pub max_co_domains: usize,
    /// At least this many certificates that also name one of the brand's domains.
    pub min_shared: u64,
    /// User-content hosting platforms (evidence): names under them belong to customers.
    pub hosting: &'a HashSet<String>,
}

fn unrelated(per: &HashMap<&str, u64>, have: &BTreeSet<String>) -> usize {
    per.keys().filter(|d| !have.contains(**d)).count()
}

fn ranked(per: &HashMap<&str, u64>, keep: impl Fn(&str) -> bool) -> Vec<Shared> {
    let mut v: Vec<Shared> = per
        .iter()
        .filter(|(d, _)| keep(d))
        .map(|(d, k)| Shared {
            domain: (*d).to_owned(),
            certificates: *k,
        })
        .collect();
    v.sort_by(|a, b| {
        b.certificates
            .cmp(&a.certificates)
            .then(a.domain.cmp(&b.domain))
    });
    v
}

/// The shared-certificate closure, per brand. The set of suggested domains does not depend
/// on the order candidates are visited in: a brand's set of domains only grows, and growing
/// it never withdraws a domain's admission.
pub fn suggest(
    owned: &HashMap<String, BTreeSet<String>>,
    cands: &HashMap<(String, String), usize>,
    cooc: &Cooc,
    limits: &Limits<'_>,
) -> (
    BTreeMap<String, Vec<Suggestion>>,
    BTreeMap<String, Vec<Rejected>>,
) {
    let per: HashMap<&str, HashMap<&str, u64>> = cooc
        .iter()
        .map(|(d, c)| (d.as_str(), c.per_domain()))
        .collect();
    let min_shared = limits.min_shared.max(1);
    let mut suggested: BTreeMap<String, Vec<Suggestion>> = BTreeMap::new();
    let mut known: HashMap<&str, BTreeSet<String>> =
        owned.iter().map(|(b, o)| (b.as_str(), o.clone())).collect();
    let mut order: Vec<&(String, String)> = cands.keys().collect();
    order.sort();
    loop {
        let mut added = false;
        for (domain, brand) in order.iter().copied() {
            let have = known.entry(brand.as_str()).or_default();
            if have.contains(domain) {
                continue;
            }
            let (Some(certs), Some(others)) = (cooc.get(domain), per.get(domain.as_str())) else {
                continue;
            };
            // Customer-named platforms and multi-tenant services are not one owner's
            // infrastructure, however many brand certificates name them.
            if limits.hosting.contains(domain) || unrelated(others, have) > limits.max_co_domains {
                continue;
            }
            let shared = certs.sharing(have);
            if shared < min_shared {
                continue;
            }
            let original = owned.get(brand).cloned().unwrap_or_default();
            let transitive = certs.sharing(&original) < min_shared;
            let evidence = ranked(others, |d| have.contains(d));
            have.insert(domain.clone());
            suggested
                .entry(brand.clone())
                .or_default()
                .push(Suggestion {
                    domain: domain.clone(),
                    flagged_names: cands[&(domain.clone(), brand.clone())],
                    certificates: certs.total(),
                    co_domains: others.len(),
                    shared_certificates: shared,
                    evidence,
                    transitive,
                });
            added = true;
        }
        if !added {
            break;
        }
    }
    let mut rejected: BTreeMap<String, Vec<Rejected>> = BTreeMap::new();
    let none = BTreeSet::new();
    for ((domain, brand), n) in cands {
        let have = known.get(brand.as_str()).unwrap_or(&none);
        if have.contains(domain) {
            continue;
        }
        let (certificates, co_domains, shared, unrelated_n, mut shares_with) =
            match (cooc.get(domain), per.get(domain.as_str())) {
                (Some(c), Some(o)) => (
                    c.total(),
                    o.len(),
                    c.sharing(have),
                    unrelated(o, have),
                    ranked(o, |_| true),
                ),
                _ => (0, 0, 0, 0, Vec::new()),
            };
        let reason = if limits.hosting.contains(domain) {
            HOSTING
        } else if certificates == 0 {
            NO_DATA
        } else if shared == 0 {
            NO_SHARED
        } else if unrelated_n > limits.max_co_domains {
            MULTI_TENANT
        } else {
            TOO_LITTLE
        };
        shares_with.truncate(5);
        rejected.entry(brand.clone()).or_default().push(Rejected {
            domain: domain.clone(),
            flagged_names: *n,
            certificates,
            co_domains,
            shared_certificates: shared,
            reason,
            shares_with,
        });
    }
    for v in suggested.values_mut() {
        v.sort_by(|a, b| {
            b.flagged_names
                .cmp(&a.flagged_names)
                .then(a.domain.cmp(&b.domain))
        });
    }
    for v in rejected.values_mut() {
        v.sort_by(|a, b| {
            b.flagged_names
                .cmp(&a.flagged_names)
                .then(a.domain.cmp(&b.domain))
        });
    }
    (suggested, rejected)
}

/// The brand list file of an evidence bundle.
fn brands_file(evidence: &Path) -> Result<PathBuf> {
    let m: serde_json::Value =
        serde_json::from_slice(&fs::read(evidence.join("bundle.json"))?).context("bundle.json")?;
    let file = m["sources"]
        .as_array()
        .and_then(|s| s.iter().find(|s| s["kind"] == "brands"))
        .and_then(|s| s["file"].as_str())
        .context("bundle.json has no brands source")?;
    Ok(evidence.join(file))
}

/// The absolute form of a path that need not exist yet (its directory must).
fn absolute(p: &Path) -> Result<PathBuf> {
    if p.exists() {
        return fs::canonicalize(p).with_context(|| format!("{}", p.display()));
    }
    let name = p
        .file_name()
        .with_context(|| format!("{}: not a file path", p.display()))?;
    let dir = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    Ok(fs::canonicalize(dir)
        .with_context(|| format!("{}", dir.display()))?
        .join(name))
}

/// Outputs must not land in the evidence or run directory, or on each other.
fn check_outputs(a: &SuggestArgs) -> Result<()> {
    let evidence = fs::canonicalize(&a.evidence)
        .with_context(|| format!("evidence {}", a.evidence.display()))?;
    let run = fs::canonicalize(&a.run).with_context(|| format!("run {}", a.run.display()))?;
    let mut outs = vec![("--out", absolute(&a.out)?)];
    if let Some(d) = &a.write_brands {
        outs.push(("--write-brands", absolute(d)?));
    }
    for (flag, p) in &outs {
        if p.starts_with(&evidence) {
            bail!(
                "{flag} {}: inside the evidence directory, which this command never changes",
                p.display()
            );
        }
        if p.starts_with(&run) {
            bail!("{flag} {}: inside the run directory", p.display());
        }
    }
    if let [(_, report), (_, brands)] = outs.as_slice()
        && report == brands
    {
        bail!("--out and --write-brands name the same file");
    }
    Ok(())
}

/// The brand list `src` with the suggested domains added to each brand's `legitimate` list.
fn extended_brands(src: &Path, rep: &Report) -> Result<Vec<serde_json::Value>> {
    let mut brands: Vec<serde_json::Value> =
        serde_json::from_slice(&fs::read(src)?).with_context(|| format!("{}", src.display()))?;
    for b in &mut brands {
        let Some(name) = b["name"].as_str().map(str::to_owned) else {
            continue;
        };
        let Some(add) = rep.suggested.get(&name) else {
            continue;
        };
        let mut legit: BTreeSet<String> = b["legitimate"]
            .as_array()
            .map(|l| {
                l.iter()
                    .filter_map(|d| d.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        legit.extend(add.iter().map(|s| s.domain.clone()));
        b["legitimate"] = serde_json::json!(legit.into_iter().collect::<Vec<_>>());
    }
    Ok(brands)
}

pub fn run(a: &SuggestArgs) -> Result<Report> {
    let window = (a.from_ms.unwrap_or(0), a.to_ms.unwrap_or(u64::MAX));
    if window.0 >= window.1 {
        bail!("the window is empty: --from-ms must be before --to-ms");
    }
    check_outputs(a)?;
    let ev = EvidenceBundle::load(&a.evidence)?;
    let brands_src = a
        .write_brands
        .as_ref()
        .map(|_| brands_file(&a.evidence))
        .transpose()?;
    let owned: HashMap<String, BTreeSet<String>> = ev
        .brands
        .iter()
        .map(|b| (b.name.clone(), b.legitimate.iter().cloned().collect()))
        .collect();
    let mut input = InputStats::default();
    let flagged = candidates(&a.run, window, &owned, &mut input)?;
    let cands: HashMap<(String, String), usize> = flagged
        .into_iter()
        .map(|(k, v)| (k, v.len()))
        .filter(|(_, n)| *n >= a.min_flagged)
        .collect();
    let domains: HashSet<String> = cands.keys().map(|(d, _)| d.clone()).collect();
    let (cooc, seg) = co_occurrence(&a.run, window, &domains, a.threads)?;
    input.add(&seg);
    let limits = Limits {
        max_co_domains: a.max_co_domains,
        min_shared: a.min_shared,
        hosting: &ev.hosting_platforms,
    };
    let (suggested, rejected) = suggest(&owned, &cands, &cooc, &limits);
    let rep = Report {
        window_from_ms: a.from_ms,
        window_to_ms: a.to_ms,
        min_flagged: a.min_flagged,
        max_co_domains: a.max_co_domains,
        min_shared: a.min_shared,
        candidates: cands.len(),
        input,
        suggested,
        rejected,
    };
    // Build every output before writing any, so a failure leaves nothing half-written.
    let brands = brands_src
        .map(|src| extended_brands(&src, &rep))
        .transpose()?;
    write_json(&a.out, &rep)?;
    if let (Some(dest), Some(brands)) = (&a.write_brands, &brands) {
        write_json(dest, brands)?;
    }
    Ok(rep)
}

pub fn print(rep: &Report) {
    let i = &rep.input;
    println!(
        "{} candidate domain(s) with at least {} flagged names; {} certificates name a candidate ({} log entries)",
        rep.candidates, rep.min_flagged, i.certificates_with_candidates, i.lines_with_candidates
    );
    if i.damaged() {
        println!(
            "  WARNING: incomplete input: {} unreadable matches line(s), {} truncated segment(s), {} malformed segment line(s)",
            i.match_lines_unreadable, i.segments_truncated, i.lines_malformed
        );
    }
    for (brand, list) in &rep.suggested {
        for s in list {
            let ev: Vec<String> = s
                .evidence
                .iter()
                .take(3)
                .map(|e| format!("{} ({})", e.domain, e.certificates))
                .collect();
            println!(
                "  suggest {brand}: {} ({} flagged names; {} certificates, {} shared, {} other domains); shares certificates with {}{}",
                s.domain,
                s.flagged_names,
                s.certificates,
                s.shared_certificates,
                s.co_domains,
                ev.join(", "),
                if s.transitive {
                    " [via a suggested domain]"
                } else {
                    ""
                }
            );
        }
    }
    let n: usize = rep.rejected.values().map(Vec::len).sum();
    println!("  {n} candidate(s) rejected");
    let mut top: Vec<(&String, &Rejected)> = rep
        .rejected
        .iter()
        .flat_map(|(b, v)| v.iter().map(move |r| (b, r)))
        .collect();
    top.sort_by_key(|(_, r)| std::cmp::Reverse(r.flagged_names));
    // Rejections that did share certificates with the brand come first: they are the ones a
    // maintainer should know about.
    let shared_but = |r: &Rejected| r.reason != NO_SHARED;
    let multi = top.iter().filter(|(_, r)| shared_but(r));
    let other = top.iter().filter(|(_, r)| !shared_but(r)).take(10);
    for (b, r) in multi.chain(other) {
        println!(
            "    {b}: {} ({} flagged names; {} certificates, {} shared, {} other domains): {}",
            r.domain,
            r.flagged_names,
            r.certificates,
            r.shared_certificates,
            r.co_domains,
            r.reason
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::io::Write as _;

    use cybermesh_protocol::{FindingCode, Verdict};
    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    fn flagged_at(name: &str, brand: &str, ts_ms: u64) -> String {
        serde_json::to_string(&MatchRecord {
            log: "log-a".into(),
            tile: 0,
            index: 0,
            precert: false,
            ts_ms,
            seen_ms: ts_ms,
            name: name.into(),
            wildcard: false,
            risk_score_bp: 5000,
            verdict: Verdict::Suspicious,
            codes: vec![FindingCode::BrandImpersonation],
            brands: vec![brand.into()],
        })
        .unwrap()
            + "\n"
    }

    fn flagged(name: &str, brand: &str) -> String {
        flagged_at(name, brand, 1000)
    }

    /// Twelve flagged names under `domain`: enough for a candidate at `min_flagged = 10`.
    fn twelve(domain: &str, brand: &str) -> String {
        (0..12)
            .map(|i| flagged(&format!("n{i}.{domain}"), brand))
            .collect()
    }

    /// `k` distinct certificates at time 1000, each naming `a` and `b`.
    fn certs(k: usize, a: &str, b: &str) -> String {
        (0..k)
            .map(|j| format!("0\t1000\tc{j}.{a} c{j}.{b}\t\n"))
            .collect()
    }

    fn gz(path: &Path, content: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut e = GzEncoder::new(File::create(path).unwrap(), Compression::default());
        e.write_all(content.as_bytes()).unwrap();
        e.finish().unwrap();
    }

    struct Fixture {
        dir: tempfile::TempDir,
    }

    impl Fixture {
        /// A run with `matches` and one segment per (log, content), and a copy of the demo
        /// evidence (where amazon owns amazon.com, amazon.de, amazon.co.uk and others).
        fn new(matches: &str, segments: &[(&str, &str)]) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let run = dir.path().join("run");
            fs::create_dir_all(&run).unwrap();
            fs::write(run.join("matches.jsonl"), matches).unwrap();
            for (log, content) in segments {
                gz(
                    &run.join(format!("names/{log}/000000000000.tsv.gz")),
                    content,
                );
            }
            let ev = dir.path().join("evidence");
            fs::create_dir_all(&ev).unwrap();
            for f in fs::read_dir(demo()).unwrap() {
                let f = f.unwrap().path();
                fs::copy(&f, ev.join(f.file_name().unwrap())).unwrap();
            }
            Self { dir }
        }

        fn path(&self, p: &str) -> PathBuf {
            self.dir.path().join(p)
        }

        fn args(&self, out: &str) -> SuggestArgs {
            SuggestArgs {
                run: self.path("run"),
                evidence: self.path("evidence"),
                from_ms: None,
                to_ms: Some(5000),
                min_flagged: 10,
                max_co_domains: 20,
                min_shared: 1,
                out: self.path(out),
                write_brands: None,
                threads: 2,
            }
        }
    }

    fn demo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../datasets/demo/evidence")
    }

    fn find<'a>(v: &'a [Suggestion], d: &str) -> &'a Suggestion {
        v.iter().find(|x| x.domain == d).unwrap()
    }

    fn find_rej<'a>(v: &'a [Rejected], d: &str) -> &'a Rejected {
        v.iter().find(|x| x.domain == d).unwrap()
    }

    #[test]
    fn suggests_only_domains_that_share_certificates_with_the_brand() {
        let mut matches = String::new();
        for d in [
            "amazon-infra.example",
            "chain-amazon.example",
            "lonely-amazon.example",
            "tenant-amazon.example",
        ] {
            matches.push_str(&twelve(d, "amazon"));
        }
        // weebly.com is on the demo evidence's hosting-platform list.
        for i in 0..12 {
            matches.push_str(&flagged(&format!("amazon-{i}.weebly.com"), "amazon"));
        }
        // Below the threshold: never a candidate, even though it shares a certificate.
        for i in 0..3 {
            matches.push_str(&flagged(&format!("n{i}.rare-amazon.example"), "amazon"));
        }
        // Already owned by the brand: never a candidate.
        matches.push_str(&flagged("aws-console.amazon.com", "amazon"));
        // amazon-infra shares a certificate with amazon.com (owned); chain-amazon shares one
        // with amazon-infra only; lonely-amazon only with an unrelated domain, and once with
        // amazon.com outside the window.
        let mut seg = String::from(
            "1\t1000\ta.amazon-infra.example amazon.com\t\n\
             2\t1000\tx.chain-amazon.example b.amazon-infra.example\t\n\
             3\t1000\ty.lonely-amazon.example other.example\t\n\
             4\t1000\tz.rare-amazon.example amazon.com\t\n\
             5\t9999999\tw.lonely-amazon.example amazon.com\t\n\
             6\t1000\tt.tenant-amazon.example amazon.com\t\n\
             7\t1000\tamazon-0.weebly.com amazon.com\t\n",
        );
        // tenant-amazon also shares certificates with 25 unrelated domains: a multi-tenant
        // service (like sslip.io), never suggested although one certificate names amazon.com.
        for i in 0..25 {
            seg.push_str(&format!(
                "{}\t1000\tc{i}.tenant-amazon.example customer{i}.example\t\n",
                100 + i
            ));
        }
        let f = Fixture::new(&matches, &[("log-a", &seg)]);
        let mut a = f.args("report.json");
        a.write_brands = Some(f.path("brands.json"));
        let rep = run(&a).unwrap();
        assert_eq!(rep.candidates, 5);
        assert!(!rep.input.damaged(), "{:?}", rep.input);
        let s = &rep.suggested["amazon"];
        assert_eq!(s.len(), 2, "{s:?}");
        let infra = find(s, "amazon-infra.example");
        assert!(!infra.transitive);
        assert_eq!(infra.shared_certificates, 1);
        assert_eq!(
            infra.evidence,
            vec![Shared {
                domain: "amazon.com".into(),
                certificates: 1
            }]
        );
        let chain = find(s, "chain-amazon.example");
        assert!(chain.transitive);
        assert_eq!(chain.evidence[0].domain, "amazon-infra.example");
        let rej = &rep.rejected["amazon"];
        assert_eq!(rej.len(), 3);
        assert_eq!(find_rej(rej, "weebly.com").reason, HOSTING);
        let lonely = find_rej(rej, "lonely-amazon.example");
        assert_eq!(lonely.shares_with[0].domain, "other.example");
        assert_eq!(lonely.reason, NO_SHARED);
        let tenant = find_rej(rej, "tenant-amazon.example");
        assert_eq!(tenant.reason, MULTI_TENANT);
        assert_eq!((tenant.certificates, tenant.co_domains), (26, 26));

        // The written brand list adds exactly the suggestions, sorted, and keeps the rest.
        let written: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(f.path("brands.json")).unwrap()).unwrap();
        let amazon = written.iter().find(|b| b["name"] == "amazon").unwrap();
        let legit: Vec<&str> = amazon["legitimate"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_str().unwrap())
            .collect();
        assert!(legit.contains(&"amazon-infra.example") && legit.contains(&"chain-amazon.example"));
        assert!(!legit.contains(&"lonely-amazon.example"));
        assert!(!legit.contains(&"tenant-amazon.example"));
        assert!(legit.windows(2).all(|w| w[0] < w[1]));
        let source: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(demo().join("brands.json")).unwrap()).unwrap();
        assert_eq!(written.len(), source.len());
        assert!(f.path("report.json").exists());

        // Requiring two shared certificates rejects amazon-infra (it shares one), and with it
        // chain-amazon, which was only linked through it.
        let mut strict = f.args("strict.json");
        strict.min_shared = 2;
        strict.threads = 1;
        let strict = run(&strict).unwrap();
        assert!(
            !strict.suggested.contains_key("amazon"),
            "{:?}",
            strict.suggested
        );
        let rej = &strict.rejected["amazon"];
        assert_eq!(find_rej(rej, "amazon-infra.example").reason, TOO_LITTLE);
        assert_eq!(find_rej(rej, "chain-amazon.example").reason, NO_SHARED);
    }

    #[test]
    fn counts_certificates_not_domains_and_each_certificate_once() {
        let matches = twelve("multi-amazon.example", "amazon");
        // One certificate naming three Amazon domains, logged as a precertificate and a
        // certificate in log-a and again (names in another order) in log-b.
        let cert = "a.multi-amazon.example amazon.com amazon.de amazon.co.uk";
        let reordered = "amazon.co.uk a.multi-amazon.example amazon.de amazon.com";
        let f = Fixture::new(
            &matches,
            &[
                ("log-a", &format!("1\t1000\t{cert}\t\n2\t1000\t{cert}\t\n")),
                ("log-b", &format!("9\t1000\t{reordered}\t\n")),
            ],
        );
        let mut a = f.args("report.json");
        a.min_shared = 2;
        let rep = run(&a).unwrap();
        assert_eq!(rep.input.lines_with_candidates, 3);
        assert_eq!(rep.input.certificates_with_candidates, 1);
        let r = find_rej(&rep.rejected["amazon"], "multi-amazon.example");
        assert_eq!(r.reason, TOO_LITTLE);
        assert_eq!((r.certificates, r.shared_certificates), (1, 1));

        a.min_shared = 1;
        let rep = run(&a).unwrap();
        let s = find(&rep.suggested["amazon"], "multi-amazon.example");
        assert_eq!((s.certificates, s.shared_certificates), (1, 1));
        assert_eq!(s.evidence.len(), 3);
        assert!(s.evidence.iter().all(|e| e.certificates == 1));
    }

    #[test]
    fn the_closure_does_not_depend_on_the_order_of_candidates() {
        let mut matches = String::new();
        for d in [
            "a-end.example",
            "m-mid.example",
            "z-infra.example",
            "x-mixed.example",
            "y-short.example",
        ] {
            matches.push_str(&twelve(d, "amazon"));
        }
        // A chain whose links sort before what admits them: z-infra shares 3 certificates
        // with amazon.com, m-mid 3 with z-infra, a-end 3 with m-mid. x-mixed shares 1 with
        // amazon.com and 2 with z-infra; y-short only 2 with amazon.com.
        let mut seg = certs(3, "z-infra.example", "amazon.com");
        seg += &certs(3, "m-mid.example", "z-infra.example");
        seg += &certs(3, "a-end.example", "m-mid.example");
        seg += "0\t1000\tq.x-mixed.example amazon.com\t\n";
        seg += &certs(2, "x-mixed.example", "z-infra.example");
        seg += &certs(2, "y-short.example", "amazon.com");
        let f = Fixture::new(&matches, &[("log-a", &seg)]);
        let mut a = f.args("report.json");
        a.min_shared = 3;
        let rep = run(&a).unwrap();
        let s = &rep.suggested["amazon"];
        assert_eq!(s.len(), 4, "{s:?}");
        assert!(!find(s, "z-infra.example").transitive);
        assert!(find(s, "m-mid.example").transitive);
        assert!(find(s, "a-end.example").transitive);
        // Admitted with 3 shared certificates, but only 1 with the brand's own domains.
        let mixed = find(s, "x-mixed.example");
        assert_eq!(mixed.shared_certificates, 3);
        assert!(mixed.transitive);
        assert_eq!(
            find_rej(&rep.rejected["amazon"], "y-short.example").reason,
            TOO_LITTLE
        );
    }

    #[test]
    fn the_window_is_half_open() {
        let mut matches = String::new();
        for i in 0..12 {
            matches.push_str(&flagged_at(
                &format!("n{i}.edge-amazon.example"),
                "amazon",
                1000,
            ));
            matches.push_str(&flagged_at(
                &format!("n{i}.late-amazon.example"),
                "amazon",
                2000,
            ));
        }
        let seg = "1\t1000\ta.edge-amazon.example amazon.com\t\n\
                   2\t2000\tb.edge-amazon.example amazon.de\t\n\
                   3\t999\tc.edge-amazon.example amazon.fr\t\n";
        let f = Fixture::new(&matches, &[("log-a", seg)]);
        let mut a = f.args("report.json");
        a.from_ms = Some(1000);
        a.to_ms = Some(2000);
        let rep = run(&a).unwrap();
        assert_eq!(
            rep.candidates, 1,
            "late-amazon is flagged only at the end time"
        );
        let s = find(&rep.suggested["amazon"], "edge-amazon.example");
        assert_eq!(s.certificates, 1);
        assert_eq!(s.evidence[0].domain, "amazon.com");

        a.from_ms = Some(2000);
        assert!(run(&a).unwrap_err().to_string().contains("window is empty"));
    }

    #[test]
    fn unreadable_input_is_counted_or_refused() {
        let mut matches = twelve("amazon-infra.example", "amazon");
        matches.push_str("not json\n");
        let seg = "1\t1000\ta.amazon-infra.example amazon.com\t\n\
                   garbage\n\
                   2\tlater\tb.amazon-infra.example\t\n\
                   3\t1000\t!unparsed\t\n";
        let f = Fixture::new(&matches, &[("log-a", seg)]);
        // A segment cut off in the middle of its gzip stream.
        let mut whole = Vec::new();
        {
            let mut e = GzEncoder::new(&mut whole, Compression::default());
            for i in 0..2000 {
                writeln!(e, "{i}\t1000\tn{i}.unrelated.example\t").unwrap();
            }
            e.finish().unwrap();
        }
        let cut = f.path("run/names/log-b/000000000000.tsv.gz");
        fs::create_dir_all(cut.parent().unwrap()).unwrap();
        fs::write(&cut, &whole[..whole.len() / 2]).unwrap();
        let rep = run(&f.args("report.json")).unwrap();
        let i = &rep.input;
        assert_eq!((i.match_lines, i.match_lines_unreadable), (13, 1));
        assert_eq!((i.segments, i.segments_truncated), (2, 1));
        assert_eq!((i.lines_malformed, i.lines_unparsed), (2, 1));
        assert!(i.damaged());
        assert!(rep.suggested["amazon"][0].domain == "amazon-infra.example");

        // Without name segments, every candidate would look unshared: refuse instead.
        fs::remove_dir_all(f.path("run/names")).unwrap();
        let e = run(&f.args("report2.json")).unwrap_err().to_string();
        assert!(e.contains("no name segments"), "{e}");
        // A matches.jsonl that this version cannot read at all is refused too.
        fs::write(f.path("run/matches.jsonl"), "{\"v\":2}\n{\"v\":2}\n").unwrap();
        let e = run(&f.args("report3.json")).unwrap_err().to_string();
        assert!(e.contains("no line could be read"), "{e}");
        assert!(!f.path("report2.json").exists() && !f.path("report3.json").exists());
    }

    #[test]
    fn outputs_never_touch_the_inputs() {
        let matches = twelve("amazon-infra.example", "amazon");
        let seg = "1\t1000\ta.amazon-infra.example amazon.com\t\n";
        let f = Fixture::new(&matches, &[("log-a", seg)]);
        let snapshot = |dir: &Path| -> BTreeMap<PathBuf, Vec<u8>> {
            fs::read_dir(dir)
                .unwrap()
                .map(|e| {
                    let p = e.unwrap().path();
                    let b = fs::read(&p).unwrap();
                    (p, b)
                })
                .collect()
        };
        let before = snapshot(&f.path("evidence"));

        let mut a = f.args("report.json");
        a.write_brands = Some(f.path("evidence/brands.json"));
        let e = run(&a).unwrap_err().to_string();
        assert!(e.contains("inside the evidence directory"), "{e}");
        let mut a = f.args("evidence/report.json");
        a.write_brands = None;
        assert!(run(&a).is_err());
        let a = f.args("run/report.json");
        let e = run(&a).unwrap_err().to_string();
        assert!(e.contains("inside the run directory"), "{e}");
        let mut a = f.args("same.json");
        a.write_brands = Some(f.path("same.json"));
        let e = run(&a).unwrap_err().to_string();
        assert!(e.contains("the same file"), "{e}");
        assert!(!f.path("report.json").exists() && !f.path("same.json").exists());

        let mut a = f.args("report.json");
        a.write_brands = Some(f.path("brands.json"));
        run(&a).unwrap();
        assert_eq!(snapshot(&f.path("evidence")), before);
    }

    #[test]
    fn the_multi_tenant_limit_counts_only_domains_the_brand_does_not_own() {
        let mut matches = String::new();
        for d in ["at-limit.example", "over-limit.example", "owner.example"] {
            matches.push_str(&twelve(d, "amazon"));
        }
        let mut seg = String::new();
        // at-limit: amazon.com plus 20 unrelated domains (the limit); over-limit: 21.
        seg += &certs(3, "at-limit.example", "amazon.com");
        seg += &certs(3, "over-limit.example", "amazon.com");
        for i in 0..21 {
            if i < 20 {
                seg += &format!("0\t1000\tx.at-limit.example u{i}.example\t\n");
            }
            seg += &format!("0\t1000\tx.over-limit.example u{i}.example\t\n");
        }
        // owner: 20 unrelated domains and many of the brand's own, which do not count.
        for d in [
            "amazon.com",
            "amazon.de",
            "amazon.fr",
            "amazon.it",
            "amazon.es",
        ] {
            seg += &certs(1, "owner.example", d);
        }
        for i in 0..20 {
            seg += &format!("0\t1000\tx.owner.example u{i}.example\t\n");
        }
        let f = Fixture::new(&matches, &[("log-a", &seg)]);
        let rep = run(&f.args("report.json")).unwrap();
        let s = &rep.suggested["amazon"];
        assert_eq!(find(s, "at-limit.example").co_domains, 21);
        assert_eq!(find(s, "owner.example").co_domains, 25);
        let over = find_rej(&rep.rejected["amazon"], "over-limit.example");
        assert_eq!((over.reason, over.co_domains), (MULTI_TENANT, 22));
    }
}
