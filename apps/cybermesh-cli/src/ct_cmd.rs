//! `cybermesh ct ...`: Certificate Transparency monitoring utilities.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use clap::Subcommand;
use cybermesh_analysis::{Engine, EvidenceBundle};
use cybermesh_ct::checkpoint::fetch_verified_checkpoint;
use cybermesh_ct::http::HttpTileSource;
use cybermesh_ct::proof::TileAuthenticator;
use cybermesh_ct::{TileSource as _, scan_tile};
use serde::Serialize;

use crate::release_cmd::load_records;
use crate::util::{self, write_json};

#[derive(Subcommand, Debug)]
pub enum CtCmd {
    /// Clear the accepted checkpoint of a followed log (`ct-follow.json`) after investigating
    /// an inconsistency, keeping the resume point so no tile is skipped.
    FollowReset {
        /// Path to the coordinator's `state_dir/ct-follow.json`.
        #[arg(long)]
        state: PathBuf,
    },
    /// Check a split-view proof (`state_dir/ct-split-views/*.json`) offline against the
    /// log's pinned key: two checkpoints signed by the log that cannot both be correct.
    VerifySplitView {
        /// Evidence bundle pinning the log (its `ct-logs` source).
        #[arg(long)]
        evidence: PathBuf,
        /// The proof file.
        proof: PathBuf,
    },
    /// Show a pinned log's current checkpoint.
    Checkpoint {
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        log: String,
    },
    /// Scan full tiles of a pinned log locally (one-off; not distributed, not verified).
    Scan {
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        log: String,
        /// First tile; defaults to the most recent `--tiles` full tiles.
        #[arg(long)]
        first_tile: Option<u64>,
        #[arg(long, default_value_t = 4)]
        tiles: u64,
        #[arg(long)]
        json_out: Option<PathBuf>,
    },
    /// Follow live logs in one process and record every name and brand signal, for
    /// evaluations (see `ct_watch`). Not distributed; tiles are verified and proven.
    Watch(crate::ct_watch::WatchArgs),
    /// Score a `ct watch` run against independently confirmed phishing (recall, lead time,
    /// a precision floor, a false-alarm sample, comparison with phishunt).
    Evaluate(crate::ct_evaluate::EvaluateArgs),
    /// Investigation report (per protected brand) from verified CT records, for security
    /// teams. Includes brand signals below the warning threshold.
    Report {
        #[arg(long)]
        records: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}

/// The protected brands named in an assessment's brand-signal findings (their detail ends
/// with `: brand, ...`, a lookalike written as `token~brand`).
pub(crate) fn brand_names(a: &cybermesh_protocol::DomainAssessment) -> Vec<String> {
    let mut out: Vec<String> = a
        .findings
        .iter()
        .filter(|f| cybermesh_ct::is_brand_signal(f.code))
        .flat_map(|f| {
            f.detail
                .rsplit(": ")
                .next()
                .unwrap_or("")
                .split(", ")
                .map(|b| b.split('~').next_back().unwrap_or(b).to_owned())
        })
        .filter(|b| !b.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

pub(crate) fn log_info(
    evidence: &EvidenceBundle,
    log: &str,
) -> Result<cybermesh_analysis::CtLogInfo> {
    evidence
        .ct_logs
        .iter()
        .find(|l| l.log_id == log)
        .cloned()
        .with_context(|| format!("log {log} is not in the ct-logs evidence"))
}

fn source(evidence: &EvidenceBundle, log: &str) -> Result<HttpTileSource> {
    Ok(HttpTileSource::new(
        &log_info(evidence, log)?,
        Duration::from_secs(30),
    )?)
}

#[derive(Serialize)]
struct ReportItem {
    name: String,
    log_id: String,
    /// Log entries (certificates / precertificates) that contain this name.
    entries: Vec<u64>,
    risk_score_bp: u16,
    verdict: String,
    codes: Vec<String>,
    published_as_warning: bool,
    verification_task: String,
}

/// What the verified records cover, and where coverage is incomplete.
#[derive(Serialize, Default)]
struct Coverage {
    tasks_verified: u64,
    tiles_verified: u64,
    entries_verified: u64,
    unparsed_entries: u64,
    /// (log, tile) whose matches or names were capped: re-scan them for a complete view.
    truncated_tiles: Vec<(String, u64)>,
    /// (log, tile) whose data did not match the log's own hash (task disputed, not verified).
    log_inconsistent_tiles: Vec<(String, u64)>,
}

#[derive(Serialize)]
struct Report<'a> {
    coverage: &'a Coverage,
    brands: &'a BTreeMap<String, Vec<ReportItem>>,
}

/// Checks a split-view proof against the pinned log keys; returns a description.
fn check_split_view(
    ev: &cybermesh_node::ct_witness::SplitViewEvidence,
    logs: &[cybermesh_analysis::CtLogInfo],
) -> Result<Vec<String>> {
    let log = logs
        .iter()
        .find(|l| l.log_id == ev.log_id)
        .with_context(|| format!("log {} is not in the ct-logs evidence", ev.log_id))?;
    let key = cybermesh_ct::LogKey::from_info(log)?;
    let (larger, smaller) = ev
        .proof
        .verify(&key)
        .map_err(|e| anyhow::anyhow!("NOT a valid split-view proof for {}: {e}", ev.log_id))?;
    let b64 = |h: &[u8; 32]| {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(h)
    };
    let mut out = vec![format!(
        "VALID: {} ({}) signed two trees that cannot both be correct",
        ev.log_id,
        key.origin()
    )];
    for cp in [&larger, &smaller] {
        out.push(format!(
            "  size {} root {} (signed at {} ms)",
            cp.size,
            b64(&cp.root),
            cp.signed_at_ms
        ));
    }
    if smaller.size < larger.size {
        out.push(format!(
            "  the larger tree's first {} entries have another root, shown by a {}-hash consistency proof",
            smaller.size,
            ev.proof.proof.len()
        ));
    }
    out.push(format!(
        "  detected by {} at {}; other view reported by {}",
        ev.detected_by.short(),
        ev.detected_at,
        ev.reported_by
            .as_ref()
            .map_or("this node's own view", |k| k.short())
    ));
    Ok(out)
}

pub fn run(c: CtCmd) -> Result<()> {
    match c {
        CtCmd::Checkpoint { evidence, log } => {
            let ev = EvidenceBundle::load(&evidence)?;
            let info = log_info(&ev, &log)?;
            let cp = fetch_verified_checkpoint(&source(&ev, &log)?, &info)
                .context("checkpoint not verified against the pinned log key")?;
            println!(
                "origin={} size={} full_tiles={} signed_at_ms={} (signature verified with the pinned key)",
                cp.origin,
                cp.size,
                cp.full_tiles(),
                cp.signed_at_ms
            );
            Ok(())
        }
        CtCmd::Scan {
            evidence,
            log,
            first_tile,
            tiles,
            json_out,
        } => {
            let ev = EvidenceBundle::load(&evidence)?;
            let src = source(&ev, &log)?;
            let info = log_info(&ev, &log)?;
            let cp = fetch_verified_checkpoint(&src, &info)
                .context("checkpoint not verified against the pinned log key")?;
            let auth = TileAuthenticator::new(&src, cp.clone());
            let first = first_tile.unwrap_or(cp.full_tiles().saturating_sub(tiles));
            let end = first
                .checked_add(tiles)
                .filter(|e| *e <= cp.full_tiles())
                .with_context(|| format!("only {} full tiles exist", cp.full_tiles()))?;
            let engine = Engine::new(ev);
            let cpu0 = cybermesh_node::governor::process_cpu();
            let t0 = Instant::now();
            let (mut bytes, mut matches, mut unparsed, mut roots_ok) =
                (0u64, Vec::new(), 0u64, 0u64);
            for n in first..end {
                let data = src.data_tile(n)?;
                bytes += data.len() as u64;
                let r = scan_tile(&data, n, &engine)?;
                // The worker's root must equal the root proven against the signed checkpoint.
                if auth.tile_root(n).is_ok_and(|x| x == r.root.0) {
                    roots_ok += 1;
                }
                unparsed += u64::from(r.unparsed);
                matches.extend(r.matches);
            }
            let cpu = cybermesh_node::governor::process_cpu().saturating_sub(cpu0);
            let entries = tiles * 256;
            println!(
                "scanned {entries} entries ({tiles} tiles from {first}) in {:.1}s: {} KiB downloaded (decoded), CPU {:.0} us/entry, unparsed {unparsed}, tile roots proven against the signed checkpoint {roots_ok}/{tiles}, brand signals {}",
                t0.elapsed().as_secs_f64(),
                bytes / 1024,
                cpu.as_secs_f64() * 1e6 / entries as f64,
                matches.len()
            );
            for m in &matches {
                println!(
                    "  {:>12} {:<60} {:>5} {:?} {:?}",
                    m.index, m.name, m.risk_score_bp, m.verdict, m.codes
                );
            }
            if let Some(p) = json_out {
                write_json(&p, &matches)?;
            }
            Ok(())
        }
        CtCmd::Watch(a) => crate::ct_watch::run(&a),
        CtCmd::Evaluate(a) => {
            let rep = crate::ct_evaluate::run(&a)?;
            crate::ct_evaluate::print(&rep);
            println!("report: {}", a.out.join("report.json").display());
            Ok(())
        }
        CtCmd::FollowReset { state } => {
            let mut s: cybermesh_node::ct_follow::FollowState = util::read_json(&state)?;
            let old = s.head.take();
            write_json(&state, &s)?;
            println!(
                "{}: accepted head cleared (was size {}); following resumes at tile {} and will accept the log's next valid checkpoint",
                s.log_id,
                old.map_or(0, |h| h.size),
                s.resume_from
            );
            Ok(())
        }
        CtCmd::VerifySplitView { evidence, proof } => {
            let ev: cybermesh_node::ct_witness::SplitViewEvidence = util::read_json(&proof)?;
            let bundle = EvidenceBundle::load(&evidence)?;
            for line in check_split_view(&ev, &bundle.ct_logs)? {
                println!("{line}");
            }
            Ok(())
        }
        CtCmd::Report {
            records,
            manifest,
            root,
            evidence,
            out,
        } => {
            let m = util::load_manifest(&manifest, &root, util::now())?;
            let engine = Engine::new(EvidenceBundle::load(&evidence)?);
            let recs = load_records(&records, &m, false)?;
            let mut by_brand: BTreeMap<String, Vec<ReportItem>> = BTreeMap::new();
            let mut cov = Coverage::default();
            for (_, r) in &recs {
                if let Some(ct) = &r.ct {
                    cov.log_inconsistent_tiles.extend(
                        ct.log_inconsistent_tiles
                            .iter()
                            .map(|t| (ct.log_id.clone(), *t)),
                    );
                }
            }
            for (_, r) in recs
                .iter()
                .filter(|(_, r)| r.status == cybermesh_verifier::TaskStatus::Verified)
            {
                let Some(ct) = &r.ct else { continue };
                cov.tasks_verified += 1;
                cov.tiles_verified += u64::from(ct.tile_count);
                cov.entries_verified += ct.entries;
                cov.unparsed_entries += ct.unparsed;
                cov.truncated_tiles
                    .extend(ct.truncated_tiles.iter().map(|t| (ct.log_id.clone(), *t)));
                let published: std::collections::BTreeSet<&str> =
                    r.outcomes.iter().map(|o| o.domain.as_str()).collect();
                for mt in &ct.matches {
                    // Attribute to the brands named in the verifier's own findings.
                    let a = engine.assess(&mt.name)?;
                    let brands = brand_names(&a);
                    for b in if brands.is_empty() {
                        vec!["(unattributed)".to_owned()]
                    } else {
                        brands
                    } {
                        let list = by_brand.entry(b).or_default();
                        if let Some(existing) = list
                            .iter_mut()
                            .find(|i| i.name == mt.name && i.log_id == ct.log_id)
                        {
                            existing.entries.push(mt.index);
                            continue;
                        }
                        list.push(ReportItem {
                            name: mt.name.clone(),
                            log_id: ct.log_id.clone(),
                            entries: vec![mt.index],
                            risk_score_bp: a.risk_score_bp,
                            verdict: format!("{:?}", a.verdict),
                            codes: a.findings.iter().map(|f| format!("{:?}", f.code)).collect(),
                            published_as_warning: published.contains(mt.name.as_str()),
                            verification_task: r.task_id.clone(),
                        });
                    }
                }
            }
            write_json(
                &out,
                &Report {
                    coverage: &cov,
                    brands: &by_brand,
                },
            )?;
            println!(
                "coverage: {} verified task(s), {} tile(s), {} entries ({} unparsed)",
                cov.tasks_verified, cov.tiles_verified, cov.entries_verified, cov.unparsed_entries
            );
            for (log, t) in &cov.truncated_tiles {
                println!(
                    "  incomplete: {log} tile {t} hit a match or name cap; re-scan it locally"
                );
            }
            for (log, t) in &cov.log_inconsistent_tiles {
                println!("  log inconsistency: {log} tile {t} does not match the log's own hash");
            }
            for (b, items) in &by_brand {
                let published = items.iter().filter(|i| i.published_as_warning).count();
                println!(
                    "{b}: {} lookalike name(s) in newly logged certificates ({published} published as advisory warnings)",
                    items.len()
                );
                for i in items {
                    println!(
                        "    {:<50} {} cert(s) {}",
                        i.name,
                        i.entries.len(),
                        if i.published_as_warning {
                            "[warning]"
                        } else {
                            "[investigate]"
                        }
                    );
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use cybermesh_ct::mock::{MockLog, demo_entries};
    use cybermesh_ct::proof::TileAuthenticator;
    use cybermesh_ct::verify_checkpoint;
    use cybermesh_ct::witness::SplitViewProof;
    use cybermesh_node::ct_witness::SplitViewEvidence;

    use super::*;

    #[test]
    fn a_split_view_proof_is_checked_against_the_pinned_key_only() {
        let base = MockLog::build("ct.example/test", &demo_entries(1)).unwrap();
        let mut a = base.clone();
        a.extend(&demo_entries(2)).unwrap();
        let mut b = base.clone();
        b.extend(&demo_entries(1)).unwrap();
        let info = base.log_info("mock-log", "http://127.0.0.1:9/");
        let key = cybermesh_ct::LogKey::from_info(&info).unwrap();
        let (na, nb) = (a.checkpoint().unwrap(), b.checkpoint().unwrap());
        let (ca, cb) = (
            verify_checkpoint(&na, &key).unwrap(),
            verify_checkpoint(&nb, &key).unwrap(),
        );
        let c = TileAuthenticator::new(&a, ca)
            .consistency_with(&cb)
            .unwrap();
        let who = cybermesh_crypto::SecretKey::from_seed(&[3; 32]).key_id();
        let mut ev = SplitViewEvidence {
            log_id: "mock-log".into(),
            detected_at: 1,
            detected_by: who.clone(),
            reported_by: Some(who),
            observation: None,
            proof: SplitViewProof::new(key.origin(), &na, &nb, &c).unwrap(),
        };
        let lines = check_split_view(&ev, std::slice::from_ref(&info)).unwrap();
        assert!(lines[0].starts_with("VALID: mock-log"), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("first 512 entries")));
        // Another log's key, a log not pinned, or a tampered proof: refused.
        let other = MockLog::build("other.example/log", &demo_entries(1))
            .unwrap()
            .log_info("mock-log", "http://127.0.0.1:9/");
        assert!(check_split_view(&ev, &[other]).is_err());
        assert!(check_split_view(&ev, &[]).is_err());
        ev.proof.smaller = base.checkpoint().unwrap();
        let e = check_split_view(&ev, &[info]).unwrap_err().to_string();
        assert!(e.starts_with("NOT a valid split-view proof"), "{e}");
    }
}
