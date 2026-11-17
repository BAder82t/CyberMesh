//! `cybermesh ct ...`: Certificate Transparency monitoring utilities.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use clap::Subcommand;
use cybermesh_analysis::{Engine, EvidenceBundle};
use cybermesh_ct::http::HttpTileSource;
use cybermesh_ct::{Checkpoint, TileSource as _, scan_tile};
use serde::Serialize;

use crate::release_cmd::load_records;
use crate::util::{self, write_json};

#[derive(Subcommand, Debug)]
pub enum CtCmd {
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

fn source(evidence: &EvidenceBundle, log: &str) -> Result<HttpTileSource> {
    let info = evidence
        .ct_logs
        .iter()
        .find(|l| l.log_id == log)
        .with_context(|| format!("log {log} is not in the ct-logs evidence"))?;
    Ok(HttpTileSource::new(info, Duration::from_secs(30))?)
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

pub fn run(c: CtCmd) -> Result<()> {
    match c {
        CtCmd::Checkpoint { evidence, log } => {
            let ev = EvidenceBundle::load(&evidence)?;
            let cp = Checkpoint::parse(&source(&ev, &log)?.checkpoint()?)?;
            println!(
                "origin={} size={} full_tiles={} (checkpoint signature not verified)",
                cp.origin,
                cp.size,
                cp.full_tiles()
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
            let cp = Checkpoint::parse(&src.checkpoint()?)?;
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
                if src.tile_root(n, cp.size).is_ok_and(|x| x == r.root.0) {
                    roots_ok += 1;
                }
                unparsed += u64::from(r.unparsed);
                matches.extend(r.matches);
            }
            let cpu = cybermesh_node::governor::process_cpu().saturating_sub(cpu0);
            let entries = tiles * 256;
            println!(
                "scanned {entries} entries ({tiles} tiles from {first}) in {:.1}s: {} KiB downloaded (decoded), CPU {:.0} us/entry, unparsed {unparsed}, tile roots matching the log {roots_ok}/{tiles}, brand signals {}",
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
                    let brands: Vec<String> = a
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
                        .collect();
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
