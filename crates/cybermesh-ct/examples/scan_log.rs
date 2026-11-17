//! Scans full tiles of a real static CT log once (manual validation; not run in CI).
//! Usage: cargo run -p cybermesh-ct --features http --example scan_log -- <monitoring-url> <evidence-dir> [tiles-from-end]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::time::{Duration, Instant};

use cybermesh_analysis::{CtLogInfo, Engine, EvidenceBundle};
use cybermesh_ct::names::certificate_names;
use cybermesh_ct::tile::parse_data_tile;
use cybermesh_ct::{Checkpoint, TileSource, scan_tile};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let log = CtLogInfo {
        log_id: "real".into(),
        description: String::new(),
        monitoring_url: args[1].clone(),
    };
    let src = cybermesh_ct::http::HttpTileSource::new(&log, Duration::from_secs(30)).unwrap();
    let engine = Engine::new(EvidenceBundle::load(std::path::Path::new(&args[2])).unwrap());
    let back: u64 = args.get(3).map_or(1, |s| s.parse().unwrap());
    let cp = Checkpoint::parse(&src.checkpoint().unwrap()).unwrap();
    println!(
        "checkpoint origin={} size={} full_tiles={}",
        cp.origin,
        cp.size,
        cp.full_tiles()
    );
    for n in cp.full_tiles().saturating_sub(back)..cp.full_tiles() {
        let t0 = Instant::now();
        let bytes = src.data_tile(n).unwrap();
        let fetch = t0.elapsed();
        let entries = parse_data_tile(&bytes, n).unwrap();
        let precerts = entries
            .iter()
            .filter(|e| e.kind == cybermesh_ct::EntryKind::Precert)
            .count();
        let mut names = 0usize;
        let mut failed = 0usize;
        for e in &entries {
            match certificate_names(e) {
                Ok(v) => names += v.len(),
                Err(_) => failed += 1,
            }
        }
        let cpu0 = Instant::now();
        let r = scan_tile(&bytes, n, &engine).unwrap();
        let scan = cpu0.elapsed();
        let log_root = src.tile_root(n, cp.size).unwrap();
        println!(
            "tile {n}: {} bytes, fetch {:?}, entries {} (precerts {precerts}), names {names}, unparsed {failed}, scan {:?}, root_matches_log={}, matches={}",
            bytes.len(),
            fetch,
            entries.len(),
            scan,
            r.root.0 == log_root,
            r.matches.len()
        );
        for m in r.matches.iter().take(10) {
            println!(
                "   match index={} name={} score={} verdict={:?} codes={:?}",
                m.index, m.name, m.risk_score_bp, m.verdict, m.codes
            );
        }
    }
}
