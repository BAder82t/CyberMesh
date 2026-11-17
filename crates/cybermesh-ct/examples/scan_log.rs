//! Scans full tiles of a real static CT log once (manual validation; not run in CI). The
//! checkpoint is verified against the log's pinned key and every tile root is proven against
//! it, exactly as the verifier does.
//! Usage: cargo run -p cybermesh-ct --features http --example scan_log -- <log-list.json> <log-id> <evidence-dir> [tiles-from-end]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::time::{Duration, Instant};

use cybermesh_analysis::{CtLogInfo, Engine, EvidenceBundle};
use cybermesh_ct::checkpoint::fetch_verified_checkpoint;
use cybermesh_ct::names::certificate_names;
use cybermesh_ct::proof::TileAuthenticator;
use cybermesh_ct::tile::parse_data_tile;
use cybermesh_ct::{TileSource, scan_tile};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let logs: Vec<CtLogInfo> =
        serde_json::from_str(&std::fs::read_to_string(&args[1]).unwrap()).unwrap();
    let log = logs
        .into_iter()
        .find(|l| l.log_id == args[2])
        .expect("log id");
    let src = cybermesh_ct::http::HttpTileSource::new(&log, Duration::from_secs(30)).unwrap();
    let engine = Engine::new(EvidenceBundle::load(std::path::Path::new(&args[3])).unwrap());
    let back: u64 = args.get(4).map_or(1, |s| s.parse().unwrap());
    let cp = fetch_verified_checkpoint(&src, &log).unwrap();
    println!(
        "checkpoint origin={} size={} full_tiles={} signature=verified (pinned key, signed at {} ms)",
        cp.origin,
        cp.size,
        cp.full_tiles(),
        cp.signed_at_ms
    );
    let t_auth = Instant::now();
    let auth = TileAuthenticator::new(&src, cp.clone());
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
        let proven = auth.tile_root(n).unwrap();
        println!(
            "tile {n}: {} bytes, fetch {:?}, entries {} (precerts {precerts}), names {names}, unparsed {failed}, scan {:?}, root_proven_against_signed_checkpoint={}, matches={}",
            bytes.len(),
            fetch,
            entries.len(),
            scan,
            r.root.0 == proven,
            r.matches.len()
        );
        for m in r.matches.iter().take(10) {
            println!(
                "   match index={} name={} score={} verdict={:?} codes={:?}",
                m.index, m.name, m.risk_score_bp, m.verdict, m.codes
            );
        }
    }
    println!(
        "proof of {back} tile root(s) against the signed checkpoint took {:?} (including hash tile fetches)",
        t_auth.elapsed()
    );
}
