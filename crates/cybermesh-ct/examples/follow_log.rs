//! Follows a real static CT log briefly (manual validation; not run in CI): verifies two
//! checkpoints `secs` apart against the pinned key and proves the second extends the first,
//! exactly as the coordinator does in follow mode.
//! Usage: cargo run -p cybermesh-ct --features http --example follow_log -- <log-list.json> <log-id> [secs]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::time::{Duration, Instant};

use cybermesh_analysis::CtLogInfo;
use cybermesh_ct::checkpoint::fetch_verified_checkpoint;
use cybermesh_ct::proof::TileAuthenticator;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let logs: Vec<CtLogInfo> =
        serde_json::from_str(&std::fs::read_to_string(&args[1]).unwrap()).unwrap();
    let log = logs
        .into_iter()
        .find(|l| l.log_id == args[2])
        .expect("log id");
    let secs: u64 = args.get(3).map_or(10, |s| s.parse().unwrap());
    let src = cybermesh_ct::http::HttpTileSource::new(&log, Duration::from_secs(30)).unwrap();
    let first = fetch_verified_checkpoint(&src, &log).unwrap();
    std::thread::sleep(Duration::from_secs(secs));
    let second = fetch_verified_checkpoint(&src, &log).unwrap();
    let t0 = Instant::now();
    TileAuthenticator::new(&src, second.clone())
        .prove_extends(&first)
        .unwrap();
    println!(
        "{}: {} -> {} entries in {secs} s (+{} full tiles); both signatures verified; consistency proven in {:?}",
        log.log_id,
        first.size,
        second.size,
        second.full_tiles() - first.full_tiles(),
        t0.elapsed()
    );
}
