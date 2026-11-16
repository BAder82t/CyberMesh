//! Scale and throughput measurements. Run with `cargo test -p cybermesh-tests --release
//! --test performance -- --ignored --nocapture`; results are reported in docs/evaluation.md.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{Duration, Instant};

use cybermesh_tests::{Harness, Options, domains};

/// 15 workers across 5 operators assess a few hundred domains.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "measurement run; see docs/evaluation.md"]
async fn fifteen_workers_five_operators() {
    let mut ds = domains();
    for i in 0..300 {
        ds.push(format!("host{i:03}.example{}.com", i % 7));
    }
    ds.sort();
    ds.dedup();
    let started = Instant::now();
    let h = Harness::start(Options {
        operators: vec![("org-a", 3), ("org-b", 3), ("org-c", 3), ("org-d", 3), ("org-e", 3)],
        replication: 3,
        batch_size: 32,
        result_timeout: Duration::from_secs(10),
        domains: ds,
        ..Options::default()
    });
    let (_, report, statuses, _dir) = h.finish(Duration::from_secs(300)).await;
    let elapsed = started.elapsed();
    let lat = &report.settle_latency_ms;
    let mut sorted = lat.clone();
    sorted.sort_unstable();
    let p50 = sorted.get(sorted.len() / 2).copied().unwrap_or(0);
    let p95 = sorted.get(sorted.len() * 95 / 100).copied().unwrap_or(0);
    let worker_bytes_out: u64 = statuses.iter().map(|s| s.net_bytes_out).sum();
    let worker_bytes_in: u64 = statuses.iter().map(|s| s.net_bytes_in).sum();
    println!(
        "PERF workers=15 operators=5 domains={} tasks={} verified={} reassignments={} elapsed={:.1}s \
         settle_latency_ms p50={p50} p95={p95} coordinator_bytes_in={} coordinator_bytes_out={} \
         worker_bytes_in={worker_bytes_in} worker_bytes_out={worker_bytes_out} bytes_per_domain={:.0}",
        report.domains_total,
        report.tasks_issued,
        report.verified,
        report.reassignments,
        elapsed.as_secs_f64(),
        report.net_bytes_in,
        report.net_bytes_out,
        (report.net_bytes_in + report.net_bytes_out + worker_bytes_in + worker_bytes_out) as f64
            / report.domains_total as f64
    );
    assert_eq!(report.verified, report.tasks_issued - report.reassignments);
}
