//! End-to-end: coordinator + workers of independent operators over real libp2p, signed
//! tasks, independent analysis, verification, a co-signed release verified offline, and
//! transparency-log anchoring on the local test chain.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use cybermesh_anchor::{Anchor, AnchorReceipt, LocalChain, LogEntry, TransparencyLog};
use cybermesh_crypto::{Digest, canonical};
use cybermesh_intelligence::{
    Action, BuildParams, TrustRoot, build_release, sign_release, verify_release,
};
use cybermesh_protocol::{Clock, SystemClock};
use cybermesh_tests::{Harness, LEXICAL, Options, PHISH};
use cybermesh_verifier::TaskStatus;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_pipeline_over_libp2p() {
    let h = Harness::start(Options::default());
    let (net, report, statuses, _dir) = h.finish(Duration::from_secs(120)).await;

    let batches = report.domains_total.div_ceil(4) as u64;
    assert_eq!(report.verified, batches, "{report:?}");
    assert_eq!(report.faults, 0);
    assert!(statuses.iter().map(|s| s.tasks_completed).sum::<u64>() >= batches * 3);

    // Every verified record was recomputed by the verifier and agreed by 3 operators.
    let verified: Vec<_> = report
        .records
        .iter()
        .filter(|(_, r)| r.status == TaskStatus::Verified)
        .collect();
    assert!(verified.iter().all(|(_, r)| r.recomputed));
    assert!(
        verified
            .iter()
            .all(|(_, r)| r.outcomes.iter().all(|o| o.agreeing_operators.len() >= 3))
    );

    // Build a release independently twice (two organisations) and co-sign.
    let now = SystemClock.now();
    let params = BuildParams {
        network_id: net.network_id.clone(),
        sequence: 1,
        previous: None,
        issued_at: now,
        ttl_secs: 86_400,
        max_record_age_secs: 86_400,
        min_verifiers: 1,
    };
    let rel_a = build_release(&report.records, &[], &params).unwrap();
    let mut reversed = report.records.clone();
    reversed.reverse();
    let rel_b = build_release(&reversed, &[], &params).unwrap();
    assert_eq!(
        canonical::to_vec(&rel_a).unwrap(),
        canonical::to_vec(&rel_b).unwrap()
    );
    let mut env = sign_release(&rel_a, &net.release_signers[0].0).unwrap();
    env.merge_signatures(&sign_release(&rel_b, &net.release_signers[1].0).unwrap())
        .unwrap();
    let root = TrustRoot::from_manifest(&net.manifest);
    let v = verify_release(&env.to_vec().unwrap(), &root, now, None).unwrap();

    assert_eq!(v.release.lookup(PHISH).unwrap().action, Action::Block);
    assert_eq!(v.release.lookup(LEXICAL).unwrap().action, Action::Warn);
    // Feed false positive on a popular domain is never published.
    assert!(v.release.lookup("www.google.com").is_none());
    assert!(v.release.lookup("wikipedia.org").is_none());
    assert!(v.release.lookup("examplebank.test").is_none());

    // Anchor the release digest through the transparency log on the local test chain.
    let mut log = TransparencyLog::new(&net.network_id);
    log.append(LogEntry {
        sequence: 1,
        release_digest: v.digest,
    })
    .unwrap();
    let cp = log.checkpoint().unwrap();
    let mut chain = LocalChain::in_memory("e2e-chain");
    let AnchorReceipt::LocalChain(receipt) = chain.submit(cp.commitment(), now).unwrap() else {
        panic!("unexpected receipt type")
    };
    let proof = log.prove_inclusion(0, 1).unwrap();
    assert!(proof.verify());
    assert_eq!(
        proof.entry.release_digest,
        Digest::of(&env.payload_bytes().unwrap())
    );
    LocalChain::verify_receipt(&receipt, &proof.checkpoint.commitment(), Some(&chain)).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnected_worker_is_replaced_by_reassignment() {
    // Four operators, every task assigned to all four; one worker disconnects early.
    let mut h = Harness::start(Options {
        replication: 4,
        result_timeout: Duration::from_secs(4),
        ..Options::default()
    });
    // Let the coordinator see its heartbeats, then stop it (simulated outage).
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (_, tx, handle) = h.workers.remove(3);
    let _ = tx.send(true);
    let _ = handle.await;
    let (_, report, _, _dir) = h.finish(Duration::from_secs(120)).await;
    let batches = report.domains_total.div_ceil(4) as u64;
    assert_eq!(report.verified, batches, "{report:?}");
    // The remaining three operators still meet the diversity requirement; tasks either
    // completed without the missing worker after the deadline or were reassigned.
    assert!(
        report
            .records
            .iter()
            .any(|(_, r)| r.status == TaskStatus::Verified)
    );
    assert_eq!(report.faults, 0, "an offline worker is not a faulty worker");
}

/// Regression: sustained load with large batches must settle every batch (no results lost to
/// rate limiting, no stalled queue).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sustained_load_settles_every_batch() {
    let mut ds = cybermesh_tests::domains();
    for i in 0..600 {
        ds.push(format!("site{i:04}.example-{}.com", i % 13));
    }
    ds.sort();
    ds.dedup();
    let h = Harness::start(Options {
        batch_size: 32,
        domains: ds,
        result_timeout: Duration::from_secs(10),
        ..Options::default()
    });
    let (_, report, _, _dir) = h.finish(Duration::from_secs(180)).await;
    let batches = report.domains_total.div_ceil(32) as u64;
    assert_eq!(report.verified, batches, "{report:?}");
    assert_eq!(report.net_dropped_rate_limited, 0);
    assert_eq!(report.domains_abandoned, 0);
}

/// Regression: when too few distinct operators remain, the coordinator abandons the batch
/// after a bounded time instead of stalling forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unassignable_batches_are_abandoned_not_stalled() {
    let mut h = Harness::start(Options {
        operators: vec![("org-a", 1), ("org-b", 1), ("org-c", 1)],
        result_timeout: Duration::from_secs(2),
        abandon_after: Duration::from_secs(4),
        ..Options::default()
    });
    tokio::time::sleep(Duration::from_millis(1500)).await;
    // Take one of only three operators offline: no batch can reach 3 operators any more.
    let (_, tx, handle) = h.workers.remove(2);
    let _ = tx.send(true);
    let _ = handle.await;
    let (_, report, _, _dir) = h.finish(Duration::from_secs(90)).await;
    // The coordinator terminated (finish() did not time out). Every domain reached an
    // explicit final state: verified, insufficient after the last attempt, or abandoned.
    let verified_domains: usize = report
        .records
        .iter()
        .filter(|(_, r)| r.status == TaskStatus::Verified)
        .map(|(_, r)| r.outcomes.len())
        .sum();
    let final_insufficient: usize = report
        .records
        .iter()
        .filter(|(_, r)| r.status != TaskStatus::Verified && r.attempt == 2)
        .count()
        * 4; // batch_size in Options::default()
    assert!(
        verified_domains + final_insufficient + report.domains_abandoned >= report.domains_total,
        "every domain must reach a final state: {report:?}"
    );
}
