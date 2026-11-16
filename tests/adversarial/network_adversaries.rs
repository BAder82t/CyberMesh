//! Misbehaving workers on a real network: each adversary mode is detected, quarantined or
//! rejected, and never changes what is published.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use cybermesh_intelligence::{Action, BuildParams, build_release};
use cybermesh_protocol::{Clock, SystemClock};
use cybermesh_tests::{Harness, LEXICAL, Options, PHISH};
use cybermesh_verifier::{FaultKind, TaskStatus};

async fn run_with(mode: &'static str) -> cybermesh_node::coordinator::CoordinatorReport {
    let h = Harness::start(Options {
        operators: vec![("org-a", 1), ("org-b", 1), ("org-c", 1), ("org-m", 1)],
        adversaries: vec![(3, mode)],
        // Assign every task to all four so the adversary always participates.
        replication: 4,
        result_timeout: Duration::from_secs(5),
        ..Options::default()
    });
    let (net, report, _, _dir) = h.finish(Duration::from_secs(150)).await;
    // Whatever the adversary does, the published release is identical to the honest one.
    let params = BuildParams {
        network_id: net.network_id.clone(),
        sequence: 1,
        previous: None,
        issued_at: SystemClock.now(),
        ttl_secs: 86_400,
        max_record_age_secs: 86_400,
    };
    let rel = build_release(&report.records, &[], &params).unwrap();
    assert_eq!(
        rel.lookup(PHISH).map(|e| e.action),
        Some(Action::Block),
        "{mode}"
    );
    assert_eq!(
        rel.lookup(LEXICAL).map(|e| e.action),
        Some(Action::Warn),
        "{mode}"
    );
    assert!(rel.lookup("www.google.com").is_none());
    assert!(
        rel.lookup("mail.example.org").is_none(),
        "{mode}: benign domain published"
    );
    report
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_verdicts_are_caught_and_quarantined() {
    let report = run_with("flip-verdicts").await;
    assert!(report.faults >= 1, "{report:?}");
    let kinds: Vec<FaultKind> = report
        .records
        .iter()
        .flat_map(|(_, r)| r.faults.iter().map(|f| f.kind))
        .collect();
    assert!(kinds.iter().all(|k| *k == FaultKind::IncorrectResult));
    // After the first fault the adversary is quarantined and excluded from later tasks.
    let faulted_tasks = report
        .records
        .iter()
        .filter(|(_, r)| !r.faults.is_empty())
        .count();
    assert!(
        faulted_tasks <= 4,
        "quarantine should stop repeated assignment"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn equivocation_is_proven_with_both_signed_results() {
    let report = run_with("equivocate").await;
    // Equivocation is proven either inside the task (both results before settlement) or
    // afterwards from the settled task's accepted digest.
    let eq: Vec<_> = report
        .records
        .iter()
        .flat_map(|(_, r)| r.faults.iter())
        .chain(report.late_faults.iter())
        .filter(|f| f.kind == FaultKind::Equivocation)
        .collect();
    assert!(!eq.is_empty(), "{report:?}");
    assert!(eq.iter().all(|f| f.evidence.len() == 2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_signatures_are_rejected() {
    let report = run_with("forge-signature").await;
    assert!(report.results_rejected >= 1, "{report:?}");
    // Rejected results do not count, but the three honest operators still verify.
    assert!(
        report
            .records
            .iter()
            .all(|(_, r)| r.status == TaskStatus::Verified)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_results_are_rejected() {
    // The adversary re-sends its previous signed result instead of answering. Identical
    // bytes from the same author share a gossip message id, so the transport drops them as
    // duplicates; the application replay cache is a second layer (unit-tested). Either way
    // a replayed result is never accepted for a new task.
    let report = run_with("replay").await;
    let adversary_accepted = report
        .records
        .iter()
        .flat_map(|(_, r)| r.accepted.iter())
        .filter(|a| a.operator.as_str() == "org-m")
        .count();
    assert!(
        adversary_accepted <= 1,
        "only the first (honest) answer may be accepted: {report:?}"
    );
    assert!(
        report
            .records
            .iter()
            .all(|(_, r)| r.status == TaskStatus::Verified)
    );
}
