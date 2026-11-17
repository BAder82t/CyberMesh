//! Independent verifiers at other organisations over real libp2p: each follows the
//! coordinator's tasks and the workers' results, settles every task with its own engine and
//! key, and a release with a verifier quorum of 2 needs both.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::time::Duration;

use cybermesh_crypto::Digest;
use cybermesh_intelligence::{Action, BuildParams, EvidenceKind, build_release};
use cybermesh_protocol::{Clock, SystemClock};
use cybermesh_tests::{Harness, LEXICAL, Options, PHISH};
use cybermesh_verifier::{FaultKind, TaskStatus, VerificationRecord};

fn params(network_id: &str, min_verifiers: usize) -> BuildParams {
    BuildParams {
        network_id: network_id.to_owned(),
        sequence: 1,
        previous: None,
        issued_at: SystemClock.now(),
        ttl_secs: 86_400,
        max_record_age_secs: 86_400,
        min_verifiers,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_independent_verifier_completes_the_release_quorum() {
    let h = Harness::start(Options {
        independent_verifiers: 1,
        min_verifiers: 2,
        ..Options::default()
    });
    let (net, report, _, verifiers, _dir) = h.finish_all(Duration::from_secs(150)).await;
    let v = &verifiers[0];
    assert_eq!(v.operator, "org-b");
    assert!(v.verified >= 1, "{v:?}");
    assert_eq!(v.faults, 0);

    // Its records are its own: signed identity org-b, digests distinct from the
    // coordinator's even for the same tasks.
    assert!(
        v.records
            .iter()
            .all(|(_, r)| r.verifier.operator.as_str() == "org-b")
    );
    assert!(
        report
            .records
            .iter()
            .all(|(_, r)| r.verifier.operator.as_str() == "org-a")
    );
    let coord_digests: BTreeSet<Digest> = report.records.iter().map(|(d, _)| *d).collect();
    assert!(v.records.iter().all(|(d, _)| !coord_digests.contains(d)));
    // It verified the same tasks the coordinator did, recomputing them itself.
    let coord_tasks: BTreeSet<&str> = report
        .records
        .iter()
        .filter(|(_, r)| r.status == TaskStatus::Verified)
        .map(|(_, r)| r.task_id.as_str())
        .collect();
    let own: Vec<&VerificationRecord> = v
        .records
        .iter()
        .filter(|(_, r)| r.status == TaskStatus::Verified)
        .map(|(_, r)| r)
        .collect();
    assert!(own.iter().all(|r| r.recomputed));
    assert!(own.iter().all(|r| coord_tasks.contains(r.task_id.as_str())));

    // Quorum 2: the coordinator's records alone publish nothing ...
    let alone = build_release(&report.records, &[], &params(&net.network_id, 2)).unwrap();
    assert!(alone.entries.is_empty(), "{:?}", alone.entries);
    // ... with the independent verifier's records the release is the usual one.
    let both: Vec<_> = report
        .records
        .iter()
        .chain(v.records.iter())
        .cloned()
        .collect();
    let rel = build_release(&both, &[], &params(&net.network_id, 2)).unwrap();
    assert_eq!(rel.lookup(PHISH).map(|e| e.action), Some(Action::Block));
    assert_eq!(rel.lookup(LEXICAL).map(|e| e.action), Some(Action::Warn));
    assert!(rel.lookup("www.google.com").is_none());
    assert!(rel.lookup("mail.example.org").is_none());
    // Records were exchanged over the network: each organisation received all of the other's.
    let digests = |v: &[(Digest, VerificationRecord)]| -> BTreeSet<Digest> {
        v.iter().map(|(d, _)| *d).collect()
    };
    assert_eq!(
        digests(&report.received),
        digests(&v.records),
        "coordinator received all of org-b's records"
    );
    assert_eq!(
        digests(&v.received),
        digests(&report.records),
        "org-b received all of the coordinator's records"
    );
    assert!(report.records_published >= report.records.len() as u64);
    assert_eq!(report.records_refused + v.records_refused, 0);
    // So each organisation builds the release from its own node alone, with identical bytes.
    let at_a: Vec<_> = report
        .records
        .iter()
        .chain(report.received.iter())
        .cloned()
        .collect();
    let at_b: Vec<_> = v.records.iter().chain(v.received.iter()).cloned().collect();
    let p = params(&net.network_id, 2);
    let rel_a = build_release(&at_a, &[], &p).unwrap();
    let rel_b = build_release(&at_b, &[], &p).unwrap();
    assert_eq!(
        cybermesh_crypto::canonical::to_vec(&rel_a).unwrap(),
        cybermesh_crypto::canonical::to_vec(&rel_b).unwrap()
    );
    assert_eq!(rel_a, rel);
    // Each entry cites a record from each verifier.
    let e = rel.lookup(PHISH).unwrap();
    let cited: BTreeSet<Digest> = e
        .evidence
        .iter()
        .filter(|r| r.kind == EvidenceKind::Verification)
        .map(|r| r.digest)
        .collect();
    assert!(cited.iter().any(|d| coord_digests.contains(d)));
    assert!(cited.iter().any(|d| v.records.iter().any(|(x, _)| x == d)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_verifiers_prove_faults_themselves() {
    let h = Harness::start(Options {
        operators: vec![("org-a", 1), ("org-b", 1), ("org-c", 1), ("org-m", 1)],
        adversaries: vec![(3, "flip-verdicts")],
        replication: 4,
        result_timeout: Duration::from_secs(5),
        independent_verifiers: 2,
        min_verifiers: 3,
        ..Options::default()
    });
    let (net, report, _, verifiers, _dir) = h.finish_all(Duration::from_secs(150)).await;
    assert_eq!(verifiers.len(), 2);
    for v in &verifiers {
        let kinds: Vec<FaultKind> = v
            .records
            .iter()
            .flat_map(|(_, r)| r.faults.iter())
            .filter(|f| f.operator.as_str() == "org-m")
            .map(|f| f.kind)
            .collect();
        assert!(
            kinds.contains(&FaultKind::IncorrectResult),
            "{} did not catch the forged verdicts: {v:?}",
            v.operator
        );
    }
    // Three verifier operators, quorum 3: the release built at organisation A from its own
    // node (own records plus those received over the network) is still correct.
    let all: Vec<_> = report
        .records
        .iter()
        .chain(report.received.iter())
        .cloned()
        .collect();
    let rel = build_release(&all, &[], &params(&net.network_id, 3)).unwrap();
    let summary: Vec<_> = verifiers
        .iter()
        .map(|v| {
            (
                v.operator.clone(),
                v.tasks_seen,
                v.verified,
                v.insufficient,
                v.results_accepted,
                v.results_buffered_early,
                v.results_dropped,
                v.net_dropped_rate_limited + v.net_dropped_queue_full,
            )
        })
        .collect();
    assert_eq!(
        rel.lookup(PHISH).map(|e| e.action),
        Some(Action::Block),
        "coordinator verified {} insufficient {} reassignments {}; verifiers (op, seen, verified, insufficient, accepted, early, dropped, net dropped): {summary:?}",
        report.verified,
        report.insufficient,
        report.reassignments
    );
    assert!(rel.lookup("www.google.com").is_none());
    assert!(rel.lookup("mail.example.org").is_none());
}
