//! Certificate Transparency monitoring end to end: a mock static CT log served over HTTP,
//! workers of independent operators scanning shards over real libp2p, verification against
//! the log, and advisory-only publication.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use cybermesh_ct::mock::{MockLog, demo_entries};
use cybermesh_intelligence::{Action, BuildParams, build_release};
use cybermesh_protocol::{Clock, SystemClock};
use cybermesh_tests::{Harness, Options};
use cybermesh_verifier::{FaultKind, TaskStatus};

/// A typosquat of the protected brand (publishable when CT publishing is enabled).
const LOOKALIKE: &str = "examp1ebank-secure-login.example.net";
/// Brand token inside a name: investigation only, never published from CT.
const TOKEN_ONLY: &str = "examplebank-secure-login.example.net";

fn release(
    report: &cybermesh_node::coordinator::CoordinatorReport,
    network: &str,
) -> cybermesh_intelligence::ThreatRelease {
    build_release(
        &report.records,
        &[],
        &BuildParams {
            network_id: network.into(),
            sequence: 1,
            previous: None,
            issued_at: SystemClock.now(),
            ttl_secs: 86_400,
            max_record_age_secs: 86_400,
        },
    )
    .unwrap()
}

fn options(adversary: Option<&'static str>) -> Options {
    let mut operators = vec![("org-a", 1), ("org-b", 1), ("org-c", 1)];
    let mut adversaries = vec![];
    if let Some(m) = adversary {
        operators.push(("org-m", 1));
        adversaries.push((3, m));
    }
    Options {
        operators,
        adversaries,
        domains: vec![],
        ct_log: Some(Arc::new(
            MockLog::build("ct.example/test", &demo_entries(4)).unwrap(),
        )),
        ct_tiles: 4,
        ct_tiles_per_task: 2,
        ct_replication: if adversary.is_some() { 4 } else { 2 },
        ct_policy: cybermesh_verifier::ct::CtPolicy {
            publish_warnings: true,
            publish_min_score_bp: 4000,
            ..cybermesh_verifier::ct::CtPolicy::default()
        },
        result_timeout: Duration::from_secs(8),
        ..Options::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ct_monitoring_over_libp2p() {
    let h = Harness::start(options(None));
    let (net, report, statuses, _dir) = h.finish(Duration::from_secs(120)).await;
    assert_eq!(report.ct_tiles_verified, 4, "{report:?}");
    assert_eq!(report.ct_entries_verified, 1024);
    assert!(report.ct_matches > 0);
    assert_eq!(report.faults, 0);
    assert!(statuses.iter().map(|s| s.ct_bytes_fetched).sum::<u64>() > 0);
    let ct_records: Vec<_> = report
        .records
        .iter()
        .filter(|(_, r)| r.ct.is_some())
        .collect();
    assert!(
        ct_records
            .iter()
            .all(|(_, r)| r.status == TaskStatus::Verified)
    );
    assert!(
        ct_records
            .iter()
            .all(|(_, r)| r.ct.as_ref().unwrap().tiles_checked_against_log > 0)
    );
    let rel = release(&report, &net.network_id);
    let e = rel
        .lookup(LOOKALIKE)
        .expect("lookalike seen in CT is published");
    assert_eq!(e.action, Action::Warn);
    assert!(
        rel.entries.iter().all(|e| e.action == Action::Warn),
        "CT evidence never blocks"
    );
    assert!(
        rel.lookup(TOKEN_ONLY).is_none(),
        "brand token alone is investigation-only"
    );
    assert!(
        report
            .records
            .iter()
            .filter_map(|(_, r)| r.ct.as_ref())
            .flat_map(|c| c.matches.iter())
            .any(|m| m.name == TOKEN_ONLY),
        "kept in the investigation data"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worker_hiding_ct_matches_is_caught() {
    let h = Harness::start(options(Some("omit-matches")));
    let (net, report, _, _dir) = h.finish(Duration::from_secs(150)).await;
    let faults: Vec<_> = report
        .records
        .iter()
        .flat_map(|(_, r)| r.faults.iter())
        .collect();
    assert!(!faults.is_empty(), "{report:?}");
    assert!(
        faults
            .iter()
            .all(|f| f.operator.as_str() == "org-m" && f.kind == FaultKind::IncorrectResult)
    );
    assert!(
        release(&report, &net.network_id)
            .lookup(LOOKALIKE)
            .is_some(),
        "nothing lost"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fabricated_ct_match_is_never_published() {
    let h = Harness::start(options(Some("forge-ct-match")));
    let (net, report, _, _dir) = h.finish(Duration::from_secs(150)).await;
    let rel = release(&report, &net.network_id);
    assert!(
        rel.lookup("examp1ebank-login-verify.example-shop.net")
            .is_none()
    );
    let faults: Vec<_> = report
        .records
        .iter()
        .flat_map(|(_, r)| r.faults.iter())
        .collect();
    assert!(
        faults.iter().any(|f| f.operator.as_str() == "org-m"),
        "{report:?}"
    );
    assert!(rel.lookup(LOOKALIKE).is_some());
}
