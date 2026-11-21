//! Certificate Transparency monitoring end to end: a mock static CT log served over HTTP,
//! workers of independent operators scanning shards over real libp2p, verification against
//! the log, and advisory-only publication.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use cybermesh_ct::mock::{MockLog, MockRfc6962Log, demo_entries};
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
            min_verifiers: 1,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_independent_verifier_checks_ct_shards_against_the_log_itself() {
    let h = Harness::start(Options {
        independent_verifiers: 1,
        ..options(Some("omit-matches"))
    });
    let (net, report, _, verifiers, _dir) = h.finish_all(Duration::from_secs(150)).await;
    let v = &verifiers[0];
    let ct: Vec<_> = v
        .records
        .iter()
        .filter_map(|(_, r)| r.ct.as_ref().map(|c| (r, c)))
        .collect();
    assert!(!ct.is_empty(), "{v:?}");
    // Its own log checks and its own spot checks (its own secret seed).
    assert!(
        ct.iter()
            .all(|(_, c)| c.tiles_checked_against_log == c.tile_count)
    );
    assert!(ct.iter().all(|(_, c)| !c.tiles_rescanned.is_empty()));
    // The lying worker is caught by this verifier too.
    assert!(
        v.records
            .iter()
            .flat_map(|(_, r)| r.faults.iter())
            .any(|f| f.operator.as_str() == "org-m" && f.kind == FaultKind::IncorrectResult),
        "{v:?}"
    );
    // With a quorum of 2, the published CT warning needs both verifiers.
    let all: Vec<_> = report
        .records
        .iter()
        .chain(v.records.iter())
        .cloned()
        .collect();
    let rel = build_release(
        &all,
        &[],
        &BuildParams {
            network_id: net.network_id.clone(),
            sequence: 1,
            previous: None,
            issued_at: SystemClock.now(),
            ttl_secs: 86_400,
            max_record_age_secs: 86_400,
            min_verifiers: 2,
        },
    )
    .unwrap();
    assert_eq!(rel.lookup(LOOKALIKE).map(|e| e.action), Some(Action::Warn));
    assert!(rel.lookup(TOKEN_ONLY).is_none());
    assert!(ct.iter().any(|(r, _)| r.status == TaskStatus::Verified));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_coordinator_follows_a_growing_log() {
    // The log starts with 2 full tiles and gains 2 more while the network runs; the
    // coordinator follows it (verified, fresh, consistent checkpoints) until tile 4.
    let mut o = options(None);
    o.ct_log = Some(Arc::new(
        MockLog::build("ct.example/test", &demo_entries(2)).unwrap(),
    ));
    o.ct_tiles = 2;
    o.ct_follow = Some((Duration::from_millis(500), 4));
    o.ct_grow = Some((Duration::from_secs(3), 2));
    let h = Harness::start(o);
    let (_net, report, _, dir) = h.finish(Duration::from_secs(120)).await;
    assert_eq!(report.ct_tiles_verified, 4, "{report:?}");
    assert_eq!(report.ct_next_tile, 4);
    assert!(
        report.ct_checkpoints_verified >= 2,
        "it saw the log grow: {report:?}"
    );
    assert_eq!(report.ct_log_inconsistencies, 0);
    let mut tiles: Vec<u64> = report
        .records
        .iter()
        .filter_map(|(_, r)| r.ct.as_ref())
        .flat_map(|c| c.first_tile..c.first_tile + u64::from(c.tile_count))
        .collect();
    tiles.sort_unstable();
    tiles.dedup();
    assert_eq!(tiles, vec![0, 1, 2, 3]);
    // Progress was saved for a restart: everything below tile 4 is settled.
    let state: cybermesh_node::ct_follow::FollowState = serde_json::from_slice(
        &std::fs::read(dir.path().join("coordinator/ct-follow.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(state.resume_from, 4);
    assert_eq!(state.head.map(|h| h.size), Some(1024));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_log_that_rewrites_history_is_not_followed() {
    // After 3 s the log is replaced by a different, larger tree signed with the same key:
    // validly signed checkpoints that do not extend the accepted one.
    let mut o = options(None);
    o.ct_log = Some(Arc::new(
        MockLog::build("ct.example/test", &demo_entries(2)).unwrap(),
    ));
    o.ct_tiles = 2;
    o.ct_follow = Some((Duration::from_millis(500), 4));
    o.ct_grow = Some((Duration::from_secs(3), 2));
    o.ct_fork = true;
    let h = Harness::start(o);
    let (_net, report, _, _dir) = h.finish(Duration::from_secs(120)).await;
    assert!(report.ct_log_inconsistencies >= 3, "{report:?}");
    assert!(
        report.ct_follow_halted,
        "a bounded run ends instead of hanging"
    );
    assert_eq!(
        report.ct_next_tile, 2,
        "nothing scheduled from the rewritten tree"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verifiers_witness_a_growing_log_and_agree_on_one_view() {
    // The coordinator and an independent verifier poll, cosign and exchange checkpoints of a
    // log that grows while they run; every comparison shows one append-only log.
    let mut o = options(None);
    o.independent_verifiers = 1;
    o.ct_log = Some(Arc::new(
        MockLog::build("ct.example/test", &demo_entries(2)).unwrap(),
    ));
    o.ct_tiles = 2;
    o.ct_follow = Some((Duration::from_millis(500), 4));
    o.ct_grow = Some((Duration::from_secs(3), 2));
    o.ct_witness = Some(Duration::from_millis(300));
    // Long enough for the verifier's redial to reach the coordinator directly.
    o.verifier_idle_exit = Duration::from_secs(15);
    let h = Harness::start(o);
    let (_net, report, _, verifiers, dir) = h.finish_all(Duration::from_secs(150)).await;
    let c = report
        .ct_witness
        .as_ref()
        .expect("the coordinator witnesses");
    let v = verifiers[0]
        .ct_witness
        .as_ref()
        .expect("the verifier witnesses");
    assert!(c.published >= 1 && v.published >= 1, "{c:?} {v:?}");
    assert!(c.received >= 1 && v.received >= 1, "{c:?} {v:?}");
    assert!(c.consistent >= 1 && v.consistent >= 1, "{c:?} {v:?}");
    assert_eq!((c.split_views, v.split_views), (0, 0));
    assert!(!report.ct_follow_halted);
    assert_eq!(report.ct_tiles_verified, 4);
    assert!(dir.path().join("coordinator/ct-witness.json").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_log_showing_organisations_different_trees_is_proven_and_not_followed() {
    // One log key, two trees of the same size: the coordinator's organisation is served one,
    // the independent verifier's organisation the other. Neither can tell from its own view;
    // their exchanged checkpoints prove the split view on both sides.
    let mut o = options(None);
    o.independent_verifiers = 1;
    let log = MockLog::build("ct.example/test", &demo_entries(2)).unwrap();
    let info = log.log_info("mock-log", "http://127.0.0.1:9/");
    o.ct_log = Some(Arc::new(log));
    o.ct_verifier_view = Some(Arc::new(
        MockLog::build("ct.example/test", &demo_entries(2)).unwrap(),
    ));
    o.ct_tiles = 2;
    // Following waits for tile 4: the proven split view ends it first. The coordinator's
    // view only grows to tile 4 after 30 s, so a split view that is not proven fails the
    // assertions below, with the witnesses' counters, rather than timing out.
    o.ct_follow = Some((Duration::from_millis(500), 4));
    o.ct_grow = Some((Duration::from_secs(30), 2));
    o.ct_witness = Some(Duration::from_millis(300));
    // The verifier cannot recompute these tasks (another view) and would otherwise go idle
    // before its redial reaches the coordinator directly, on a slow machine.
    o.verifier_idle_exit = Duration::from_secs(15);
    let h = Harness::start(o);
    let (_net, report, _, verifiers, _dir) = h.finish_all(Duration::from_secs(150)).await;
    let c = report.ct_witness.as_ref().unwrap();
    let v = verifiers[0].ct_witness.as_ref().unwrap();
    assert!(
        report.ct_follow_halted,
        "coordinator {c:?}; verifier {v:?}; {report:?}"
    );
    assert_eq!(c.split_views, 1, "{c:?}");
    let ev: cybermesh_node::ct_witness::SplitViewEvidence =
        serde_json::from_slice(&std::fs::read(&c.proofs[0]).unwrap()).unwrap();
    assert!(ev.reported_by.is_some());
    // The proof stands on its own: the log's key is all that is needed to check it.
    let key = cybermesh_ct::LogKey::from_info(&info).unwrap();
    let (l, s) = ev.proof.verify(&key).unwrap();
    // Usually two roots for size 512; on a slow machine the coordinator's view may have
    // grown first, and the proof then shows its first 512 entries have another root.
    assert_eq!(s.size, 512, "{ev:?}");
    assert!(l.size == 512 || l.size == 1024, "{ev:?}");
    assert_eq!(v.split_views, 1, "{v:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_split_view_proven_before_a_restart_keeps_following_halted() {
    // The witness state says a split view of the followed log was proven before the
    // restart: following stays halted and nothing is scheduled from the log.
    let mut o = options(None);
    o.ct_tiles = 2;
    o.ct_follow = Some((Duration::from_millis(500), 4));
    o.ct_witness = Some(Duration::from_millis(300));
    o.ct_witness_state = Some(r#"{"logs":{"mock-log":{"head":null,"split":true}}}"#);
    let h = Harness::start(o);
    let (_net, report, _, _dir) = h.finish(Duration::from_secs(120)).await;
    assert!(report.ct_follow_halted, "{report:?}");
    assert_eq!(report.ct_next_tile, 0, "{report:?}");
    assert_eq!(report.ct_tiles_verified, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_coordinator_quarantines_workers_another_verifier_proves_lied() {
    // Every worker hides the lookalikes it finds, identically, so they agree and the
    // coordinator (no spot checks) accepts their result. The independent verifier's own spot
    // checks catch them; it publishes fault proofs, and the coordinator re-scans the log
    // itself before quarantining them.
    let mut o = options(None);
    o.operators = vec![("org-a", 1), ("org-b", 1), ("org-c", 1)];
    o.adversaries = vec![
        (0, "omit-matches"),
        (1, "omit-matches"),
        (2, "omit-matches"),
    ];
    o.independent_verifiers = 1;
    o.min_verifiers = 2;
    o.ct_policy = cybermesh_verifier::ct::CtPolicy {
        spot_check_tiles: 0,
        ..cybermesh_verifier::ct::CtPolicy::default()
    };
    o.verifier_ct_policy = Some(cybermesh_verifier::ct::CtPolicy {
        spot_check_tiles: 4,
        ..cybermesh_verifier::ct::CtPolicy::default()
    });
    o.verifier_idle_exit = Duration::from_secs(15);
    let h = Harness::start(o);
    let (_net, report, _, verifiers, dir) = h.finish_all(Duration::from_secs(150)).await;
    let v = &verifiers[0];
    assert!(v.faults >= 2, "the verifier caught the liars: {v:?}");
    assert!(v.fault_proofs_published >= 2, "{v:?}");
    assert!(
        report.peer_faults_confirmed >= 2,
        "confirmed {} refuted {} unconfirmed {} received {} dropped {}",
        report.peer_faults_confirmed,
        report.peer_faults_refuted,
        report.peer_faults_unconfirmed,
        report.peer_fault_proofs_received,
        report.peer_fault_proofs_dropped
    );
    assert_eq!(report.peer_faults_refuted, 0);
    // The workers are quarantined at the coordinator, with the proofs kept as evidence.
    let book: cybermesh_verifier::ReputationBook = serde_json::from_slice(
        &std::fs::read(dir.path().join("coordinator/reputation.json")).unwrap(),
    )
    .unwrap();
    let quarantined = book.workers.values().filter(|w| w.quarantined).count();
    assert!(quarantined >= 2, "{book:?}");
    let proofs = std::fs::read_dir(dir.path().join("coordinator/faults"))
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("peer-")
        })
        .count();
    assert!(proofs >= 2);
}

/// The same scenario as `options`, over a classic RFC 6962 log (`get-sth`, `get-entries`,
/// audit paths) instead of a static CT log.
fn classic_options(adversary: Option<&'static str>) -> Options {
    Options {
        ct_log: None,
        ct_classic_log: Some(Arc::new(
            MockRfc6962Log::build("ct.example/classic", &demo_entries(4)[..1024]).unwrap(),
        )),
        ..options(adversary)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ct_monitoring_over_a_classic_log() {
    let h = Harness::start(classic_options(None));
    let (net, report, statuses, _dir) = h.finish(Duration::from_secs(120)).await;
    // Every tile root is proven against the signed tree head with an audit path.
    assert_eq!(report.ct_tiles_verified, 4, "{report:?}");
    assert_eq!(report.ct_entries_verified, 1024);
    assert!(report.ct_matches > 0);
    assert_eq!(report.faults, 0);
    assert!(statuses.iter().map(|s| s.ct_bytes_fetched).sum::<u64>() > 0);
    let rel = release(&report, &net.network_id);
    assert_eq!(rel.lookup(LOOKALIKE).map(|e| e.action), Some(Action::Warn));
    assert!(rel.lookup(TOKEN_ONLY).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_independent_verifier_checks_classic_ct_shards_against_the_log_itself() {
    let h = Harness::start(Options {
        independent_verifiers: 1,
        ..classic_options(Some("omit-matches"))
    });
    let (_net, _report, _, verifiers, _dir) = h.finish_all(Duration::from_secs(150)).await;
    let v = &verifiers[0];
    let ct: Vec<_> = v
        .records
        .iter()
        .filter_map(|(_, r)| r.ct.as_ref())
        .collect();
    assert!(!ct.is_empty(), "{v:?}");
    // Its own log checks and spot checks, through the classic API.
    assert!(
        ct.iter()
            .all(|c| c.tiles_checked_against_log == c.tile_count)
    );
    assert!(ct.iter().all(|c| !c.tiles_rescanned.is_empty()));
    // The lying worker is caught against the log's own entries.
    assert!(
        v.records
            .iter()
            .flat_map(|(_, r)| r.faults.iter())
            .any(|f| f.operator.as_str() == "org-m" && f.kind == FaultKind::IncorrectResult),
        "{v:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn classic_logs_are_followed_and_witnessed_as_they_grow() {
    // The coordinator and a verifier follow a classic log that grows, prove each new tree
    // head extends the last with `get-sth-consistency`, cosign it and compare their views.
    let mut o = classic_options(None);
    o.independent_verifiers = 1;
    o.ct_classic_log = Some(Arc::new(
        MockRfc6962Log::build("ct.example/classic", &demo_entries(2)).unwrap(),
    ));
    o.ct_tiles = 2;
    o.ct_follow = Some((Duration::from_millis(500), 4));
    o.ct_grow = Some((Duration::from_secs(3), 2));
    o.ct_witness = Some(Duration::from_millis(300));
    o.verifier_idle_exit = Duration::from_secs(15);
    let h = Harness::start(o);
    let (_net, report, _, verifiers, dir) = h.finish_all(Duration::from_secs(150)).await;
    let c = report
        .ct_witness
        .as_ref()
        .expect("the coordinator witnesses");
    let v = verifiers[0]
        .ct_witness
        .as_ref()
        .expect("the verifier witnesses");
    assert!(c.published >= 1 && v.published >= 1, "{c:?} {v:?}");
    assert!(c.consistent >= 1 && v.consistent >= 1, "{c:?} {v:?}");
    assert_eq!((c.split_views, v.split_views), (0, 0));
    assert!(!report.ct_follow_halted);
    assert_eq!(report.ct_tiles_verified, 4, "{report:?}");
    assert!(dir.path().join("coordinator/ct-witness.json").exists());
}
