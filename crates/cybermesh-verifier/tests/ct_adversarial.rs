//! CT shard-scan verification against a mock log with real certificates.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use cybermesh_analysis::{Engine, EvidenceBundle, engine_spec};
use cybermesh_crypto::{Digest, canonical};
use cybermesh_ct::mock::{MockEntry, MockLog};
use cybermesh_ct::{TileSource, scan_tile, scan_tiles};
use cybermesh_protocol::ct::{CtMatch, CtScanResult, CtScanTask, TileScanResult};
use cybermesh_protocol::testkit::{TestNetwork, sign_bytes};
use cybermesh_protocol::*;
use cybermesh_verifier::ct::{CtOracle, CtPolicy, CtTaskVerifier};
use cybermesh_verifier::*;

const NOW: u64 = 1_800_000_000;
const LOOKALIKE: &str = "examplebank-account-verify.example.net";
const FEED_LISTED: &str = "examplebank-secure-login.phish.localhost";

fn engine() -> Engine {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../datasets/demo/evidence");
    Engine::new(EvidenceBundle::load(&dir).unwrap())
}

/// 4 tiles; tile 1 holds a lookalike and a feed-listed phishing host, tile 3 another lookalike.
fn log() -> MockLog {
    let entries: Vec<MockEntry> = (0..1024)
        .map(|i| MockEntry {
            names: match i {
                300 => vec![LOOKALIKE.into()],
                301 => vec![FEED_LISTED.into()],
                900 => vec!["paypa1-billing-update.com".into()],
                _ => vec![format!("host{i}.example-org.com")],
            },
            precert: i % 2 == 0,
        })
        .collect();
    MockLog::build("ct.example/test", &entries).unwrap()
}

struct Oracle<'a> {
    log: &'a MockLog,
    engine: &'a Engine,
}

impl CtOracle for Oracle<'_> {
    fn tile_root(&self, _log: &str, tile: u64) -> Option<Digest> {
        self.log.tile_root(tile, 1024).ok().map(Digest)
    }
    fn rescan(&self, _log: &str, tile: u64) -> Option<TileScanResult> {
        scan_tile(&self.log.data_tile(tile).ok()?, tile, self.engine).ok()
    }
}

struct Fx {
    net: TestNetwork,
    log: MockLog,
    engine: Engine,
    task: CtScanTask,
    digest: Digest,
    honest: Vec<TileScanResult>,
}

/// Operators a, b, c, m; workers 0..=3.
fn fx(assignees: &[usize]) -> Fx {
    let net = TestNetwork::new(
        &[("org-a", 1), ("org-b", 1), ("org-c", 1), ("org-m", 1)],
        NOW,
    );
    let engine = engine();
    let log = log();
    let task = CtScanTask {
        v: PROTOCOL_VERSION,
        network_id: net.network_id.clone(),
        task_id: "0123456789abcdef0123456789abcdef".into(),
        attempt: 0,
        issuer: net.issuer.key_id(),
        issued_at: NOW,
        expires_at: NOW + 600,
        nonce: "fedcba9876543210fedcba9876543210".into(),
        engine: engine_spec(),
        evidence: engine.evidence().pins.clone(),
        log_id: "mock-log".into(),
        first_tile: 0,
        tile_count: 4,
        assignees: assignees.iter().map(|i| net.worker_id(*i)).collect(),
        min_operators: 2,
    };
    let digest = Digest::of(&canonical::to_vec(&task).unwrap());
    let (honest, _) = scan_tiles(&log, 0, 4, &engine).unwrap();
    Fx {
        net,
        log,
        engine,
        task,
        digest,
        honest,
    }
}

impl Fx {
    fn result(&self, w: usize, tiles: Vec<TileScanResult>) -> Vec<u8> {
        let r = CtScanResult {
            v: PROTOCOL_VERSION,
            network_id: self.net.network_id.clone(),
            task_id: self.task.task_id.clone(),
            attempt: 0,
            task_digest: self.digest,
            input_digest: self.task.input_digest().unwrap(),
            worker: self.net.worker_id(w),
            operator: self.net.workers[w].operator.clone(),
            engine: engine_spec(),
            evidence: self.task.evidence.clone(),
            log_id: "mock-log".into(),
            tiles,
            completed_at: NOW + 1,
            nonce: format!("{:032x}", w + 1),
            usage: ResourceUsage::default(),
            fetched_bytes: 0,
        };
        sign_bytes(payload_type::CT_RESULT, &r, &self.net.workers[w].key)
    }

    fn verifier(&self, spot: usize) -> CtTaskVerifier {
        CtTaskVerifier::new(
            self.task.clone(),
            self.digest,
            CtPolicy {
                spot_check_tiles: spot,
                publish_warnings: true,
                publish_min_score_bp: 4000,
                ..CtPolicy::default()
            },
            Policy::default(),
            Limits::default(),
        )
        .unwrap()
    }

    fn oracle(&self) -> Oracle<'_> {
        Oracle {
            log: &self.log,
            engine: &self.engine,
        }
    }
}

fn names(rec: &VerificationRecord) -> Vec<String> {
    rec.outcomes.iter().map(|o| o.domain.clone()).collect()
}

#[test]
fn honest_shard_is_verified_and_findings_are_advisory_only() {
    let f = fx(&[0, 1]);
    let mut v = f.verifier(1);
    for w in [0, 1] {
        assert_eq!(
            v.submit(&f.result(w, f.honest.clone()), &f.net.manifest, NOW + 2),
            SubmitOutcome::Accepted
        );
    }
    let rec = v.finalize(Some(&f.engine), Some(&f.oracle()), b"seed", NOW + 3);
    assert_eq!(rec.status, TaskStatus::Verified);
    assert!(rec.faults.is_empty());
    let ct = rec.ct.as_ref().unwrap();
    assert_eq!(ct.tiles_checked_against_log, 4);
    assert_eq!(ct.entries, 1024);
    // Typosquats/homographs are published (when enabled); a brand token merely appearing
    // in a name is not, even if feed-listed: CT evidence is advisory and conservative.
    assert!(
        names(&rec).contains(&"paypa1-billing-update.com".to_owned()),
        "{:?}",
        names(&rec)
    );
    assert!(!names(&rec).contains(&LOOKALIKE.to_owned()));
    assert!(
        rec.outcomes
            .iter()
            .all(|o| o.classification == Classification::Warn)
    );
    assert!(
        ct.matches.iter().any(|m| m.name == LOOKALIKE),
        "kept for investigation"
    );
}

#[test]
fn by_default_ct_findings_are_for_investigation_only() {
    let f = fx(&[0, 1]);
    let mut v = CtTaskVerifier::new(
        f.task.clone(),
        f.digest,
        CtPolicy::default(),
        Policy::default(),
        Limits::default(),
    )
    .unwrap();
    for w in [0, 1] {
        v.submit(&f.result(w, f.honest.clone()), &f.net.manifest, NOW + 2);
    }
    let rec = v.finalize(Some(&f.engine), Some(&f.oracle()), b"seed", NOW + 3);
    assert_eq!(rec.status, TaskStatus::Verified);
    assert!(rec.outcomes.is_empty());
    assert!(!rec.ct.unwrap().matches.is_empty());
}

#[test]
fn omitted_matches_are_caught_by_spot_checks() {
    let f = fx(&[0, 1, 3]);
    let mut v = f.verifier(4); // spot-check every tile
    for w in [0, 1] {
        v.submit(&f.result(w, f.honest.clone()), &f.net.manifest, NOW + 2);
    }
    let mut lying = f.honest.clone();
    lying[1].matches.clear(); // hide the lookalikes in tile 1
    v.submit(&f.result(3, lying), &f.net.manifest, NOW + 2);
    let rec = v.finalize(Some(&f.engine), Some(&f.oracle()), b"seed", NOW + 3);
    assert_eq!(rec.status, TaskStatus::Verified);
    assert_eq!(rec.faults.len(), 1);
    assert_eq!(rec.faults[0].operator.as_str(), "org-m");
    assert!(names(&rec).contains(&"paypa1-billing-update.com".to_owned()));
}

#[test]
fn colluders_cannot_publish_a_fabricated_lookalike() {
    // Two operators agree on a fabricated match in a tile that is not spot-checked.
    let f = fx(&[2, 3]);
    let mut v = f.verifier(0);
    let mut forged = f.honest.clone();
    forged[2].matches.push(CtMatch {
        index: 2 * 256 + 7,
        name: "paypa1-login-verify.example-shop.net".into(),
        risk_score_bp: 5600,
        verdict: Verdict::Suspicious,
        codes: vec![FindingCode::BrandLookalike],
    });
    for w in [2, 3] {
        v.submit(&f.result(w, forged.clone()), &f.net.manifest, NOW + 2);
    }
    let rec = v.finalize(Some(&f.engine), Some(&f.oracle()), b"seed", NOW + 3);
    assert!(!names(&rec).contains(&"paypa1-login-verify.example-shop.net".to_owned()));
    assert_eq!(
        rec.faults.len(),
        2,
        "both colluders proven wrong by the confirming rescan"
    );
    assert_eq!(rec.status, TaskStatus::Insufficient);
}

#[test]
fn wrong_tile_root_is_caught_against_the_log() {
    let f = fx(&[0, 1, 3]);
    let mut v = f.verifier(0);
    for w in [0, 1] {
        v.submit(&f.result(w, f.honest.clone()), &f.net.manifest, NOW + 2);
    }
    let mut lazy = f.honest.clone();
    lazy[3].root = Digest::of(b"did not download tile 3");
    v.submit(&f.result(3, lazy), &f.net.manifest, NOW + 2);
    let rec = v.finalize(Some(&f.engine), Some(&f.oracle()), b"seed", NOW + 3);
    assert_eq!(rec.faults.len(), 1);
    assert_eq!(rec.faults[0].kind, FaultKind::IncorrectResult);
    assert_eq!(rec.status, TaskStatus::Verified);
}

#[test]
fn without_log_access_disagreement_is_disputed_and_nothing_is_published() {
    let f = fx(&[0, 3]);
    let mut v = f.verifier(1);
    v.submit(&f.result(0, f.honest.clone()), &f.net.manifest, NOW + 2);
    let mut other = f.honest.clone();
    other[0].matches.clear();
    other[1].matches.clear();
    v.submit(&f.result(3, other), &f.net.manifest, NOW + 2);
    let rec = v.finalize(Some(&f.engine), None, b"seed", NOW + 3);
    assert_eq!(rec.status, TaskStatus::Disputed);
    assert!(rec.outcomes.is_empty());
    // Agreement without log access: matches are listed for investigation but nothing is
    // published, because publishable tiles cannot be confirmed.
    let mut v = f.verifier(1);
    for w in [0, 1] {
        v.submit(&f.result(w, f.honest.clone()), &f.net.manifest, NOW + 2);
    }
    let rec = v.finalize(Some(&f.engine), None, b"seed", NOW + 3);
    assert!(rec.outcomes.is_empty());
}

#[test]
fn binding_replay_and_equivocation() {
    let f = fx(&[0, 1]);
    let mut v = f.verifier(1);
    // Unassigned worker.
    assert!(matches!(
        v.submit(&f.result(2, f.honest.clone()), &f.net.manifest, NOW + 2),
        SubmitOutcome::Rejected(_)
    ));
    // Missing a tile.
    let mut short = f.honest.clone();
    short.pop();
    assert!(matches!(
        v.submit(&f.result(0, short), &f.net.manifest, NOW + 2),
        SubmitOutcome::Fault(FaultKind::DomainSetMismatch)
    ));
    // Equivocation.
    let ok = f.result(1, f.honest.clone());
    assert_eq!(
        v.submit(&ok, &f.net.manifest, NOW + 2),
        SubmitOutcome::Accepted
    );
    assert_eq!(
        v.submit(&ok, &f.net.manifest, NOW + 2),
        SubmitOutcome::Duplicate
    );
    let mut alt = f.honest.clone();
    alt[0].unparsed = 1;
    assert_eq!(
        v.submit(&f.result(1, alt), &f.net.manifest, NOW + 2),
        SubmitOutcome::Fault(FaultKind::Equivocation)
    );
    // A domain-task payload type is not a CT result.
    let bytes = sign_bytes(payload_type::RESULT, &f.task, &f.net.workers[1].key);
    assert!(matches!(
        v.submit(&bytes, &f.net.manifest, NOW + 2),
        SubmitOutcome::Rejected(_)
    ));
}
