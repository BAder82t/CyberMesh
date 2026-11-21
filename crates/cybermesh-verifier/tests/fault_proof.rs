//! Fault proofs: another organisation confirms a worker's fault from the evidence itself,
//! never on the reporter's word.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use cybermesh_analysis::{Brand, Engine, EvidenceBundle, engine_spec};
use cybermesh_crypto::{Digest, canonical};
use cybermesh_ct::mock::{MockEntry, MockLog};
use cybermesh_ct::{TileSource, scan_tile, scan_tiles};
use cybermesh_protocol::ct::{CtScanResult, CtScanTask, TileScanResult};
use cybermesh_protocol::testkit::{TestNetwork, sign_bytes, test_key};
use cybermesh_protocol::*;
use cybermesh_verifier::ct::CtOracle;
use cybermesh_verifier::fault_proof::{
    Check, FaultProof, check_fault_proof, sign_fault_proof, verify_fault_proof,
};
use cybermesh_verifier::*;

const NOW: u64 = 1_800_000_000;
const PHISH: &str = "examplebank-secure-login.phish.localhost";

fn net() -> TestNetwork {
    TestNetwork::new(
        &[("org-a", 1), ("org-b", 1), ("org-c", 1), ("org-m", 1)],
        NOW,
    )
}

fn evidence(feed: &[&str]) -> EvidenceBundle {
    EvidenceBundle {
        blocklists: vec![(
            "reference-feed".into(),
            feed.iter().map(|s| (*s).to_owned()).collect(),
        )],
        popular: HashSet::from(["google.com".to_owned()]),
        hosting_platforms: HashSet::new(),
        ct_logs: vec![],
        brands: vec![Brand {
            name: "examplebank".into(),
            tokens: vec!["examplebank".into()],
            legitimate: vec!["examplebank.test".into()],
        }],
        pins: BTreeMap::from([(
            "reference-feed".into(),
            Digest::of(feed.join("\n").as_bytes()),
        )]),
        sources: vec![],
        skipped_lines: 0,
    }
}

fn digest_of<T: serde::Serialize>(v: &T) -> Digest {
    Digest::of(&canonical::to_vec(v).unwrap())
}

/// A proof by `n`'s own verifier against `worker`, with the given results.
fn proof(
    n: &TestNetwork,
    kind: FaultKind,
    worker: usize,
    task: &[u8],
    results: &[(Digest, Vec<u8>)],
) -> FaultProof {
    FaultProof {
        v: PROTOCOL_VERSION,
        network_id: n.network_id.clone(),
        reporter: n.verifier.key_id(),
        reported_at: NOW + 10,
        fault: FaultRecord {
            worker: n.worker_id(worker),
            operator: n.workers[worker].operator.clone(),
            kind,
            evidence: results.iter().map(|(d, _)| *d).collect(),
        },
        task: String::from_utf8(task.to_vec()).unwrap(),
        results: results
            .iter()
            .map(|(_, b)| String::from_utf8(b.clone()).unwrap())
            .collect(),
    }
}

struct Domain {
    n: TestNetwork,
    engine: Engine,
    task: TaskAnnouncement,
    task_bytes: Vec<u8>,
}

fn domain() -> Domain {
    let n = net();
    let engine = Engine::new(evidence(&[PHISH]));
    let task = n.task(
        &[PHISH, "mailservice.example.com"],
        &[0, 1, 2],
        engine_spec(),
        engine.evidence().pins.clone(),
        NOW,
    );
    let task_bytes = sign_bytes(payload_type::TASK, &task, &n.issuer);
    Domain {
        n,
        engine,
        task,
        task_bytes,
    }
}

impl Domain {
    fn result(&self, w: usize) -> TaskResult {
        TaskResult {
            v: PROTOCOL_VERSION,
            network_id: self.n.network_id.clone(),
            task_id: self.task.task_id.clone(),
            attempt: self.task.attempt,
            task_digest: digest_of(&self.task),
            input_digest: self.task.input_digest().unwrap(),
            worker: self.n.worker_id(w),
            operator: self.n.workers[w].operator.clone(),
            engine: engine_spec(),
            evidence: self.task.evidence.clone(),
            assessments: self.engine.assess_task(&self.task).unwrap(),
            completed_at: NOW + 2,
            nonce: format!("{:032x}", w + 1),
            usage: ResourceUsage::default(),
        }
    }

    fn signed(&self, w: usize, r: &TaskResult) -> (Digest, Vec<u8>) {
        (
            digest_of(r),
            sign_bytes(payload_type::RESULT, r, &self.n.workers[w].key),
        )
    }

    fn check(&self, p: &FaultProof, engine: Option<&Engine>) -> Check {
        check_fault_proof(
            p,
            &self.n.manifest,
            engine,
            None,
            &Limits::default(),
            NOW + 20,
        )
    }
}

fn confirmed(c: &Check) -> bool {
    matches!(c, Check::Confirmed(_))
}

#[test]
fn equivocation_and_mismatched_results_are_confirmed_from_signatures_alone() {
    let d = domain();
    let honest = d.signed(0, &d.result(0));
    let mut other = d.result(0);
    other.nonce = format!("{:032x}", 99);
    other.assessments[0].risk_score_bp = 1;
    let other = d.signed(0, &other);
    // Two different signed claims for one task attempt: no engine needed.
    let p = proof(
        &d.n,
        FaultKind::Equivocation,
        0,
        &d.task_bytes,
        &[honest.clone(), other],
    );
    assert!(confirmed(&d.check(&p, None)), "{:?}", d.check(&p, None));
    // The same answer signed again (re-run after a restart, new nonce) is not equivocation.
    let mut resent = d.result(0);
    resent.nonce = format!("{:032x}", 98);
    resent.completed_at += 30;
    let p = proof(
        &d.n,
        FaultKind::Equivocation,
        0,
        &d.task_bytes,
        &[honest.clone(), d.signed(0, &resent)],
    );
    assert!(matches!(d.check(&p, None), Check::Refuted(_)));
    // Evidence from a task long expired is not acted on, however fresh the proof.
    let old = check_fault_proof(
        &p,
        &d.n.manifest,
        None,
        None,
        &Limits::default(),
        NOW + 30 * 86_400,
    );
    assert!(matches!(old, Check::Unconfirmed(_)), "{old:?}");
    let p = proof(
        &d.n,
        FaultKind::Equivocation,
        0,
        &d.task_bytes,
        std::slice::from_ref(&honest),
    );
    assert!(matches!(d.check(&p, None), Check::Refuted(_)));

    // A wrong input digest, or other domains than the task's.
    let mut wrong = d.result(1);
    wrong.input_digest = Digest::of(b"another input");
    let p = proof(
        &d.n,
        FaultKind::WrongInputDigest,
        1,
        &d.task_bytes,
        &[d.signed(1, &wrong)],
    );
    assert!(confirmed(&d.check(&p, None)));
    let mut fewer = d.result(1);
    fewer.assessments.pop();
    let p = proof(
        &d.n,
        FaultKind::DomainSetMismatch,
        1,
        &d.task_bytes,
        &[d.signed(1, &fewer)],
    );
    assert!(confirmed(&d.check(&p, None)));
    // The same claims against an honest result are refuted.
    for kind in [FaultKind::WrongInputDigest, FaultKind::DomainSetMismatch] {
        let p = proof(&d.n, kind, 0, &d.task_bytes, std::slice::from_ref(&honest));
        assert!(matches!(d.check(&p, None), Check::Refuted(_)), "{kind:?}");
    }
}

#[test]
fn an_incorrect_result_is_confirmed_only_by_the_checkers_own_recomputation() {
    let d = domain();
    let mut lie = d.result(2);
    for a in &mut lie.assessments {
        a.verdict = Verdict::NoSignal;
        a.risk_score_bp = 0;
        a.findings.clear();
    }
    let lie = d.signed(2, &lie);
    let p = proof(&d.n, FaultKind::IncorrectResult, 2, &d.task_bytes, &[lie]);
    assert!(confirmed(&d.check(&p, Some(&d.engine))));
    // Without the pinned engine and evidence the checker cannot decide: nothing happens.
    assert!(matches!(d.check(&p, None), Check::Unconfirmed(_)));
    let other = Engine::new(evidence(&[PHISH, "another.example"]));
    assert!(matches!(d.check(&p, Some(&other)), Check::Unconfirmed(_)));
    // A false accusation against an honest worker is refuted.
    let honest = d.signed(0, &d.result(0));
    let p = proof(
        &d.n,
        FaultKind::IncorrectResult,
        0,
        &d.task_bytes,
        &[honest],
    );
    assert!(matches!(d.check(&p, Some(&d.engine)), Check::Refuted(_)));
}

#[test]
fn evidence_must_be_the_accused_workers_own_results_for_this_task() {
    let d = domain();
    let r1 = d.signed(1, &d.result(1));
    // Worker 1's result presented as evidence against worker 0.
    let mut p = proof(
        &d.n,
        FaultKind::Equivocation,
        0,
        &d.task_bytes,
        &[r1.clone(), r1.clone()],
    );
    p.fault.evidence = vec![r1.0];
    assert!(matches!(d.check(&p, None), Check::Refuted(_)));
    // Digests that do not name the results presented.
    let mut p = proof(
        &d.n,
        FaultKind::IncorrectResult,
        1,
        &d.task_bytes,
        std::slice::from_ref(&r1),
    );
    p.fault.evidence = vec![Digest::of(b"something else")];
    assert!(matches!(d.check(&p, Some(&d.engine)), Check::Refuted(_)));
    // A worker not assigned the task.
    let r3 = d.signed(3, &d.result(3));
    let p = proof(&d.n, FaultKind::IncorrectResult, 3, &d.task_bytes, &[r3]);
    assert!(matches!(d.check(&p, Some(&d.engine)), Check::Refuted(_)));
    // A task this node's manifest does not know the issuer of: undecidable, not refuted.
    let unknown = sign_bytes(payload_type::TASK, &d.task, &test_key("another-issuer"));
    let p = proof(&d.n, FaultKind::IncorrectResult, 1, &unknown, &[r1]);
    assert!(matches!(
        d.check(&p, Some(&d.engine)),
        Check::Unconfirmed(_)
    ));
}

#[test]
fn proofs_are_signed_by_the_verifier_that_reports_them() {
    let d = domain();
    let r = d.signed(0, &d.result(0));
    let p = proof(
        &d.n,
        FaultKind::IncorrectResult,
        0,
        &d.task_bytes,
        std::slice::from_ref(&r),
    );
    let limits = Limits::default();
    let ok = sign_fault_proof(&p, &d.n.verifier).unwrap();
    let v = verify_fault_proof(&ok, &d.n.manifest, NOW + 20, &limits).unwrap();
    assert_eq!(v.message, p);
    // Not a verifier; another verifier's name; too old; too many results.
    let by_worker = sign_fault_proof(&p, &d.n.workers[0].key).unwrap();
    assert!(verify_fault_proof(&by_worker, &d.n.manifest, NOW + 20, &limits).is_err());
    let mut claimed = p.clone();
    claimed.reporter = d.n.other_verifiers[0].0.key_id();
    let bytes = sign_fault_proof(&claimed, &d.n.verifier).unwrap();
    assert_eq!(
        verify_fault_proof(&bytes, &d.n.manifest, NOW + 20, &limits).unwrap_err(),
        ProtocolError::SignerMismatch
    );
    assert_eq!(
        verify_fault_proof(&ok, &d.n.manifest, NOW + 8 * 86_400, &limits).unwrap_err(),
        ProtocolError::Expired
    );
    let mut three = p.clone();
    three.results = vec![three.results[0].clone(); 3];
    let bytes = sign_fault_proof(&three, &d.n.verifier).unwrap();
    assert!(verify_fault_proof(&bytes, &d.n.manifest, NOW + 20, &limits).is_err());
}

// ---------------------------------------------------------------------------------------
// CT: an incorrect result is confirmed by re-scanning the log.

struct Oracle<'a> {
    log: &'a MockLog,
    engine: &'a Engine,
}

impl CtOracle for Oracle<'_> {
    fn tile_root(&self, _log: &str, tile: u64) -> Option<Digest> {
        let info = self.log.log_info("mock-log", "http://127.0.0.1/");
        let cp = cybermesh_ct::checkpoint::fetch_verified_checkpoint(self.log, &info).ok()?;
        cybermesh_ct::authenticated_tile_root(self.log, &cp, tile)
            .ok()
            .map(Digest)
    }
    fn rescan(&self, _log: &str, tile: u64) -> Option<TileScanResult> {
        scan_tile(&self.log.data_tile(tile).ok()?, tile, self.engine).ok()
    }
}

#[test]
fn an_incorrect_ct_result_is_confirmed_by_rescanning_the_log() {
    let n = net();
    let engine = Engine::new(
        EvidenceBundle::load(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../datasets/demo/evidence"),
        )
        .unwrap(),
    );
    let entries: Vec<MockEntry> = (0..512)
        .map(|i| MockEntry {
            names: if i == 300 {
                vec!["paypa1-billing-update.com".into()]
            } else {
                vec![format!("host{i}.example-org.com")]
            },
            precert: false,
        })
        .collect();
    let log = MockLog::build("ct.example/test", &entries).unwrap();
    let task = CtScanTask {
        v: PROTOCOL_VERSION,
        network_id: n.network_id.clone(),
        task_id: "0123456789abcdef0123456789abcdef".into(),
        attempt: 0,
        issuer: n.issuer.key_id(),
        issued_at: NOW,
        expires_at: NOW + 600,
        nonce: "fedcba9876543210fedcba9876543210".into(),
        engine: engine_spec(),
        evidence: engine.evidence().pins.clone(),
        log_id: "mock-log".into(),
        first_tile: 0,
        tile_count: 2,
        assignees: [0, 1].iter().map(|i| n.worker_id(*i)).collect(),
        min_operators: 2,
    };
    let task_bytes = sign_bytes(payload_type::CT_TASK, &task, &n.issuer);
    let (honest, _) = scan_tiles(&log, 0, 2, &engine).unwrap();
    let result = |w: usize, tiles: Vec<TileScanResult>| {
        let r = CtScanResult {
            v: PROTOCOL_VERSION,
            network_id: n.network_id.clone(),
            task_id: task.task_id.clone(),
            attempt: 0,
            task_digest: digest_of(&task),
            input_digest: task.input_digest().unwrap(),
            worker: n.worker_id(w),
            operator: n.workers[w].operator.clone(),
            engine: engine_spec(),
            evidence: task.evidence.clone(),
            log_id: "mock-log".into(),
            tiles,
            completed_at: NOW + 1,
            nonce: format!("{:032x}", w + 1),
            usage: ResourceUsage::default(),
            fetched_bytes: 0,
        };
        (
            digest_of(&r),
            sign_bytes(payload_type::CT_RESULT, &r, &n.workers[w].key),
        )
    };
    // The worker hid the lookalike in tile 1 (its root is still right).
    let mut hidden = honest.clone();
    assert!(!hidden[1].matches.is_empty());
    hidden[1].matches.clear();
    let lie = result(1, hidden);
    let oracle = Oracle {
        log: &log,
        engine: &engine,
    };
    let check = |p: &FaultProof, o: Option<&dyn CtOracle>, e: Option<&Engine>| {
        check_fault_proof(p, &n.manifest, e, o, &Limits::default(), NOW + 20)
    };
    let p = proof(&n, FaultKind::IncorrectResult, 1, &task_bytes, &[lie]);
    assert!(confirmed(&check(&p, Some(&oracle), Some(&engine))));
    // Without log access, or with another engine, the checker cannot decide.
    assert!(matches!(
        check(&p, None, Some(&engine)),
        Check::Unconfirmed(_)
    ));
    assert!(matches!(
        check(&p, Some(&oracle), None),
        Check::Unconfirmed(_)
    ));
    // An honest worker accused falsely: every tile re-scans to its result.
    let p = proof(
        &n,
        FaultKind::IncorrectResult,
        0,
        &task_bytes,
        &[result(0, honest)],
    );
    assert!(matches!(
        check(&p, Some(&oracle), Some(&engine)),
        Check::Refuted(_)
    ));
}
