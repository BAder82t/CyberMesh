//! Adversarial verification scenarios: forged, conflicting, colluding, equivocating,
//! replayed and Sybil submissions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, HashSet};

use cybermesh_analysis::{Brand, Engine, EvidenceBundle, engine_spec};
use cybermesh_crypto::{Digest, canonical};
use cybermesh_protocol::testkit::{TestNetwork, sign_bytes, test_key};
use cybermesh_protocol::*;
use cybermesh_verifier::*;

/// The test network's own verifier (operator `org-a`).
fn vid() -> VerifierId {
    VerifierId {
        key: test_key("verifier").key_id(),
        operator: OperatorId::new("org-a").unwrap(),
    }
}

const NOW: u64 = 1_800_000_000;
const PHISH: &str = "examplebank-secure-login.phish.localhost";
const LEXICAL: &str = "examplebank-account-verify.phish.localhost";
const BENIGN: &str = "mailservice.example.com";

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
        pins: BTreeMap::from([
            ("brands".into(), Digest::of(b"brands-v1")),
            (
                "reference-feed".into(),
                Digest::of(feed.join("\n").as_bytes()),
            ),
        ]),
        sources: vec![],
        skipped_lines: 0,
    }
}

struct Fixture {
    net: TestNetwork,
    engine: Engine,
    task: TaskAnnouncement,
    task_digest: Digest,
}

/// Operators: org-a (2 workers), org-b, org-c, org-m (malicious) => worker indices
/// 0,1 = org-a; 2 = org-b; 3 = org-c; 4 = org-m.
fn fixture(assignees: &[usize]) -> Fixture {
    let net = TestNetwork::new(
        &[("org-a", 2), ("org-b", 1), ("org-c", 1), ("org-m", 1)],
        NOW,
    );
    let engine = Engine::new(evidence(&[PHISH]));
    let task = net.task(
        &[PHISH, LEXICAL, BENIGN],
        assignees,
        engine_spec(),
        engine.evidence().pins.clone(),
        NOW,
    );
    let task_digest = Digest::of(&canonical::to_vec(&task).unwrap());
    Fixture {
        net,
        engine,
        task,
        task_digest,
    }
}

impl Fixture {
    fn honest(&self, w: usize) -> TaskResult {
        TaskResult {
            v: PROTOCOL_VERSION,
            network_id: self.net.network_id.clone(),
            task_id: self.task.task_id.clone(),
            attempt: 0,
            task_digest: self.task_digest,
            input_digest: self.task.input_digest().unwrap(),
            worker: self.net.worker_id(w),
            operator: self.net.workers[w].operator.clone(),
            engine: engine_spec(),
            evidence: self.task.evidence.clone(),
            assessments: self.engine.assess_task(&self.task).unwrap(),
            completed_at: NOW + 2,
            nonce: format!("{:032x}", w + 1),
            usage: ResourceUsage::default(),
        }
    }

    fn sign(&self, w: usize, r: &TaskResult) -> Vec<u8> {
        sign_bytes(payload_type::RESULT, r, &self.net.workers[w].key)
    }

    fn verifier(&self) -> TaskVerifier {
        TaskVerifier::new(
            self.task.clone(),
            self.task_digest,
            vid(),
            Policy::default(),
            Limits::default(),
        )
        .unwrap()
    }
}

fn classification(rec: &VerificationRecord, d: &str) -> Classification {
    rec.outcomes
        .iter()
        .find(|o| o.domain == d)
        .map_or(Classification::None, |o| o.classification)
}

/// Fake "malicious + feed-listed" claim for every domain.
fn forged_malicious(r: &mut TaskResult) {
    for a in &mut r.assessments {
        a.verdict = Verdict::Malicious;
        a.risk_score_bp = 10_000;
        a.confidence_bp = 9800;
        a.findings = vec![Finding {
            code: FindingCode::FeedMatch,
            points: 9000,
            detail: "listed in reference feed: reference-feed".into(),
        }];
    }
}

#[test]
fn honest_operators_produce_block_and_warn() {
    let f = fixture(&[0, 2, 3]);
    let mut v = f.verifier();
    for w in [0, 2, 3] {
        assert_eq!(
            v.submit(&f.sign(w, &f.honest(w)), &f.net.manifest, NOW + 3),
            SubmitOutcome::Accepted
        );
    }
    assert!(v.is_complete());
    let rec = v.finalize(Some(&f.engine), NOW + 5);
    assert_eq!(rec.status, TaskStatus::Verified);
    assert_eq!(classification(&rec, PHISH), Classification::Block);
    assert_eq!(classification(&rec, LEXICAL), Classification::Warn);
    assert_eq!(classification(&rec, BENIGN), Classification::None);
    assert!(rec.faults.is_empty());
}

#[test]
fn forged_signature_and_impersonation_are_rejected() {
    let f = fixture(&[0, 2, 3]);
    let mut v = f.verifier();
    // Unenrolled key signs a result claiming to be worker 2.
    let bytes = sign_bytes(payload_type::RESULT, &f.honest(2), &test_key("intruder"));
    assert!(matches!(
        v.submit(&bytes, &f.net.manifest, NOW + 3),
        SubmitOutcome::Rejected(_)
    ));
    // Enrolled worker 3 signs a result claiming to be worker 2.
    let bytes = sign_bytes(payload_type::RESULT, &f.honest(2), &f.net.workers[3].key);
    assert!(matches!(
        v.submit(&bytes, &f.net.manifest, NOW + 3),
        SubmitOutcome::Rejected(_)
    ));
    // Bit flip in the envelope signature.
    let mut env: cybermesh_crypto::Envelope =
        serde_json::from_slice(&f.sign(2, &f.honest(2))).unwrap();
    env.signatures[0].sig = env.signatures[0].sig.replacen('A', "B", 1);
    assert!(matches!(
        v.submit(&env.to_vec().unwrap(), &f.net.manifest, NOW + 3),
        SubmitOutcome::Rejected(_)
    ));
}

#[test]
fn single_malicious_worker_is_caught_by_recomputation() {
    let f = fixture(&[0, 2, 3, 4]);
    let mut v = f.verifier();
    for w in [0, 2, 3] {
        v.submit(&f.sign(w, &f.honest(w)), &f.net.manifest, NOW + 3);
    }
    let mut bad = f.honest(4);
    forged_malicious(&mut bad);
    assert_eq!(
        v.submit(&f.sign(4, &bad), &f.net.manifest, NOW + 3),
        SubmitOutcome::Accepted
    );
    let rec = v.finalize(Some(&f.engine), NOW + 5);
    assert!(rec.recomputed);
    assert_eq!(rec.status, TaskStatus::Verified);
    assert_eq!(rec.faults.len(), 1);
    assert_eq!(rec.faults[0].kind, FaultKind::IncorrectResult);
    assert_eq!(rec.faults[0].operator.as_str(), "org-m");
    assert_eq!(classification(&rec, BENIGN), Classification::None);

    let mut book = ReputationBook::default();
    book.apply(&rec);
    assert!(book.is_quarantined(&f.net.worker_id(4)));
    assert!(!book.is_quarantined(&f.net.worker_id(0)));
    assert!(book.score_per_mille(&f.net.worker_id(0)) > book.score_per_mille(&f.net.worker_id(4)));
}

#[test]
fn colluding_operators_cannot_cause_block() {
    // Three distinct operators collude and sign identical false "malicious, feed-listed"
    // claims for every domain, including the benign one.
    let f = fixture(&[2, 3, 4]);
    let forged = |w: usize| {
        let mut r = f.honest(w);
        forged_malicious(&mut r);
        f.sign(w, &r)
    };

    // (a) A verifier with the pinned evidence always recomputes and catches all three.
    let mut v = f.verifier();
    for w in [2, 3, 4] {
        v.submit(&forged(w), &f.net.manifest, NOW + 3);
    }
    let rec = v.finalize(Some(&f.engine), NOW + 5);
    assert!(rec.recomputed);
    assert_eq!(rec.faults.len(), 3);
    assert_eq!(rec.status, TaskStatus::Insufficient);
    assert_eq!(rec.publishable().count(), 0);

    // (b) A verifier without evidence cannot recompute: unanimous claims are accepted but can
    // only ever produce advisory warnings, never a block.
    let mut v = f.verifier();
    for w in [2, 3, 4] {
        v.submit(&forged(w), &f.net.manifest, NOW + 3);
    }
    let rec = v.finalize(None, NOW + 5);
    assert!(!rec.recomputed);
    assert_eq!(classification(&rec, BENIGN), Classification::Warn);
    assert!(
        rec.outcomes
            .iter()
            .all(|o| o.classification != Classification::Block)
    );
}

/// Regression for an audit finding: the reference feed lists a host on a popular domain
/// (a feed false positive). Colluders omit the popularity finding and claim "malicious".
/// The verifier must classify from its own assessment (known-benign), not the claim.
#[test]
fn colluders_cannot_turn_a_feed_false_positive_on_a_popular_domain_into_a_block() {
    let net = TestNetwork::new(&[("org-a", 1), ("org-b", 1), ("org-c", 1)], NOW);
    let mut ev = evidence(&["www.google.com"]);
    ev.popular.insert("google.com".into());
    let engine = Engine::new(ev);
    let task = net.task(
        &["www.google.com"],
        &[0, 1, 2],
        engine_spec(),
        engine.evidence().pins.clone(),
        NOW,
    );
    let task_digest = Digest::of(&canonical::to_vec(&task).unwrap());
    let honest = engine.assess("www.google.com").unwrap();
    assert_eq!(honest.verdict, Verdict::KnownBenign);
    let mut v = TaskVerifier::new(
        task.clone(),
        task_digest,
        vid(),
        Policy::default(),
        Limits::default(),
    )
    .unwrap();
    for w in 0..3 {
        let mut r = TaskResult {
            v: PROTOCOL_VERSION,
            network_id: net.network_id.clone(),
            task_id: task.task_id.clone(),
            attempt: 0,
            task_digest,
            input_digest: task.input_digest().unwrap(),
            worker: net.worker_id(w),
            operator: net.workers[w].operator.clone(),
            engine: engine_spec(),
            evidence: task.evidence.clone(),
            assessments: vec![honest.clone()],
            completed_at: NOW + 1,
            nonce: format!("{:032x}", w + 1),
            usage: ResourceUsage::default(),
        };
        forged_malicious(&mut r);
        v.submit(
            &sign_bytes(payload_type::RESULT, &r, &net.workers[w].key),
            &net.manifest,
            NOW + 2,
        );
    }
    let rec = v.finalize(Some(&engine), NOW + 3);
    assert!(rec.recomputed);
    assert_eq!(rec.faults.len(), 3);
    assert!(
        rec.outcomes
            .iter()
            .all(|o| o.classification != Classification::Block)
    );
}

#[test]
fn unsafe_policies_are_refused() {
    let f = fixture(&[0, 2, 3]);
    for p in [
        Policy {
            min_operators: 0,
            ..Policy::default()
        },
        Policy {
            warn_min_score_bp: 8000,
            block_min_score_bp: 7000,
            ..Policy::default()
        },
        Policy {
            warn_min_score_bp: 0,
            ..Policy::default()
        },
    ] {
        assert!(
            TaskVerifier::new(f.task.clone(), f.task_digest, vid(), p, Limits::default()).is_err()
        );
    }
}

#[test]
fn rejection_log_is_bounded_under_flooding() {
    let f = fixture(&[0, 2, 3]);
    let mut v = f.verifier();
    for i in 0..500u32 {
        let _ = v.submit(format!("garbage-{i}").as_bytes(), &f.net.manifest, NOW + 3);
    }
    let rec = v.finalize(Some(&f.engine), NOW + 5);
    assert_eq!(rec.rejected.len(), 64);
    assert_eq!(rec.rejected_overflow, 436);
}

#[test]
fn reputation_apply_is_idempotent() {
    let f = fixture(&[0, 2, 3]);
    let mut v = f.verifier();
    for w in [0, 2, 3] {
        v.submit(&f.sign(w, &f.honest(w)), &f.net.manifest, NOW + 3);
    }
    let rec = v.finalize(Some(&f.engine), NOW + 5);
    let mut book = ReputationBook::default();
    book.apply(&rec);
    book.apply(&rec);
    assert_eq!(book.workers[&f.net.worker_id(0)].agreed, 1);
}

#[test]
fn one_operator_with_many_workers_is_not_diverse() {
    // Workers 0 and 1 both belong to org-a: two keys, one organisation.
    let f = fixture(&[0, 1, 2]);
    let mut v = f.verifier();
    for w in [0, 1, 2] {
        v.submit(&f.sign(w, &f.honest(w)), &f.net.manifest, NOW + 3);
    }
    let rec = v.finalize(Some(&f.engine), NOW + 5);
    assert_eq!(
        rec.status,
        TaskStatus::Insufficient,
        "only 2 distinct operators"
    );
    assert_eq!(rec.publishable().count(), 0);
}

#[test]
fn equivocation_is_a_provable_fault() {
    let f = fixture(&[0, 2, 3]);
    let mut v = f.verifier();
    let r1 = f.honest(2);
    let mut r2 = f.honest(2);
    r2.nonce = "ffffffffffffffffffffffffffffffff".into();
    r2.assessments[0].risk_score_bp = 1;
    assert_eq!(
        v.submit(&f.sign(2, &r1), &f.net.manifest, NOW + 3),
        SubmitOutcome::Accepted
    );
    assert_eq!(
        v.submit(&f.sign(2, &r1), &f.net.manifest, NOW + 3),
        SubmitOutcome::Duplicate
    );
    assert_eq!(
        v.submit(&f.sign(2, &r2), &f.net.manifest, NOW + 3),
        SubmitOutcome::Fault(FaultKind::Equivocation)
    );
    let rec = v.finalize(Some(&f.engine), NOW + 5);
    assert_eq!(rec.faults[0].evidence.len(), 2);
}

#[test]
fn replayed_late_unassigned_and_mismatched_results_are_rejected() {
    let f = fixture(&[0, 2, 3]);
    let mut v = f.verifier();
    // Result for a different (older) task payload.
    let mut old = f.honest(2);
    old.task_digest = Digest::of(b"older task");
    assert!(matches!(
        v.submit(&f.sign(2, &old), &f.net.manifest, NOW + 3),
        SubmitOutcome::Rejected(_)
    ));
    // Worker 4 was not assigned.
    assert!(matches!(
        v.submit(&f.sign(4, &f.honest(4)), &f.net.manifest, NOW + 3),
        SubmitOutcome::Rejected(_)
    ));
    // Deadline passed.
    assert!(matches!(
        v.submit(
            &f.sign(3, &f.honest(3)),
            &f.net.manifest,
            f.task.expires_at + 3600
        ),
        SubmitOutcome::Rejected(_)
    ));
    // Wrong input digest is signed misbehaviour.
    let mut wrong = f.honest(0);
    wrong.input_digest = Digest::of(b"x");
    assert_eq!(
        v.submit(&f.sign(0, &wrong), &f.net.manifest, NOW + 3),
        SubmitOutcome::Fault(FaultKind::WrongInputDigest)
    );
    // Dropping a domain from the answer.
    let mut partial = f.honest(2);
    partial.assessments.pop();
    assert_eq!(
        v.submit(&f.sign(2, &partial), &f.net.manifest, NOW + 3),
        SubmitOutcome::Fault(FaultKind::DomainSetMismatch)
    );
}

#[test]
fn disagreement_without_recompute_is_disputed_not_resolved() {
    let f = fixture(&[0, 2, 3]);
    let mut v = f.verifier();
    v.submit(&f.sign(0, &f.honest(0)), &f.net.manifest, NOW + 3);
    v.submit(&f.sign(2, &f.honest(2)), &f.net.manifest, NOW + 3);
    let mut bad = f.honest(3);
    forged_malicious(&mut bad);
    v.submit(&f.sign(3, &bad), &f.net.manifest, NOW + 3);
    let rec = v.finalize(None, NOW + 5);
    assert_eq!(rec.status, TaskStatus::Disputed);
    assert!(rec.outcomes.is_empty());
    assert!(
        rec.faults.is_empty(),
        "no fault can be proven without recomputation"
    );
}

#[test]
fn revoked_worker_results_are_rejected() {
    let mut f = fixture(&[0, 2, 3]);
    let kid = f.net.worker_id(3);
    f.net.manifest.revocations.push(Revocation {
        key_id: kid,
        revoked_at: NOW,
        reason: "compromised host".into(),
    });
    let mut v = f.verifier();
    assert!(matches!(
        v.submit(&f.sign(3, &f.honest(3)), &f.net.manifest, NOW + 3),
        SubmitOutcome::Rejected(_)
    ));
}

#[test]
fn rejections_say_whether_they_prove_misbehaviour() {
    let f = fixture(&[0, 2, 3]);
    let mut v = f.verifier();
    let blame = |o: SubmitOutcome| match o {
        SubmitOutcome::Rejected(r) => r.misbehaviour,
        other => panic!("expected a rejection, got {other:?}"),
    };
    // Proof of misbehaviour: a forged signature, impersonation, an unassigned worker.
    let mut env: cybermesh_crypto::Envelope =
        serde_json::from_slice(&f.sign(2, &f.honest(2))).unwrap();
    env.signatures[0].sig = env.signatures[0].sig.replacen('A', "B", 1);
    assert!(blame(v.submit(
        &env.to_vec().unwrap(),
        &f.net.manifest,
        NOW + 3
    )));
    let bytes = sign_bytes(payload_type::RESULT, &f.honest(2), &f.net.workers[3].key);
    assert!(blame(v.submit(&bytes, &f.net.manifest, NOW + 3)));
    assert!(blame(v.submit(
        &f.sign(4, &f.honest(4)),
        &f.net.manifest,
        NOW + 3
    )));
    // What an honest worker can send: late, for an older task payload, or before this
    // node's manifest knows its signer.
    assert!(!blame(v.submit(
        &f.sign(3, &f.honest(3)),
        &f.net.manifest,
        f.task.expires_at + 3600
    )));
    let mut old = f.honest(2);
    old.task_digest = Digest::of(b"older task");
    assert!(!blame(v.submit(&f.sign(2, &old), &f.net.manifest, NOW + 3)));
    let bytes = sign_bytes(payload_type::RESULT, &f.honest(2), &test_key("newcomer"));
    assert!(!blame(v.submit(&bytes, &f.net.manifest, NOW + 3)));
    // Another engine version (an upgrade under way) is not misbehaviour either.
    let mut skew = f.honest(0);
    skew.engine.version = "0.0.1".into();
    assert!(!blame(v.submit(
        &f.sign(0, &skew),
        &f.net.manifest,
        NOW + 3
    )));
}
