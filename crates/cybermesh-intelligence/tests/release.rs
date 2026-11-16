#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use cybermesh_crypto::{Digest, Envelope, canonical};
use cybermesh_intelligence::*;
use cybermesh_protocol::testkit::{TestNetwork, test_key};
use cybermesh_protocol::*;
use cybermesh_verifier::{Classification, DomainOutcome, TaskStatus, VerificationRecord};

const NOW: u64 = 1_800_000_000;

fn outcome(domain: &str, c: Classification, score: u16) -> DomainOutcome {
    DomainOutcome {
        domain: domain.into(),
        classification: c,
        verdict: if c == Classification::Block {
            Verdict::Malicious
        } else {
            Verdict::Suspicious
        },
        risk_score_bp: score,
        confidence_bp: 9000,
        findings: vec![Finding {
            code: FindingCode::BrandImpersonation,
            points: 3500,
            detail: "brand name outside its legitimate domains: examplebank".into(),
        }],
        agreeing_operators: vec![
            OperatorId::new("org-a").unwrap(),
            OperatorId::new("org-b").unwrap(),
            OperatorId::new("org-c").unwrap(),
        ],
        feed_corroborated: c == Classification::Block,
        rationale: "test".into(),
    }
}

fn record(task: &str, outcomes: Vec<DomainOutcome>, at: u64) -> (Digest, VerificationRecord) {
    let r = VerificationRecord {
        v: 1,
        network_id: "cybermesh-test".into(),
        task_id: task.into(),
        attempt: 0,
        task_digest: Digest::of(task.as_bytes()),
        input_digest: Digest::of(b"input"),
        engine: EngineSpec {
            name: "cybermesh-lexical".into(),
            version: "0.1.0".into(),
        },
        evidence: BTreeMap::from([("reference-feed".to_owned(), Digest::of(b"feed"))]),
        status: TaskStatus::Verified,
        recomputed: true,
        accepted_assessments_digest: Some(Digest::of(b"a")),
        accepted: vec![],
        rejected: vec![],
        rejected_overflow: 0,
        faults: vec![],
        outcomes,
        verified_at: at,
    };
    (Digest::of(&canonical::to_vec(&r).unwrap()), r)
}

fn params(seq: u64) -> BuildParams {
    BuildParams {
        network_id: "cybermesh-test".into(),
        sequence: seq,
        previous: None,
        issued_at: NOW,
        ttl_secs: 7 * 86_400,
        max_record_age_secs: 30 * 86_400,
    }
}

fn records() -> Vec<(Digest, VerificationRecord)> {
    vec![
        record(
            "00000000000000000000000000000001",
            vec![
                outcome(
                    "examplebank-secure-login.phish.localhost",
                    Classification::Block,
                    10_000,
                ),
                outcome("benign.example.com", Classification::None, 100),
            ],
            NOW - 100,
        ),
        record(
            "00000000000000000000000000000002",
            vec![outcome(
                "examplebank-account-verify.phish.localhost",
                Classification::Warn,
                4900,
            )],
            NOW - 50,
        ),
        // Unverified records never contribute.
        {
            let (_, mut r) = record("00000000000000000000000000000003", vec![], NOW - 10);
            r.status = TaskStatus::Disputed;
            r.outcomes = vec![outcome("disputed.example.com", Classification::Warn, 5000)];
            (Digest::of(&canonical::to_vec(&r).unwrap()), r)
        },
    ]
}

fn net() -> TestNetwork {
    TestNetwork::new(&[("org-a", 1), ("org-b", 1), ("org-c", 1)], NOW)
}

fn signed(net: &TestNetwork, rel: &ThreatRelease, signers: &[usize]) -> Vec<u8> {
    let mut env = sign_release(rel, &net.release_signers[signers[0]].0).unwrap();
    for i in &signers[1..] {
        env.add_signature(&net.release_signers[*i].0).unwrap();
    }
    env.to_vec().unwrap()
}

#[test]
fn deterministic_generation_and_independent_cosigning() {
    let net = net();
    let mut recs = records();
    let a = build_release(&recs, &[], &params(1)).unwrap();
    recs.reverse();
    let b = build_release(&recs, &[], &params(1)).unwrap();
    let (ba, bb) = (
        canonical::to_vec(&a).unwrap(),
        canonical::to_vec(&b).unwrap(),
    );
    assert_eq!(ba, bb, "input order must not change the release bytes");
    assert_eq!(a.entries.len(), 2);
    assert_eq!(a.entries[0].action, Action::Warn);
    assert_eq!(a.entries[1].action, Action::Block);
    assert!(a.lookup("disputed.example.com").is_none());

    // Two organisations build independently and sign; signatures merge because the payload
    // bytes are identical.
    let mut env_a = sign_release(&a, &net.release_signers[0].0).unwrap();
    let env_b = sign_release(&b, &net.release_signers[1].0).unwrap();
    env_a.merge_signatures(&env_b).unwrap();
    let root = TrustRoot::from_manifest(&net.manifest);
    let v = verify_release(&env_a.to_vec().unwrap(), &root, NOW + 10, None).unwrap();
    assert_eq!(v.operators.len(), 2);
    assert_eq!(
        v.release
            .lookup("www.examplebank-secure-login.phish.localhost")
            .unwrap()
            .action,
        Action::Block
    );
}

#[test]
fn threshold_counts_distinct_operators() {
    let net = net();
    let rel = build_release(&records(), &[], &params(1)).unwrap();
    let root = TrustRoot::from_manifest(&net.manifest);
    assert!(matches!(
        verify_release(&signed(&net, &rel, &[0]), &root, NOW, None),
        Err(ReleaseError::Threshold {
            valid_operators: 1,
            required: 2
        })
    ));
    // Two keys, but both registered to the same operator.
    let mut same_op = root.clone();
    same_op.signers[1].operator = same_op.signers[0].operator.clone();
    assert!(matches!(
        verify_release(&signed(&net, &rel, &[0, 1]), &same_op, NOW, None),
        Err(ReleaseError::Threshold {
            valid_operators: 1,
            ..
        })
    ));
    // Unknown signers are ignored.
    let mut env = sign_release(&rel, &test_key("attacker-1")).unwrap();
    env.add_signature(&test_key("attacker-2")).unwrap();
    assert!(matches!(
        verify_release(&env.to_vec().unwrap(), &root, NOW, None),
        Err(ReleaseError::Threshold { .. })
    ));
}

#[test]
fn revoked_signing_key_no_longer_counts() {
    let mut net = net();
    let rel = build_release(&records(), &[], &params(1)).unwrap();
    let bytes = signed(&net, &rel, &[0, 1]);
    net.manifest.revocations.push(Revocation {
        key_id: net.release_signers[1].0.key_id(),
        revoked_at: NOW,
        reason: "release key compromised".into(),
    });
    let root = TrustRoot::from_manifest(&net.manifest);
    assert!(matches!(
        verify_release(&bytes, &root, NOW, None),
        Err(ReleaseError::Threshold {
            valid_operators: 1,
            ..
        })
    ));
}

#[test]
fn time_network_and_tamper_checks() {
    let net = net();
    let root = TrustRoot::from_manifest(&net.manifest);
    let rel = build_release(&records(), &[], &params(1)).unwrap();
    let bytes = signed(&net, &rel, &[0, 2]);
    assert_eq!(
        verify_release(&bytes, &root, rel.expires_at, None).unwrap_err(),
        ReleaseError::Expired
    );
    assert_eq!(
        verify_release(&bytes, &root, NOW - 3600, None).unwrap_err(),
        ReleaseError::NotYetValid
    );
    let mut other = root.clone();
    other.network_id = "other".into();
    assert!(matches!(
        verify_release(&bytes, &other, NOW, None),
        Err(ReleaseError::WrongNetwork(_))
    ));
    // Flip one entry action after signing.
    let mut env: Envelope = serde_json::from_slice(&bytes).unwrap();
    let mut tampered = rel.clone();
    tampered.entries[0].action = Action::Block;
    env.payload = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(canonical::to_vec(&tampered).unwrap())
    };
    assert!(verify_release(&env.to_vec().unwrap(), &root, NOW, None).is_err());
    // Garbage and oversize input.
    assert!(verify_release(b"{}", &root, NOW, None).is_err());
    assert!(verify_release(&vec![b' '; MAX_RELEASE_BYTES + 1], &root, NOW, None).is_err());
}

#[test]
fn anti_rollback_and_equivocation() {
    let net = net();
    let root = TrustRoot::from_manifest(&net.manifest);
    let r5 = build_release(&records(), &[], &params(5)).unwrap();
    let v5 = verify_release(&signed(&net, &r5, &[0, 1]), &root, NOW, None).unwrap();
    let state = ConsumerState {
        sequence: 5,
        digest: v5.digest,
    };
    let r4 = build_release(&records(), &[], &params(4)).unwrap();
    assert_eq!(
        verify_release(&signed(&net, &r4, &[0, 1]), &root, NOW, Some(&state)).unwrap_err(),
        ReleaseError::Rollback { got: 4, last: 5 }
    );
    // Same sequence, different content: equivocation by the signers.
    let r5b = build_release(&records()[..1], &[], &params(5)).unwrap();
    assert_eq!(
        verify_release(&signed(&net, &r5b, &[0, 1]), &root, NOW, Some(&state)).unwrap_err(),
        ReleaseError::Equivocation(5)
    );
    // Re-delivery of the same release is fine.
    verify_release(&signed(&net, &r5, &[1, 2]), &root, NOW, Some(&state)).unwrap();
}

#[test]
fn upheld_appeal_removes_entry_and_is_published_as_correction() {
    let decision = AppealDecision {
        v: 1,
        network_id: "cybermesh-test".into(),
        appeal_id: "appeal-0001".into(),
        indicator: "examplebank-account-verify.phish.localhost".into(),
        outcome: AppealOutcome::Upheld,
        rationale: "site owner demonstrated legitimate use".into(),
        decided_at: NOW - 1,
    };
    let rel = build_release(&records(), std::slice::from_ref(&decision), &params(2)).unwrap();
    assert!(
        rel.lookup("examplebank-account-verify.phish.localhost")
            .is_none()
    );
    assert_eq!(rel.corrections.len(), 1);
    assert_eq!(rel.corrections[0].kind, CorrectionKind::AppealUpheld);
    // A decision dated after the release is not applied yet.
    let future = AppealDecision {
        decided_at: NOW + 10,
        ..decision.clone()
    };
    let rel = build_release(&records(), &[future], &params(2)).unwrap();
    assert!(
        rel.lookup("examplebank-account-verify.phish.localhost")
            .is_some()
    );
    // A later rejection supersedes the upheld decision.
    let rejected = AppealDecision {
        appeal_id: "appeal-0002".into(),
        outcome: AppealOutcome::Rejected,
        decided_at: NOW,
        ..decision.clone()
    };
    let rel = build_release(&records(), &[decision, rejected], &params(2)).unwrap();
    assert!(
        rel.lookup("examplebank-account-verify.phish.localhost")
            .is_some()
    );
}

#[test]
fn rollback_publishes_old_content_under_new_sequence() {
    let r1 = build_release(&records()[..1], &[], &params(1)).unwrap();
    let mut p3 = params(3);
    p3.previous = Some(ReleaseRef {
        sequence: 2,
        digest: Digest::of(b"r2"),
    });
    let r3 = rollback(&r1, &[], &p3).unwrap();
    assert_eq!(r3.sequence, 3);
    assert_eq!(r3.entries, r1.entries);
    assert!(
        r3.corrections
            .iter()
            .any(|c| c.kind == CorrectionKind::Rollback)
    );
    assert!(rollback(&r1, &[], &params(1)).is_err());
}

#[test]
fn stale_records_are_excluded() {
    let mut p = params(1);
    p.max_record_age_secs = 60;
    let rel = build_release(&records(), &[], &p).unwrap();
    assert_eq!(
        rel.entries.len(),
        1,
        "only the record from NOW-50 is fresh enough"
    );
}

#[test]
fn newest_record_wins_and_can_delist() {
    let d = "examplebank-account-verify.phish.localhost";
    let old = record(
        "00000000000000000000000000000010",
        vec![outcome(d, Classification::Warn, 4900)],
        NOW - 100,
    );
    let new = record(
        "00000000000000000000000000000011",
        vec![outcome(d, Classification::None, 100)],
        NOW - 10,
    );
    let rel = build_release(&[old.clone(), new], &[], &params(1)).unwrap();
    assert!(
        rel.lookup(d).is_none(),
        "a newer no-risk verdict de-lists the domain"
    );
    let rel = build_release(&[old], &[], &params(1)).unwrap();
    assert!(rel.lookup(d).is_some());
}

#[test]
fn caller_supplied_record_digest_must_match() {
    let mut recs = records();
    recs[0].0 = Digest::of(b"forged digest");
    assert!(build_release(&recs, &[], &params(1)).is_err());
}

#[test]
fn appeal_covers_subdomains_and_only_fresh_block_relists() {
    let parent = "phish.localhost";
    let decision = AppealDecision {
        v: 1,
        network_id: "cybermesh-test".into(),
        appeal_id: "appeal-0003".into(),
        indicator: parent.into(),
        outcome: AppealOutcome::Upheld,
        rationale: "whole zone is a test zone".into(),
        decided_at: NOW - 75,
    };
    // Records: block verified before the decision (NOW-100), warn after it (NOW-50).
    let rel = build_release(&records(), std::slice::from_ref(&decision), &params(2)).unwrap();
    assert!(
        rel.entries.is_empty(),
        "subdomains of the appealed indicator are removed"
    );
    // A block from fresh feed-corroborated evidence after the decision re-lists.
    let fresh = record(
        "00000000000000000000000000000020",
        vec![outcome(
            "examplebank-secure-login.phish.localhost",
            Classification::Block,
            10_000,
        )],
        NOW - 5,
    );
    let mut recs = records();
    recs.push(fresh);
    let rel = build_release(&recs, &[decision], &params(2)).unwrap();
    assert_eq!(rel.entries.len(), 1);
    assert_eq!(rel.entries[0].action, Action::Block);
}

#[test]
fn hostile_parameters_are_rejected_not_wrapped() {
    let mut p = params(1);
    p.issued_at = u64::MAX - 1;
    p.ttl_secs = 10;
    assert!(build_release(&[], &[], &p).is_err());
    let mut p = params(1);
    p.ttl_secs = 365 * 86_400;
    assert!(build_release(&[], &[], &p).is_err(), "ttl above the cap");
    let mut p = params(1);
    p.max_record_age_secs = u64::MAX;
    assert!(build_release(&records(), &[], &p).is_ok());
}

#[test]
fn consumer_detects_forks_and_bad_text() {
    let net = net();
    let root = TrustRoot::from_manifest(&net.manifest);
    let r1 = build_release(&records(), &[], &params(1)).unwrap();
    let v1 = verify_release(&signed(&net, &r1, &[0, 1]), &root, NOW, None).unwrap();
    let state = ConsumerState {
        sequence: 1,
        digest: v1.digest,
    };
    // Successor whose previous link points elsewhere: a fork.
    let mut p2 = params(2);
    p2.previous = Some(ReleaseRef {
        sequence: 1,
        digest: Digest::of(b"other branch"),
    });
    let r2 = build_release(&records(), &[], &p2).unwrap();
    assert!(matches!(
        verify_release(&signed(&net, &r2, &[0, 1]), &root, NOW, Some(&state)),
        Err(ReleaseError::Invalid(_))
    ));
    // Correct link is accepted.
    p2.previous = Some(ReleaseRef {
        sequence: 1,
        digest: v1.digest,
    });
    let r2 = build_release(&records(), &[], &p2).unwrap();
    verify_release(&signed(&net, &r2, &[0, 1]), &root, NOW, Some(&state)).unwrap();
    // Huge sequence jump is refused.
    let r_big = build_release(&records(), &[], &params(10_000_000)).unwrap();
    assert!(verify_release(&signed(&net, &r_big, &[0, 1]), &root, NOW, Some(&state)).is_err());
    // Control characters in a reason are refused even when properly signed.
    let mut bad = build_release(&records(), &[], &params(2)).unwrap();
    bad.entries[0].reasons[0].detail = "click <here>\u{7}".replace("\\u{7}", "\u{7}");
    bad.entries[0].reasons[0].detail.push('\u{7}');
    assert!(verify_release(&signed(&net, &bad, &[0, 1]), &root, NOW, None).is_err());
}
