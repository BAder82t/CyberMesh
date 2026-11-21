#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use cybermesh_crypto::{Digest, Envelope, canonical};
use cybermesh_protocol::testkit::{TestNetwork, sign_bytes, test_key};
use cybermesh_protocol::validate::{verify_heartbeat, verify_result, verify_task};
use cybermesh_protocol::*;

const NOW: u64 = 1_800_000_000;

fn net() -> TestNetwork {
    TestNetwork::new(&[("org-a", 2), ("org-b", 1), ("org-c", 1)], NOW)
}

fn engine() -> EngineSpec {
    EngineSpec {
        name: "cybermesh-lexical".into(),
        version: "0.1.0".into(),
    }
}

fn pins() -> EvidencePins {
    BTreeMap::from([("reference-feed".to_owned(), Digest::of(b"feed"))])
}

fn result_for(n: &TestNetwork, t: &TaskAnnouncement, w: usize) -> TaskResult {
    let payload = canonical::to_vec(t).unwrap();
    TaskResult {
        v: PROTOCOL_VERSION,
        network_id: n.network_id.clone(),
        task_id: t.task_id.clone(),
        attempt: t.attempt,
        task_digest: Digest::of(&payload),
        input_digest: t.input_digest().unwrap(),
        worker: n.worker_id(w),
        operator: n.workers[w].operator.clone(),
        engine: engine(),
        evidence: pins(),
        assessments: t
            .domains
            .iter()
            .map(|d| DomainAssessment {
                domain: d.clone(),
                risk_score_bp: 100,
                confidence_bp: 5000,
                verdict: Verdict::NoSignal,
                findings: vec![],
            })
            .collect(),
        completed_at: NOW + 1,
        nonce: "0123456789abcdef0123456789abcdef".into(),
        usage: ResourceUsage::default(),
    }
}

#[test]
fn manifest_requires_governance_threshold_and_rejects_rollback() {
    let mut n = net();
    TrustManifest::verify(&n.manifest_envelope, &n.root, NOW, 1).unwrap();
    // Only one governance signature: below the 2-of-3 threshold.
    let single = testkit::sign(payload_type::MANIFEST, &n.manifest, &n.governance[0]);
    assert!(matches!(
        TrustManifest::verify(&single, &n.root, NOW, 1),
        Err(ProtocolError::Crypto(_))
    ));
    // Signed by non-governance keys.
    let rogue = TestNetwork::sign_manifest_with(&[test_key("x"), test_key("y")], &n.manifest);
    assert!(TrustManifest::verify(&rogue, &n.root, NOW, 1).is_err());
    // Rollback: a node that has seen sequence 5 refuses sequence 1.
    assert!(matches!(
        TrustManifest::verify(&n.manifest_envelope, &n.root, NOW, 5),
        Err(ProtocolError::Rollback { got: 1, min: 5 })
    ));
    // Expired manifest.
    n.manifest.expires_at = NOW;
    n.resign_manifest();
    assert_eq!(
        TrustManifest::verify(&n.manifest_envelope, &n.root, NOW, 1).unwrap_err(),
        ProtocolError::Expired
    );
}

#[test]
fn valid_task_is_accepted() {
    let n = net();
    let t = n.task(
        &["b.example.com", "a.example.com"],
        &[0, 2, 3],
        engine(),
        pins(),
        NOW,
    );
    let bytes = sign_bytes(payload_type::TASK, &t, &n.issuer);
    let v = verify_task(&bytes, &n.manifest, NOW, &Limits::default()).unwrap();
    assert_eq!(v.message.domains, vec!["a.example.com", "b.example.com"]);
    assert_eq!(v.signer, n.issuer.key_id());
}

#[test]
fn forged_tasks_are_rejected() {
    let n = net();
    let limits = Limits::default();
    let t = n.task(&["a.example.com"], &[0, 2, 3], engine(), pins(), NOW);

    // Signed by a worker (not an issuer).
    let bytes = sign_bytes(payload_type::TASK, &t, &n.workers[0].key);
    assert_eq!(
        verify_task(&bytes, &n.manifest, NOW, &limits).unwrap_err(),
        ProtocolError::NotAuthorized("issuer")
    );
    // Signed by an unknown key.
    let bytes = sign_bytes(payload_type::TASK, &t, &test_key("intruder"));
    assert!(verify_task(&bytes, &n.manifest, NOW, &limits).is_err());
    // Correct key but payload type of a result (cross-type replay).
    let bytes = sign_bytes(payload_type::RESULT, &t, &n.issuer);
    assert!(verify_task(&bytes, &n.manifest, NOW, &limits).is_err());
    // Tampered payload after signing.
    let mut env = testkit::sign(payload_type::TASK, &t, &n.issuer);
    let mut t2 = t.clone();
    t2.domains = vec!["evil.example.com".into()];
    env.payload = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(canonical::to_vec(&t2).unwrap())
    };
    assert!(verify_task(&env.to_vec().unwrap(), &n.manifest, NOW, &limits).is_err());
    // Issuer field claims someone else.
    let mut t3 = t.clone();
    t3.issuer = n.verifier.key_id();
    let bytes = sign_bytes(payload_type::TASK, &t3, &n.issuer);
    assert_eq!(
        verify_task(&bytes, &n.manifest, NOW, &limits).unwrap_err(),
        ProtocolError::SignerMismatch
    );
}

#[test]
fn revoked_issuer_is_rejected() {
    let mut n = net();
    n.manifest.revocations.push(Revocation {
        key_id: n.issuer.key_id(),
        revoked_at: NOW,
        reason: "key compromise".into(),
    });
    let t = n.task(&["a.example.com"], &[0, 2, 3], engine(), pins(), NOW);
    let bytes = sign_bytes(payload_type::TASK, &t, &n.issuer);
    assert_eq!(
        verify_task(&bytes, &n.manifest, NOW, &Limits::default()).unwrap_err(),
        ProtocolError::NotAuthorized("issuer")
    );
}

#[test]
fn task_time_and_shape_rules() {
    let n = net();
    let limits = Limits::default();
    let base = n.task(&["a.example.com"], &[0, 2, 3], engine(), pins(), NOW);
    let check = |t: &TaskAnnouncement| {
        verify_task(
            &sign_bytes(payload_type::TASK, t, &n.issuer),
            &n.manifest,
            NOW,
            &limits,
        )
    };

    let mut t = base.clone();
    t.expires_at = NOW;
    assert_eq!(check(&t).unwrap_err(), ProtocolError::Expired);

    let mut t = base.clone();
    t.issued_at = NOW + 1000;
    t.expires_at = NOW + 1100;
    assert_eq!(check(&t).unwrap_err(), ProtocolError::NotYetValid);

    let mut t = base.clone();
    t.expires_at = NOW + 86_400;
    assert_eq!(check(&t).unwrap_err(), ProtocolError::TtlTooLong);

    let mut t = base.clone();
    t.domains = vec!["b.example.com".into(), "a.example.com".into()];
    assert!(check(&t).is_err(), "unsorted domains");

    let mut t = base.clone();
    t.domains = vec!["Bad Domain".into()];
    assert!(check(&t).is_err(), "non-normalised domain");

    let mut t = base.clone();
    t.domains = (0..65).map(|i| format!("d{i:03}.example.com")).collect();
    assert!(check(&t).is_err(), "too many domains");

    let mut t = base.clone();
    t.assignees.push(n.verifier.key_id());
    assert!(check(&t).is_err(), "assignee without worker role");

    let mut t = base.clone();
    t.min_operators = 4;
    assert!(check(&t).is_err(), "min_operators above distinct operators");

    let mut t = base.clone();
    t.v = 2;
    assert_eq!(check(&t).unwrap_err(), ProtocolError::UnsupportedVersion(2));

    let mut t = base;
    t.network_id = "other".into();
    assert!(matches!(
        check(&t).unwrap_err(),
        ProtocolError::WrongNetwork { .. }
    ));
}

#[test]
fn oversized_and_malformed_inputs_are_rejected() {
    let n = net();
    let limits = Limits::default();
    let huge = vec![b'{'; limits.max_envelope_bytes + 1];
    assert!(matches!(
        verify_task(&huge, &n.manifest, NOW, &limits).unwrap_err(),
        ProtocolError::Crypto(cybermesh_crypto::CryptoError::TooLarge { .. })
    ));
    for junk in [
        &b""[..],
        b"null",
        b"[]",
        b"{\"payloadType\":1}",
        &[0xff, 0xfe],
    ] {
        assert!(verify_task(junk, &n.manifest, NOW, &limits).is_err());
    }
    // Non-canonical payload bytes (extra whitespace) under a valid signature.
    let t = n.task(&["a.example.com"], &[0, 2, 3], engine(), pins(), NOW);
    let mut bytes = canonical::to_vec(&t).unwrap();
    bytes.insert(1, b' ');
    let env = Envelope::sign(payload_type::TASK, &bytes, &n.issuer);
    assert_eq!(
        verify_task(&env.to_vec().unwrap(), &n.manifest, NOW, &limits).unwrap_err(),
        ProtocolError::Crypto(cybermesh_crypto::CryptoError::NonCanonical)
    );
    // Two signatures on a network message.
    let mut env = testkit::sign(payload_type::TASK, &t, &n.issuer);
    env.add_signature(&n.verifier).unwrap();
    assert!(verify_task(&env.to_vec().unwrap(), &n.manifest, NOW, &limits).is_err());
}

#[test]
fn results_bind_worker_identity_and_operator() {
    let n = net();
    let limits = Limits::default();
    let t = n.task(&["a.example.com"], &[0, 2, 3], engine(), pins(), NOW);
    let r = result_for(&n, &t, 2);
    let ok = verify_result(
        &sign_bytes(payload_type::RESULT, &r, &n.workers[2].key),
        &n.manifest,
        NOW,
        &limits,
    )
    .unwrap();
    assert_eq!(ok.message.operator.as_str(), "org-b");

    // Worker 0 signs a result that claims to come from worker 2.
    let bytes = sign_bytes(payload_type::RESULT, &r, &n.workers[0].key);
    assert_eq!(
        verify_result(&bytes, &n.manifest, NOW, &limits).unwrap_err(),
        ProtocolError::SignerMismatch
    );
    // Worker claims a different operator (Sybil-style inflation of diversity): refused. Not
    // proof of misbehaviour, since a manifest that moved the key would look the same.
    let mut r2 = r.clone();
    r2.operator = OperatorId::new("org-c").unwrap();
    let bytes = sign_bytes(payload_type::RESULT, &r2, &n.workers[2].key);
    let e = verify_result(&bytes, &n.manifest, NOW, &limits).unwrap_err();
    assert!(matches!(e, ProtocolError::ManifestMismatch(_)), "{e:?}");
    assert!(!e.proves_misbehaviour());
    // Issuer key cannot sign results.
    let bytes = sign_bytes(payload_type::RESULT, &r, &n.issuer);
    assert!(verify_result(&bytes, &n.manifest, NOW, &limits).is_err());
    // Out-of-range score.
    let mut r3 = r;
    r3.assessments[0].risk_score_bp = 10_001;
    let bytes = sign_bytes(payload_type::RESULT, &r3, &n.workers[2].key);
    assert!(verify_result(&bytes, &n.manifest, NOW, &limits).is_err());
}

#[test]
fn heartbeat_freshness() {
    let n = net();
    let limits = Limits::default();
    let hb = Heartbeat {
        v: PROTOCOL_VERSION,
        network_id: n.network_id.clone(),
        worker: n.worker_id(1),
        operator: n.workers[1].operator.clone(),
        sent_at: NOW,
        nonce: "0123456789abcdef0123456789abcdef".into(),
        state: WorkerState::Active,
        engine: engine(),
        evidence: pins(),
        queue_depth: 0,
        capabilities: vec![],
    };
    let bytes = sign_bytes(payload_type::HEARTBEAT, &hb, &n.workers[1].key);
    verify_heartbeat(&bytes, &n.manifest, NOW + 10, &limits).unwrap();
    assert_eq!(
        verify_heartbeat(&bytes, &n.manifest, NOW + 10_000, &limits).unwrap_err(),
        ProtocolError::Expired
    );
}

#[test]
fn replay_cache_rejects_redelivered_task() {
    let n = net();
    let t = n.task(&["a.example.com"], &[0, 2, 3], engine(), pins(), NOW);
    let bytes = sign_bytes(payload_type::TASK, &t, &n.issuer);
    let v = verify_task(&bytes, &n.manifest, NOW, &Limits::default()).unwrap();
    let mut cache = replay::ReplayCache::new(100);
    cache
        .check_and_insert(v.payload_digest, t.expires_at + 120, NOW)
        .unwrap();
    let v2 = verify_task(&bytes, &n.manifest, NOW + 5, &Limits::default()).unwrap();
    assert_eq!(
        cache.check_and_insert(v2.payload_digest, t.expires_at + 120, NOW + 5),
        Err(ProtocolError::Replay)
    );
}

#[test]
fn input_digest_covers_engine_evidence_and_domains() {
    let n = net();
    let t = n.task(&["a.example.com"], &[0, 2, 3], engine(), pins(), NOW);
    let d = t.input_digest().unwrap();
    let mut t2 = t.clone();
    t2.engine.version = "0.1.1".into();
    assert_ne!(d, t2.input_digest().unwrap());
    let mut t3 = t.clone();
    t3.evidence.insert("popularity".into(), Digest::of(b"p"));
    assert_ne!(d, t3.input_digest().unwrap());
    let mut t4 = t.clone();
    t4.domains = vec!["b.example.com".into()];
    assert_ne!(d, t4.input_digest().unwrap());
    // Assignment and timing do not change what is computed.
    let mut t5 = t;
    t5.assignees.pop();
    t5.expires_at += 1;
    assert_eq!(d, t5.input_digest().unwrap());
}

#[test]
fn min_verifiers_is_bounded_by_verifier_operators_and_omitted_when_one() {
    let mut n = net();
    // Three operators each hold a verifier key in the test network.
    assert_eq!(n.manifest.verifier_operators().len(), 3);
    let text = String::from_utf8(canonical::to_vec(&n.manifest).unwrap()).unwrap();
    assert!(
        !text.contains("min_verifiers"),
        "default 1 keeps v0.1 manifest bytes"
    );
    for (k, ok) in [(0u8, false), (1, true), (3, true), (4, false)] {
        n.manifest.min_verifiers = k;
        assert_eq!(n.manifest.validate().is_ok(), ok, "min_verifiers = {k}");
    }
    n.manifest.min_verifiers = 3;
    // Revoking one verifier makes a quorum of 3 unreachable.
    let (b_key, _) = &n.other_verifiers[0];
    n.manifest.revocations.push(Revocation {
        key_id: b_key.key_id(),
        revoked_at: NOW,
        reason: "compromised".into(),
    });
    assert!(n.manifest.validate().is_err());
    n.manifest.min_verifiers = 2;
    n.resign_manifest();
    let m = TrustManifest::verify(&n.manifest_envelope, &n.root, NOW, 0).unwrap();
    assert_eq!(m.min_verifiers, 2);
}

#[test]
fn checkpoint_observations_come_from_verifiers_naming_themselves() {
    use cybermesh_protocol::ct::{
        CheckpointObservation, MAX_OBSERVED_NOTE_BYTES, verify_checkpoint_observation,
    };
    let n = net();
    let limits = Limits::default();
    let obs = CheckpointObservation {
        v: PROTOCOL_VERSION,
        network_id: n.network_id.clone(),
        log_id: "letsencrypt-willow-2027h1".into(),
        witness: n.verifier.key_id(),
        observed_at: NOW,
        checkpoint: "log.example/1\n10\nAAAA\n\n\u{2014} log.example/1 AAAA\n".into(),
    };
    let sign = |o: &CheckpointObservation, k: &cybermesh_crypto::SecretKey| {
        sign_bytes(payload_type::CT_CHECKPOINT, o, k)
    };
    let ok =
        verify_checkpoint_observation(&sign(&obs, &n.verifier), &n.manifest, NOW, &limits).unwrap();
    assert_eq!(ok.message, obs);

    // Only verifiers witness; a worker or issuer key is refused, as is naming another key.
    let mut by_worker = obs.clone();
    by_worker.witness = n.worker_id(0);
    assert!(matches!(
        verify_checkpoint_observation(
            &sign(&by_worker, &n.workers[0].key),
            &n.manifest,
            NOW,
            &limits
        ),
        Err(ProtocolError::NotAuthorized(_))
    ));
    let other = &n.other_verifiers[0].0;
    assert_eq!(
        verify_checkpoint_observation(&sign(&obs, other), &n.manifest, NOW, &limits).unwrap_err(),
        ProtocolError::SignerMismatch
    );
    // Another network, an invalid log id, an oversized note, a stale or future observation.
    let mut wrong = obs.clone();
    wrong.network_id = "other-net".into();
    assert!(matches!(
        verify_checkpoint_observation(&sign(&wrong, &n.verifier), &n.manifest, NOW, &limits),
        Err(ProtocolError::WrongNetwork { .. })
    ));
    let mut wrong = obs.clone();
    wrong.log_id = "Bad Log".into();
    assert!(
        verify_checkpoint_observation(&sign(&wrong, &n.verifier), &n.manifest, NOW, &limits)
            .is_err()
    );
    let mut wrong = obs.clone();
    wrong.checkpoint = "x".repeat(MAX_OBSERVED_NOTE_BYTES + 1);
    assert!(
        verify_checkpoint_observation(&sign(&wrong, &n.verifier), &n.manifest, NOW, &limits)
            .is_err()
    );
    let bytes = sign(&obs, &n.verifier);
    assert_eq!(
        verify_checkpoint_observation(&bytes, &n.manifest, NOW + 3601, &limits).unwrap_err(),
        ProtocolError::Expired
    );
    assert_eq!(
        verify_checkpoint_observation(&bytes, &n.manifest, NOW - 1000, &limits).unwrap_err(),
        ProtocolError::NotYetValid
    );
    // A signature over another message kind does not pass as an observation.
    let as_heartbeat = sign_bytes(payload_type::HEARTBEAT, &obs, &n.verifier);
    assert!(verify_checkpoint_observation(&as_heartbeat, &n.manifest, NOW, &limits).is_err());
}

#[test]
fn only_what_no_version_or_manifest_explains_proves_misbehaviour() {
    let n = net();
    let limits = Limits::default();
    let t = n.task(&["a.example"], &[0, 2, 3], engine(), pins(), NOW);
    let good = sign_bytes(payload_type::TASK, &t, &n.issuer);
    // A broken signature by the enrolled issuer is a forgery ...
    let mut env: Envelope = serde_json::from_slice(&good).unwrap();
    env.signatures[0].sig = env.signatures[0].sig.replacen('A', "B", 1);
    let e = verify_task(&env.to_vec().unwrap(), &n.manifest, NOW, &limits).unwrap_err();
    assert_eq!(
        e,
        ProtocolError::Crypto(cybermesh_crypto::CryptoError::BadSignature)
    );
    assert!(e.proves_misbehaviour());
    // ... a key this manifest does not know may be enrolled in a newer one.
    let stranger = sign_bytes(payload_type::TASK, &t, &test_key("newly-enrolled"));
    let e = verify_task(&stranger, &n.manifest, NOW, &limits).unwrap_err();
    assert!(matches!(e, ProtocolError::NotAuthorized(_)), "{e:?}");
    assert!(!e.proves_misbehaviour());
    // A field this version does not know (a newer release) is refused, not blamed.
    let mut v = serde_json::to_value(&t).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("added_in_a_later_release".into(), serde_json::json!(1));
    let payload = serde_json::to_vec(&v).unwrap();
    let newer = Envelope::sign(payload_type::TASK, &payload, &n.issuer)
        .to_vec()
        .unwrap();
    let e = verify_task(&newer, &n.manifest, NOW, &limits).unwrap_err();
    assert!(!e.proves_misbehaviour(), "{e:?}");
    // So is an assignee a lagging manifest does not have yet.
    let mut later = t.clone();
    later
        .assignees
        .push(test_key("worker-enrolled-later").key_id());
    later.assignees.sort();
    let e = verify_task(
        &sign_bytes(payload_type::TASK, &later, &n.issuer),
        &n.manifest,
        NOW,
        &limits,
    )
    .unwrap_err();
    assert!(matches!(e, ProtocolError::ManifestMismatch(_)), "{e:?}");
    assert!(!e.proves_misbehaviour());
}
