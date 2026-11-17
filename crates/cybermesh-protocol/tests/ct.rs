#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use cybermesh_crypto::{Digest, canonical};
use cybermesh_protocol::ct::*;
use cybermesh_protocol::testkit::{TestNetwork, sign_bytes, test_key};
use cybermesh_protocol::*;

const NOW: u64 = 1_800_000_000;

fn net() -> TestNetwork {
    TestNetwork::new(&[("org-a", 1), ("org-b", 1), ("org-c", 1)], NOW)
}

fn task(n: &TestNetwork) -> CtScanTask {
    CtScanTask {
        v: PROTOCOL_VERSION,
        network_id: n.network_id.clone(),
        task_id: "0123456789abcdef0123456789abcdef".into(),
        attempt: 0,
        issuer: n.issuer.key_id(),
        issued_at: NOW,
        expires_at: NOW + 600,
        nonce: "fedcba9876543210fedcba9876543210".into(),
        engine: EngineSpec {
            name: "cybermesh-lexical".into(),
            version: "x".into(),
        },
        evidence: BTreeMap::from([("ct-logs".to_owned(), Digest::of(b"logs"))]),
        log_id: "willow-2026h2".into(),
        first_tile: 4_126_000,
        tile_count: 8,
        assignees: vec![n.worker_id(0), n.worker_id(1)],
        min_operators: 2,
    }
}

fn tile(i: u64) -> TileScanResult {
    TileScanResult {
        tile_index: i,
        leaf_count: 256,
        root: Digest::of(&i.to_be_bytes()),
        unparsed: 0,
        names: 0,
        names_digest: Digest::of(b"names"),
        matches: vec![],
        truncated: false,
    }
}

fn result(n: &TestNetwork, t: &CtScanTask, w: usize, tiles: Vec<TileScanResult>) -> CtScanResult {
    CtScanResult {
        v: PROTOCOL_VERSION,
        network_id: n.network_id.clone(),
        task_id: t.task_id.clone(),
        attempt: 0,
        task_digest: Digest::of(&canonical::to_vec(t).unwrap()),
        input_digest: t.input_digest().unwrap(),
        worker: n.worker_id(w),
        operator: n.workers[w].operator.clone(),
        engine: t.engine.clone(),
        evidence: t.evidence.clone(),
        log_id: t.log_id.clone(),
        tiles,
        completed_at: NOW + 1,
        nonce: "00112233445566778899aabbccddeeff".into(),
        usage: ResourceUsage::default(),
        fetched_bytes: 1,
    }
}

#[test]
fn valid_task_and_result() {
    let n = net();
    let t = task(&n);
    let v = verify_ct_task(
        &sign_bytes(CT_TASK, &t, &n.issuer),
        &n.manifest,
        NOW,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(v.message.tiles().count(), 8);
    let r = result(
        &n,
        &t,
        0,
        (t.first_tile..t.first_tile + 8).map(tile).collect(),
    );
    verify_ct_result(
        &sign_bytes(CT_RESULT, &r, &n.workers[0].key),
        &n.manifest,
        NOW,
        &Limits::default(),
    )
    .unwrap();
}

#[test]
fn forged_or_malformed_tasks_are_rejected() {
    let n = net();
    let l = Limits::default();
    let t = task(&n);
    assert!(
        verify_ct_task(
            &sign_bytes(CT_TASK, &t, &n.workers[0].key),
            &n.manifest,
            NOW,
            &l
        )
        .is_err()
    );
    assert!(
        verify_ct_task(
            &sign_bytes(CT_TASK, &t, &test_key("x")),
            &n.manifest,
            NOW,
            &l
        )
        .is_err()
    );
    assert!(
        verify_ct_task(
            &sign_bytes(payload_type::TASK, &t, &n.issuer),
            &n.manifest,
            NOW,
            &l
        )
        .is_err()
    );
    for bad in [
        CtScanTask {
            tile_count: 0,
            ..t.clone()
        },
        CtScanTask {
            tile_count: MAX_TILES_PER_TASK + 1,
            ..t.clone()
        },
        CtScanTask {
            first_tile: u64::MAX,
            ..t.clone()
        },
        CtScanTask {
            log_id: "Bad/Log".into(),
            ..t.clone()
        },
        CtScanTask {
            expires_at: NOW,
            ..t.clone()
        },
        CtScanTask {
            min_operators: 3,
            ..t.clone()
        },
    ] {
        assert!(
            verify_ct_task(&sign_bytes(CT_TASK, &bad, &n.issuer), &n.manifest, NOW, &l).is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn result_shape_rules() {
    let n = net();
    let l = Limits::default();
    let t = task(&n);
    let base: Vec<TileScanResult> = (t.first_tile..t.first_tile + 8).map(tile).collect();
    let check = |tiles: Vec<TileScanResult>| {
        let r = result(&n, &t, 0, tiles);
        verify_ct_result(
            &sign_bytes(CT_RESULT, &r, &n.workers[0].key),
            &n.manifest,
            NOW,
            &l,
        )
    };
    let mut gap = base.clone();
    gap.remove(3);
    assert!(check(gap).is_err(), "tiles must be consecutive");
    let mut partial = base.clone();
    partial[0].leaf_count = 100;
    assert!(check(partial).is_err(), "only full tiles");
    let m = |index: u64, name: &str| CtMatch {
        index,
        name: name.into(),
        risk_score_bp: 4000,
        verdict: Verdict::Suspicious,
        codes: vec![FindingCode::BrandLookalike],
    };
    let lo = t.first_tile * 256;
    let mut outside = base.clone();
    outside[0].matches = vec![m(lo + 256, "a.example.com")];
    assert!(check(outside).is_err(), "match outside its tile");
    let mut unsorted = base.clone();
    unsorted[0].matches = vec![m(lo + 2, "b.example.com"), m(lo + 1, "a.example.com")];
    assert!(check(unsorted).is_err());
    let mut bad_name = base.clone();
    bad_name[0].matches = vec![m(lo, "Not A Domain")];
    assert!(check(bad_name).is_err());
    // Worker claims another operator.
    let mut r = result(&n, &t, 0, base);
    r.operator = n.workers[1].operator.clone();
    assert!(
        verify_ct_result(
            &sign_bytes(CT_RESULT, &r, &n.workers[0].key),
            &n.manifest,
            NOW,
            &l
        )
        .is_err()
    );
}

#[test]
fn domain_task_kind_cannot_carry_ct() {
    let n = net();
    let mut t = n.task(
        &["a.example.com"],
        &[0, 1, 2],
        EngineSpec {
            name: "e".into(),
            version: "1".into(),
        },
        BTreeMap::new(),
        NOW,
    );
    t.kind = TaskKind::CtShardScan;
    assert!(
        validate::verify_task(
            &sign_bytes(payload_type::TASK, &t, &n.issuer),
            &n.manifest,
            NOW,
            &Limits::default()
        )
        .is_err()
    );
}

/// Worst case: every tile saturated with maximum-length names must still fit one message.
#[test]
fn worst_case_result_fits_the_envelope_limit() {
    let n = net();
    let mut t = task(&n);
    t.tile_count = MAX_TILES_PER_TASK;
    let long = format!(
        "{}.{}.{}.{}.example.com",
        "a".repeat(60),
        "b".repeat(60),
        "c".repeat(60),
        "d".repeat(45)
    );
    assert!(long.len() <= 253);
    let tiles: Vec<TileScanResult> = (0..u64::from(MAX_TILES_PER_TASK))
        .map(|i| {
            let ti = t.first_tile + i;
            let mut x = tile(ti);
            x.names = MAX_NAMES_PER_TILE;
            x.truncated = true;
            x.matches = (0..MAX_MATCHES_PER_TILE as u64)
                .map(|k| CtMatch {
                    index: ti * 256 + k,
                    name: long.clone(),
                    risk_score_bp: 10_000,
                    verdict: Verdict::Suspicious,
                    codes: vec![
                        FindingCode::BrandImpersonation,
                        FindingCode::BrandLookalike,
                        FindingCode::IdnHomograph,
                        FindingCode::MixedScript,
                        FindingCode::SuspiciousKeywords,
                        FindingCode::ManyHyphens,
                        FindingCode::DeepSubdomain,
                        FindingCode::LongHostname,
                        FindingCode::HighEntropy,
                        FindingCode::DigitHeavy,
                        FindingCode::SuspiciousTld,
                    ],
                })
                .collect();
            x
        })
        .collect();
    let r = result(&n, &t, 0, tiles);
    let bytes = sign_bytes(CT_RESULT, &r, &n.workers[0].key);
    eprintln!("worst-case CT result envelope: {} bytes", bytes.len());
    assert!(
        bytes.len() < Limits::default().max_envelope_bytes,
        "{} bytes",
        bytes.len()
    );
    verify_ct_result(&bytes, &n.manifest, NOW, &Limits::default()).unwrap();
}

#[test]
fn at_most_four_matches_per_entry() {
    let n = net();
    let t = task(&n);
    let lo = t.first_tile * 256;
    let mut tiles: Vec<TileScanResult> = (t.first_tile..t.first_tile + 8).map(tile).collect();
    let m = |name: String| CtMatch {
        index: lo + 5,
        name,
        risk_score_bp: 4000,
        verdict: Verdict::Suspicious,
        codes: vec![FindingCode::BrandLookalike],
    };
    tiles[0].matches = (0..=MAX_MATCHES_PER_ENTRY)
        .map(|i| m(format!("a{i}.example.com")))
        .collect();
    let r = result(&n, &t, 0, tiles.clone());
    let l = Limits::default();
    assert!(
        verify_ct_result(
            &sign_bytes(CT_RESULT, &r, &n.workers[0].key),
            &n.manifest,
            NOW,
            &l
        )
        .is_err()
    );
    tiles[0].matches.pop();
    let r = result(&n, &t, 0, tiles);
    verify_ct_result(
        &sign_bytes(CT_RESULT, &r, &n.workers[0].key),
        &n.manifest,
        NOW,
        &l,
    )
    .unwrap();
}
