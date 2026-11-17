//! Developer utilities: cross-language test vectors for the browser extension.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Result;
use clap::Subcommand;
use cybermesh_crypto::{Digest, canonical};
use cybermesh_intelligence::{BuildParams, TrustRoot, build_release, sign_release};
use cybermesh_protocol::testkit::{TestNetwork, test_key};
use cybermesh_protocol::{EngineSpec, Finding, FindingCode, OperatorId, Verdict};
use cybermesh_verifier::{Classification, DomainOutcome, TaskStatus, VerificationRecord};

use crate::util::{write, write_json};

#[derive(Subcommand, Debug)]
pub enum DevCmd {
    /// Write release verification test vectors (deterministic test keys).
    /// Serve a synthetic static CT log (real X.509 certificates) on a loopback address.
    MockCtLog {
        #[arg(long, default_value = "127.0.0.1:8090")]
        addr: String,
        /// Full tiles at start.
        #[arg(long, default_value_t = 8)]
        tiles: usize,
        /// Grow by this many full tiles every `--grow-every-secs` (0: a static log).
        #[arg(long, default_value_t = 0)]
        grow_tiles: usize,
        #[arg(long, default_value_t = 5)]
        grow_every_secs: u64,
        /// Stop growing at this many full tiles.
        #[arg(long, default_value_t = 0)]
        max_tiles: usize,
    },
    TestVectors {
        #[arg(long)]
        out: PathBuf,
        /// Reference time (Unix seconds) the vectors are built around.
        #[arg(long, default_value_t = 1_800_000_000)]
        now: u64,
    },
}

#[allow(non_snake_case)]
fn outcome(
    d: &str,
    c: Classification,
    score: u16,
    codes: &[(FindingCode, i32, &str)],
) -> DomainOutcome {
    DomainOutcome {
        domain: d.into(),
        classification: c,
        verdict: if c == Classification::Block {
            Verdict::Malicious
        } else {
            Verdict::Suspicious
        },
        risk_score_bp: score,
        confidence_bp: 9000,
        findings: codes
            .iter()
            .map(|(code, points, detail)| Finding {
                code: *code,
                points: *points,
                detail: (*detail).into(),
            })
            .collect(),
        agreeing_operators: ["org-a", "org-b", "org-c"]
            .iter()
            .filter_map(|o| OperatorId::new(o).ok())
            .collect(),
        feed_corroborated: c == Classification::Block,
        rationale: "test vector".into(),
    }
}

#[allow(non_snake_case)]
pub fn run(c: DevCmd) -> Result<()> {
    let (out, NOW) = match c {
        DevCmd::TestVectors { out, now } => (out, now),
        DevCmd::MockCtLog {
            addr,
            tiles,
            grow_tiles,
            grow_every_secs,
            max_tiles,
        } => {
            let log = cybermesh_ct::mock::MockLog::build(
                "ct.cybermesh.test/mock",
                &cybermesh_ct::mock::demo_entries(tiles),
            )?;
            let shared = std::sync::Arc::new(std::sync::RwLock::new(log));
            let (url, handle) =
                cybermesh_ct::mock::serve_shared(std::sync::Arc::clone(&shared), &addr)?;
            eprintln!("mock static CT log with {} entries at {url}", tiles * 256);
            if grow_tiles > 0 {
                // Grows like a real log: history unchanged, a new signed checkpoint each time.
                std::thread::spawn(move || {
                    let mut now = tiles;
                    while now + grow_tiles <= max_tiles.max(tiles) {
                        std::thread::sleep(std::time::Duration::from_secs(grow_every_secs));
                        let more = cybermesh_ct::mock::demo_entries(grow_tiles);
                        let ok = shared.write().map(|mut l| l.extend(&more).is_ok());
                        if !matches!(ok, Ok(true)) {
                            break;
                        }
                        now += grow_tiles;
                        eprintln!("mock CT log grew to {} full tiles", now);
                    }
                });
            }
            let _ = handle.join();
            return Ok(());
        }
    };
    let net = TestNetwork::new(&[("org-a", 1), ("org-b", 1), ("org-c", 1)], NOW);
    let rec = VerificationRecord {
        v: 1,
        network_id: net.network_id.clone(),
        verifier: cybermesh_verifier::VerifierId {
            key: net.verifier.key_id(),
            operator: OperatorId::new("org-a")?,
        },
        task_id: "00000000000000000000000000000001".into(),
        attempt: 0,
        task_digest: Digest::of(b"task"),
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
        outcomes: vec![
            outcome(
                "examplebank-secure-login.phish.localhost",
                Classification::Block,
                10_000,
                &[
                    (
                        FindingCode::FeedMatch,
                        9000,
                        "listed in reference feed: reference-feed",
                    ),
                    (
                        FindingCode::BrandImpersonation,
                        3500,
                        "brand name outside its legitimate domains: examplebank",
                    ),
                ],
            ),
            outcome(
                "examplebank-account-verify.phish.localhost",
                Classification::Warn,
                4900,
                &[(
                    FindingCode::BrandImpersonation,
                    3500,
                    "brand name outside its legitimate domains: examplebank",
                )],
            ),
        ],
        verified_at: NOW - 60,
        ct: None,
    };
    let rd = Digest::of(&canonical::to_vec(&rec)?);
    let params = BuildParams {
        network_id: net.network_id.clone(),
        sequence: 7,
        previous: None,
        issued_at: NOW,
        ttl_secs: 86_400,
        max_record_age_secs: 86_400,
        min_verifiers: 1,
    };
    let rel = build_release(&[(rd, rec)], &[], &params)?;
    let root = TrustRoot::from_manifest(&net.manifest);
    std::fs::create_dir_all(&out)?;
    write_json(&out.join("trust-root.json"), &root)?;

    let mut valid = sign_release(&rel, &net.release_signers[0].0)?;
    valid.add_signature(&net.release_signers[1].0)?;
    write(&out.join("release-valid.json"), &valid.to_vec()?)?;

    let single = sign_release(&rel, &net.release_signers[0].0)?;
    write(&out.join("release-one-signature.json"), &single.to_vec()?)?;

    let mut rogue = sign_release(&rel, &test_key("attacker-1"))?;
    rogue.add_signature(&test_key("attacker-2"))?;
    write(&out.join("release-unknown-signers.json"), &rogue.to_vec()?)?;

    let mut tampered = valid.clone();
    let mut t = rel.clone();
    t.entries[0].action = cybermesh_intelligence::Action::Block;
    tampered.payload = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(canonical::to_vec(&t)?)
    };
    write(&out.join("release-tampered.json"), &tampered.to_vec()?)?;

    let mut duplicated = single.clone();
    duplicated.signatures.push(duplicated.signatures[0].clone());
    write(
        &out.join("release-duplicate-signature.json"),
        &duplicated.to_vec()?,
    )?;

    let mut same_op_root = root.clone();
    same_op_root.signers[1].operator = same_op_root.signers[0].operator.clone();
    write_json(&out.join("trust-root-same-operator.json"), &same_op_root)?;

    let mut older = params.clone();
    older.sequence = 6;
    let rel6 = build_release(&[], &[], &older)?;
    let mut env6 = sign_release(&rel6, &net.release_signers[1].0)?;
    env6.add_signature(&net.release_signers[2].0)?;
    write(&out.join("release-older-sequence.json"), &env6.to_vec()?)?;

    write_json(
        &out.join("expected.json"),
        &serde_json::json!({
            "now": NOW + 10,
            "expired_now": NOW + 86_400,
            "future_now": NOW - 3600,
            "network_id": net.network_id,
            "valid_sequence": 7,
            "valid_digest": Digest::of(&valid.payload_bytes()?).to_string(),
            "block": "examplebank-secure-login.phish.localhost",
            "warn": "examplebank-account-verify.phish.localhost",
            "subdomain_of_block": "login.examplebank-secure-login.phish.localhost",
            "unlisted": "examplebank.test",
        }),
    )?;
    println!("test vectors written to {}", out.display());
    Ok(())
}
