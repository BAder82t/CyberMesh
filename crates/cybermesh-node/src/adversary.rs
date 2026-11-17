//! Simulated misbehaviour for adversarial demonstrations (feature `adversary-sim`).
//!
//! Modes:
//! * `flip-verdicts`: sign a result claiming every domain is malicious and feed-listed.
//! * `equivocate`: sign the honest result and a second, different result for the same task.
//! * `forge-signature`: sign with an unenrolled key while claiming this worker's identity.
//! * `replay`: re-send the previous task's signed result instead of computing a new one.

use cybermesh_crypto::{Envelope, SecretKey, canonical};
use cybermesh_protocol::ct::{CtMatch, CtScanResult};
use cybermesh_protocol::{Finding, FindingCode, TaskResult, Verdict, payload_type};

fn sign(r: &TaskResult, key: &SecretKey) -> Vec<u8> {
    let bytes = canonical::to_vec(r).unwrap_or_default();
    Envelope::sign(payload_type::RESULT, &bytes, key)
        .to_vec()
        .unwrap_or_default()
}

/// Claims every domain is malicious with a fabricated feed listing.
pub fn forge_malicious(r: &mut TaskResult) {
    for a in &mut r.assessments {
        a.verdict = Verdict::Malicious;
        a.risk_score_bp = 10_000;
        a.confidence_bp = 9_800;
        a.findings = vec![Finding {
            code: FindingCode::FeedMatch,
            points: 9_000,
            detail: "listed in reference feed: reference-feed".into(),
        }];
    }
}

/// Returns the envelopes a misbehaving worker publishes instead of the honest one.
#[must_use]
pub fn apply(
    mode: &str,
    honest: &TaskResult,
    key: &SecretKey,
    last: Option<&[u8]>,
) -> Vec<Vec<u8>> {
    match mode {
        "flip-verdicts" => {
            let mut r = honest.clone();
            forge_malicious(&mut r);
            vec![sign(&r, key)]
        }
        "equivocate" => {
            let mut r = honest.clone();
            forge_malicious(&mut r);
            r.nonce = "e".repeat(32);
            vec![sign(honest, key), sign(&r, key)]
        }
        "forge-signature" => match SecretKey::generate() {
            Ok(k) => vec![sign(honest, &k)],
            Err(_) => vec![],
        },
        "replay" => match last {
            Some(b) => vec![b.to_vec()],
            None => vec![sign(honest, key)],
        },
        _ => vec![sign(honest, key)],
    }
}

fn sign_ct(r: &CtScanResult, key: &SecretKey) -> Vec<u8> {
    let bytes = canonical::to_vec(r).unwrap_or_default();
    Envelope::sign(payload_type::CT_RESULT, &bytes, key)
        .to_vec()
        .unwrap_or_default()
}

/// CT misbehaviour:
/// * `omit-matches` (and `flip-verdicts`): hide every lookalike found.
/// * `forge-ct-match`: add a fabricated, publishable lookalike to the first tile.
/// * `equivocate`, `forge-signature`, `replay`: as for domain tasks.
#[must_use]
pub fn apply_ct(
    mode: &str,
    honest: &CtScanResult,
    key: &SecretKey,
    last: Option<&[u8]>,
) -> Vec<Vec<u8>> {
    match mode {
        "omit-matches" | "flip-verdicts" => {
            let mut r = honest.clone();
            for t in &mut r.tiles {
                t.matches.clear();
                t.truncated = false;
            }
            vec![sign_ct(&r, key)]
        }
        "forge-ct-match" => {
            let mut r = honest.clone();
            if let Some(t) = r.tiles.first_mut() {
                t.matches.insert(
                    0,
                    CtMatch {
                        index: t.tile_index * 256,
                        name: "examp1ebank-login-verify.example-shop.net".into(),
                        risk_score_bp: 5900,
                        verdict: Verdict::Suspicious,
                        codes: vec![FindingCode::BrandLookalike, FindingCode::SuspiciousKeywords],
                    },
                );
                t.matches
                    .sort_by(|a, b| (a.index, &a.name).cmp(&(b.index, &b.name)));
            }
            vec![sign_ct(&r, key)]
        }
        "equivocate" => {
            let mut r = honest.clone();
            r.nonce = "e".repeat(32);
            if let Some(t) = r.tiles.first_mut() {
                t.matches.clear();
            }
            vec![sign_ct(honest, key), sign_ct(&r, key)]
        }
        "forge-signature" => match SecretKey::generate() {
            Ok(k) => vec![sign_ct(honest, &k)],
            Err(_) => vec![],
        },
        "replay" => match last {
            Some(b) => vec![b.to_vec()],
            None => vec![sign_ct(honest, key)],
        },
        _ => vec![sign_ct(honest, key)],
    }
}
