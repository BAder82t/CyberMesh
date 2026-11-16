use std::collections::{BTreeMap, BTreeSet};

use cybermesh_crypto::{Digest, Envelope, SecretKey, canonical};
use cybermesh_protocol::{AppealDecision, AppealOutcome, PROTOCOL_VERSION, payload_type};
use cybermesh_verifier::{Classification, DomainOutcome, TaskStatus, VerificationRecord};

use crate::model::{
    Action, Confidence, Correction, CorrectionKind, EvidenceKind, EvidenceRef, MatchScope, Reason,
    ReleaseRef, ThreatEntry, ThreatRelease,
};
use crate::{GENERATOR, MAX_ENTRIES, MAX_RELEASE_TTL_SECS, verify::ReleaseError};

/// Parameters fixed by the publishers. All time values are explicit inputs (never read from
/// the clock), which is what makes generation deterministic.
#[derive(Debug, Clone)]
pub struct BuildParams {
    pub network_id: String,
    pub sequence: u64,
    pub previous: Option<ReleaseRef>,
    pub issued_at: u64,
    pub ttl_secs: u64,
    /// Verification records older than this (relative to `issued_at`) are not included.
    pub max_record_age_secs: u64,
}

fn rank(o: &DomainOutcome) -> (u8, u16) {
    let a = match o.classification {
        Classification::Block => 2,
        Classification::Warn => 1,
        Classification::None => 0,
    };
    (a, o.risk_score_bp)
}

fn entry_from(o: &DomainOutcome, rec: &VerificationRecord, rec_digest: Digest) -> ThreatEntry {
    let (action, confidence) = match o.classification {
        Classification::Block => (Action::Block, Confidence::High),
        _ => (Action::Warn, Confidence::Medium),
    };
    let reasons = o
        .findings
        .iter()
        .filter(|f| f.points > 0)
        .map(|f| Reason {
            code: f.code,
            detail: f.detail.clone(),
        })
        .collect();
    let mut evidence: Vec<EvidenceRef> = rec
        .evidence
        .iter()
        .map(|(id, d)| EvidenceRef {
            kind: EvidenceKind::Snapshot,
            id: id.clone(),
            digest: *d,
        })
        .collect();
    evidence.push(EvidenceRef {
        kind: EvidenceKind::Verification,
        id: rec.task_id.clone(),
        digest: rec_digest,
    });
    evidence.sort();
    ThreatEntry {
        indicator: o.domain.clone(),
        scope: MatchScope::HostAndSubdomains,
        action,
        confidence,
        risk_score_bp: o.risk_score_bp,
        operators: u8::try_from(o.agreeing_operators.len()).unwrap_or(u8::MAX),
        reasons,
        evidence,
    }
}

/// Latest decision per indicator, considering only decisions made before `issued_at`.
fn latest_decisions<'a>(
    decisions: &'a [AppealDecision],
    params: &BuildParams,
) -> BTreeMap<&'a str, &'a AppealDecision> {
    let mut sorted: Vec<&AppealDecision> = decisions
        .iter()
        .filter(|d| d.network_id == params.network_id && d.decided_at <= params.issued_at)
        .collect();
    sorted.sort_by(|a, b| (a.decided_at, &a.appeal_id).cmp(&(b.decided_at, &b.appeal_id)));
    let mut latest = BTreeMap::new();
    for d in sorted {
        latest.insert(d.indicator.as_str(), d);
    }
    latest
}

fn covers(appealed: &str, indicator: &str) -> bool {
    indicator == appealed
        || (indicator.len() > appealed.len()
            && indicator.ends_with(appealed)
            && indicator.as_bytes()[indicator.len() - appealed.len() - 1] == b'.')
}

/// Applies upheld appeals to the candidate entries. An upheld appeal removes the indicator
/// and its subdomains. It can only be overridden by a `block` (independent feed
/// corroboration) from a record verified *after* the decision; lexical evidence alone never
/// re-lists an appealed indicator.
fn apply_appeals(
    entries: &mut BTreeMap<String, (ThreatEntry, u64)>,
    corrections: &mut BTreeSet<Correction>,
    decisions: &[AppealDecision],
    params: &BuildParams,
) {
    for (indicator, d) in latest_decisions(decisions, params) {
        if d.outcome != AppealOutcome::Upheld {
            continue;
        }
        entries.retain(|k, (e, verified_at)| {
            !covers(indicator, k) || (e.action == Action::Block && *verified_at > d.decided_at)
        });
        corrections.insert(Correction {
            indicator: indicator.to_owned(),
            kind: CorrectionKind::AppealUpheld,
            reference: d.appeal_id.clone(),
            note: d.rationale.clone(),
        });
    }
}

fn finish(
    params: &BuildParams,
    inputs: Vec<Digest>,
    entries: BTreeMap<String, (ThreatEntry, u64)>,
    corrections: BTreeSet<Correction>,
) -> Result<ThreatRelease, ReleaseError> {
    if entries.len() > MAX_ENTRIES {
        return Err(ReleaseError::Invalid("too many entries".into()));
    }
    if params.ttl_secs == 0 || params.ttl_secs > MAX_RELEASE_TTL_SECS {
        return Err(ReleaseError::Invalid(format!(
            "ttl must be between 1 and {MAX_RELEASE_TTL_SECS} seconds"
        )));
    }
    // Refuse to produce a release that consumers would reject.
    let printable =
        |s: &str, max: usize| s.len() <= max && s.bytes().all(|b| (0x20..0x7f).contains(&b));
    if corrections.iter().any(|c| {
        !printable(&c.indicator, 253) || !printable(&c.reference, 128) || !printable(&c.note, 500)
    }) {
        return Err(ReleaseError::Invalid(
            "correction fields must be printable ASCII within length limits".into(),
        ));
    }
    let expires_at = params
        .issued_at
        .checked_add(params.ttl_secs)
        .ok_or_else(|| ReleaseError::Invalid("issued_at + ttl overflows".into()))?;
    Ok(ThreatRelease {
        v: PROTOCOL_VERSION,
        network_id: params.network_id.clone(),
        sequence: params.sequence,
        previous: params.previous.clone(),
        issued_at: params.issued_at,
        expires_at,
        generator: GENERATOR.to_owned(),
        inputs,
        entries: entries.into_values().map(|(e, _)| e).collect(),
        corrections: corrections.into_iter().collect(),
    })
}

/// Builds a release from verification records and governance appeal decisions.
///
/// Deterministic: input order does not matter. For each domain the outcome of the most
/// recently verified record wins (ties: stronger classification, then smaller record
/// digest), so a newer "no longer risky" verdict de-lists a domain. Record digests are
/// recomputed from the records; a mismatching caller digest is an error. Appeal decisions
/// must already have been verified against the governance root by the caller.
pub fn build_release(
    records: &[(Digest, VerificationRecord)],
    decisions: &[AppealDecision],
    params: &BuildParams,
) -> Result<ThreatRelease, ReleaseError> {
    let mut usable: Vec<(Digest, &VerificationRecord)> = Vec::new();
    for (claimed, r) in records {
        let actual = Digest::of(&canonical::to_vec(r).map_err(ReleaseError::Envelope)?);
        if &actual != claimed {
            return Err(ReleaseError::Invalid(format!(
                "record {} digest mismatch",
                r.task_id
            )));
        }
        let fresh = r.verified_at <= params.issued_at
            && r.verified_at.saturating_add(params.max_record_age_secs) >= params.issued_at;
        if r.network_id == params.network_id && r.status == TaskStatus::Verified && fresh {
            usable.push((actual, r));
        }
    }
    usable.sort_by_key(|a| a.0);
    usable.dedup_by(|a, b| a.0 == b.0);

    // domain -> (verified_at, rank, record digest, outcome, record)
    type Cand<'a> = (
        u64,
        (u8, u16),
        Digest,
        &'a DomainOutcome,
        &'a VerificationRecord,
    );
    let mut best: BTreeMap<&str, Cand<'_>> = BTreeMap::new();
    for (digest, rec) in &usable {
        for o in &rec.outcomes {
            let key = (rec.verified_at, rank(o));
            let replace = best
                .get(o.domain.as_str())
                .is_none_or(|cur| key > (cur.0, cur.1));
            if replace {
                best.insert(o.domain.as_str(), (key.0, key.1, *digest, o, rec));
            }
        }
    }
    let mut entries: BTreeMap<String, (ThreatEntry, u64)> = BTreeMap::new();
    let mut used = BTreeSet::new();
    for (domain, (verified_at, _, digest, o, rec)) in best {
        if o.classification == Classification::None {
            continue;
        }
        used.insert(digest);
        entries.insert(domain.to_owned(), (entry_from(o, rec, digest), verified_at));
    }
    let mut corrections = BTreeSet::new();
    apply_appeals(&mut entries, &mut corrections, decisions, params);
    finish(params, used.into_iter().collect(), entries, corrections)
}

/// Publishes the content of an earlier release under a new, higher sequence number.
/// Appeal decisions are re-applied so a rollback never resurrects a corrected entry.
pub fn rollback(
    target: &ThreatRelease,
    decisions: &[AppealDecision],
    params: &BuildParams,
) -> Result<ThreatRelease, ReleaseError> {
    if params.sequence <= target.sequence {
        return Err(ReleaseError::Invalid(
            "a rollback must use a higher sequence than the release it restores".into(),
        ));
    }
    // Restored entries carry no fresh evidence: upheld appeals always apply to them.
    let mut entries: BTreeMap<String, (ThreatEntry, u64)> = target
        .entries
        .iter()
        .map(|e| (e.indicator.clone(), (e.clone(), 0)))
        .collect();
    let mut corrections: BTreeSet<Correction> = target.corrections.iter().cloned().collect();
    corrections.insert(Correction {
        indicator: "*".into(),
        kind: CorrectionKind::Rollback,
        reference: format!("sequence:{}", target.sequence),
        note: "content restored from an earlier release".into(),
    });
    apply_appeals(&mut entries, &mut corrections, decisions, params);
    finish(params, target.inputs.clone(), entries, corrections)
}

/// Canonical payload bytes and a first signature.
pub fn sign_release(release: &ThreatRelease, key: &SecretKey) -> Result<Envelope, ReleaseError> {
    let bytes = canonical::to_vec(release).map_err(ReleaseError::Envelope)?;
    Ok(Envelope::sign(payload_type::RELEASE, &bytes, key))
}
