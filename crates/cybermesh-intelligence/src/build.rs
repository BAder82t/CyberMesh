use std::collections::{BTreeMap, BTreeSet};

use cybermesh_crypto::{Digest, Envelope, SecretKey, canonical};
use cybermesh_protocol::{AppealDecision, AppealOutcome, PROTOCOL_VERSION, payload_type};
use cybermesh_verifier::{Classification, DomainOutcome, TaskStatus, VerificationRecord};

use crate::model::{
    Action, Confidence, Correction, CorrectionKind, EvidenceKind, EvidenceRef, MatchScope,
    Reason, ReleaseRef, ThreatEntry, ThreatRelease,
};
use crate::{GENERATOR, MAX_ENTRIES, verify::ReleaseError};

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

fn apply_appeals(
    entries: &mut BTreeMap<String, ThreatEntry>,
    corrections: &mut BTreeSet<Correction>,
    decisions: &[AppealDecision],
    params: &BuildParams,
) {
    for (indicator, d) in latest_decisions(decisions, params) {
        if d.outcome == AppealOutcome::Upheld {
            entries.remove(indicator);
            corrections.insert(Correction {
                indicator: indicator.to_owned(),
                kind: CorrectionKind::AppealUpheld,
                reference: d.appeal_id.clone(),
                note: d.rationale.clone(),
            });
        }
    }
}

fn finish(
    params: &BuildParams,
    inputs: Vec<Digest>,
    entries: BTreeMap<String, ThreatEntry>,
    corrections: BTreeSet<Correction>,
) -> Result<ThreatRelease, ReleaseError> {
    if entries.len() > MAX_ENTRIES {
        return Err(ReleaseError::Invalid("too many entries".into()));
    }
    if params.ttl_secs == 0 {
        return Err(ReleaseError::Invalid("ttl must be positive".into()));
    }
    Ok(ThreatRelease {
        v: PROTOCOL_VERSION,
        network_id: params.network_id.clone(),
        sequence: params.sequence,
        previous: params.previous.clone(),
        issued_at: params.issued_at,
        expires_at: params.issued_at + params.ttl_secs,
        generator: GENERATOR.to_owned(),
        inputs,
        entries: entries.into_values().collect(),
        corrections: corrections.into_iter().collect(),
    })
}

/// Builds a release from verification records `(record digest, record)` and governance
/// appeal decisions. Deterministic: input order does not matter.
pub fn build_release(
    records: &[(Digest, VerificationRecord)],
    decisions: &[AppealDecision],
    params: &BuildParams,
) -> Result<ThreatRelease, ReleaseError> {
    let mut usable: Vec<&(Digest, VerificationRecord)> = records
        .iter()
        .filter(|(_, r)| {
            r.network_id == params.network_id
                && r.status == TaskStatus::Verified
                && r.verified_at <= params.issued_at
                && r.verified_at + params.max_record_age_secs >= params.issued_at
        })
        .collect();
    usable.sort_by(|a, b| a.0.cmp(&b.0));
    usable.dedup_by(|a, b| a.0 == b.0);

    let mut best: BTreeMap<String, (ThreatEntry, (u8, u16))> = BTreeMap::new();
    let mut inputs = Vec::new();
    for (digest, rec) in &usable {
        let mut used = false;
        for o in rec.publishable() {
            used = true;
            let r = rank(o);
            let replace = best.get(&o.domain).is_none_or(|(_, cur)| r > *cur);
            if replace {
                best.insert(o.domain.clone(), (entry_from(o, rec, *digest), r));
            }
        }
        if used {
            inputs.push(*digest);
        }
    }
    let mut entries: BTreeMap<String, ThreatEntry> =
        best.into_iter().map(|(k, (e, _))| (k, e)).collect();
    let mut corrections = BTreeSet::new();
    apply_appeals(&mut entries, &mut corrections, decisions, params);
    finish(params, inputs, entries, corrections)
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
    let mut entries: BTreeMap<String, ThreatEntry> = target
        .entries
        .iter()
        .map(|e| (e.indicator.clone(), e.clone()))
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
