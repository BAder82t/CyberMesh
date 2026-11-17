use std::collections::{BTreeMap, BTreeSet};

use cybermesh_crypto::{Digest, Envelope, SecretKey, canonical};
use cybermesh_protocol::{AppealDecision, AppealOutcome, PROTOCOL_VERSION, payload_type};
use cybermesh_verifier::{Classification, DomainOutcome, TaskStatus, VerificationRecord};

use crate::model::{
    Action, Confidence, Correction, CorrectionKind, EvidenceKind, EvidenceRef, MatchScope, Reason,
    ReleaseRef, ThreatEntry, ThreatRelease,
};
use crate::{
    GENERATOR, MAX_ENTRIES, MAX_RELEASE_TTL_SECS, verify::MAX_EVIDENCE, verify::ReleaseError,
};

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
    /// Distinct verifier operators that must agree before an indicator is listed (from the
    /// trust manifest's `min_verifiers`; 0 is treated as 1).
    pub min_verifiers: usize,
}

fn rank(o: &DomainOutcome) -> (u8, u16) {
    (rank_of(o.classification), o.risk_score_bp)
}

/// Builds an entry from the representative outcome `o` (in record `rec`), citing every
/// supporting verification record (`(record digest, task id)`, sorted).
fn entry_from(
    o: &DomainOutcome,
    rec: &VerificationRecord,
    support: &[(Digest, &str)],
) -> ThreatEntry {
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
    // Supporting verification records first (they carry the quorum), then the evidence
    // snapshots they were computed from; never more than consumers accept.
    let mut evidence: Vec<EvidenceRef> = support
        .iter()
        .take(MAX_EVIDENCE - 1)
        .map(|(d, task)| EvidenceRef {
            kind: EvidenceKind::Verification,
            id: (*task).to_owned(),
            digest: *d,
        })
        .collect();
    let room = MAX_EVIDENCE - evidence.len();
    evidence.extend(rec.evidence.iter().take(room).map(|(id, d)| EvidenceRef {
        kind: EvidenceKind::Snapshot,
        id: id.clone(),
        digest: *d,
    }));
    evidence.sort();
    evidence.dedup();
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
/// Deterministic: input order does not matter.
///
/// - **Per verifier.** For each verifier *operator* and domain, the outcome of that
///   operator's most recently verified record counts (ties: stronger classification, then
///   smaller record digest), so a newer "no longer risky" verdict withdraws that operator's
///   support.
/// - **Quorum.** A domain is listed only if at least `min_verifiers` distinct verifier
///   operators currently classify it `warn` or `block`. It is `block` only if at least
///   `min_verifiers` of them classify it `block`; otherwise it is downgraded to `warn`. A
///   single verifier can therefore neither add nor escalate an entry once the quorum is 2+.
/// - **Independence.** With a quorum of 2 or more, only records the verifier *recomputed*
///   count. A verifier that lacks the task's engine or evidence can only echo the workers'
///   agreement, which adds no independent check.
/// - **Content.** Reasons and scores come from the supporting outcome with the weakest
///   classification and lowest score (ties: smallest record digest); every supporting record
///   is cited as evidence.
///
/// Record digests are recomputed from the records; a mismatching caller digest is an error.
/// The caller must have checked each record's envelope signature and that
/// `record.verifier` is the signer and its operator per the trust manifest (as
/// `cybermesh release build` does). Appeal decisions must already have been verified against
/// the governance root by the caller.
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
        let independent = params.min_verifiers <= 1 || r.recomputed;
        if r.network_id == params.network_id
            && r.status == TaskStatus::Verified
            && fresh
            && independent
        {
            usable.push((actual, r));
        }
    }
    usable.sort_by_key(|a| a.0);
    usable.dedup_by(|a, b| a.0 == b.0);

    // (domain, verifier operator) -> (verified_at, rank, record digest, outcome, record)
    type Cand<'a> = (
        u64,
        (u8, u16),
        Digest,
        &'a DomainOutcome,
        &'a VerificationRecord,
    );
    let mut latest: BTreeMap<(&str, &str), Cand<'_>> = BTreeMap::new();
    for (digest, rec) in &usable {
        for o in &rec.outcomes {
            let key = (rec.verified_at, rank(o));
            let slot = (o.domain.as_str(), rec.verifier.operator.as_str());
            if latest.get(&slot).is_none_or(|cur| key > (cur.0, cur.1)) {
                latest.insert(slot, (key.0, key.1, *digest, o, rec));
            }
        }
    }
    let mut by_domain: BTreeMap<&str, Vec<Cand<'_>>> = BTreeMap::new();
    for ((domain, _), c) in latest {
        by_domain.entry(domain).or_default().push(c);
    }
    let quorum = params.min_verifiers.max(1);
    let mut entries: BTreeMap<String, (ThreatEntry, u64)> = BTreeMap::new();
    let mut used = BTreeSet::new();
    for (domain, cands) in by_domain {
        let at_least = |c: Classification| -> Vec<&Cand<'_>> {
            cands.iter().filter(|x| rank(x.3).0 >= rank_of(c)).collect()
        };
        let blocks = at_least(Classification::Block);
        let listed = at_least(Classification::Warn);
        let mut support = if blocks.len() >= quorum {
            blocks
        } else if listed.len() >= quorum {
            listed
        } else {
            continue;
        };
        // Representative: weakest supporting outcome (a warn when the level is warn).
        support.sort_by_key(|c| (c.1, c.2));
        let rep = support[0];
        // Re-listing after an upheld appeal needs a quorum verified after the decision.
        let mut times: Vec<u64> = support.iter().map(|c| c.0).collect();
        times.sort_unstable_by(|a, b| b.cmp(a));
        let verified_at = times[quorum - 1];
        let mut cited: Vec<(Digest, &str)> = support
            .iter()
            .map(|c| (c.2, c.4.task_id.as_str()))
            .collect();
        cited.sort();
        used.extend(cited.iter().map(|c| c.0));
        entries.insert(
            domain.to_owned(),
            (entry_from(rep.3, rep.4, &cited), verified_at),
        );
    }
    let mut corrections = BTreeSet::new();
    apply_appeals(&mut entries, &mut corrections, decisions, params);
    finish(params, used.into_iter().collect(), entries, corrections)
}

fn rank_of(c: Classification) -> u8 {
    match c {
        Classification::Block => 2,
        Classification::Warn => 1,
        Classification::None => 0,
    }
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
