//! Stateless verification of signed messages received from the network.

use std::collections::BTreeSet;

use cybermesh_crypto::{Digest, Envelope, KeyId, canonical};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::domain::is_normalized_domain;
use crate::manifest::Role;
use crate::messages::{EvidencePins, Heartbeat, TaskAnnouncement, TaskResult};
use crate::{PROTOCOL_VERSION, ProtocolError, TrustManifest, payload_type};

/// Hard limits applied to every message. Defaults are deliberately small.
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_envelope_bytes: usize,
    pub max_domains_per_task: usize,
    pub max_assignees: usize,
    pub max_task_ttl_secs: u64,
    pub max_clock_skew_secs: u64,
    pub max_heartbeat_age_secs: u64,
    pub max_findings: usize,
    pub max_detail_len: usize,
    pub max_evidence_sources: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_envelope_bytes: 256 * 1024,
            max_domains_per_task: 64,
            max_assignees: 16,
            max_task_ttl_secs: 3600,
            max_clock_skew_secs: 120,
            max_heartbeat_age_secs: 300,
            max_findings: 32,
            max_detail_len: 200,
            max_evidence_sources: 16,
        }
    }
}

/// A message whose signature, signer authorisation and shape have been verified.
#[derive(Debug, Clone)]
pub struct Verified<T> {
    pub message: T,
    /// SHA-256 of the exact signed payload bytes (the message id).
    pub payload_digest: Digest,
    pub signer: KeyId,
    pub envelope: Envelope,
}

pub(crate) fn verify_signed<T: Serialize + DeserializeOwned>(
    bytes: &[u8],
    ptype: &str,
    role: Role,
    manifest: &TrustManifest,
    limits: &Limits,
) -> Result<Verified<T>, ProtocolError> {
    let env = Envelope::parse(bytes, limits.max_envelope_bytes)?;
    if env.signatures.len() != 1 {
        return Err(ProtocolError::invalid(
            "network messages carry exactly one signature",
        ));
    }
    let v = env
        .verify(ptype, 1, |id| manifest.key_with_role(id, role))
        .map_err(|e| match e {
            cybermesh_crypto::CryptoError::InsufficientSignatures { .. } => {
                ProtocolError::NotAuthorized(role.as_str())
            }
            other => ProtocolError::Crypto(other),
        })?;
    let message: T = canonical::from_slice(&v.payload)?;
    let signer = v
        .signers
        .into_iter()
        .next()
        .ok_or(ProtocolError::NotAuthorized(role.as_str()))?;
    Ok(Verified {
        message,
        payload_digest: Digest::of(&v.payload),
        signer,
        envelope: env,
    })
}

fn check_header(v: u16, network: &str, manifest: &TrustManifest) -> Result<(), ProtocolError> {
    if v != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(v));
    }
    if network != manifest.network_id {
        return Err(ProtocolError::WrongNetwork {
            expected: manifest.network_id.clone(),
            actual: network.to_owned(),
        });
    }
    Ok(())
}

fn is_hex_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn check_evidence(e: &EvidencePins, limits: &Limits) -> Result<(), ProtocolError> {
    if e.len() > limits.max_evidence_sources {
        return Err(ProtocolError::invalid("too many evidence sources"));
    }
    for k in e.keys() {
        let ok = (1..=32).contains(&k.len())
            && k.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err(ProtocolError::invalid("invalid evidence source id"));
        }
    }
    Ok(())
}

fn check_sorted_domains<'a, I: Iterator<Item = &'a str>>(
    domains: I,
    max: usize,
) -> Result<usize, ProtocolError> {
    let mut prev: Option<&str> = None;
    let mut n = 0usize;
    for d in domains {
        if !is_normalized_domain(d) {
            return Err(ProtocolError::invalid("domain is not normalised"));
        }
        if let Some(p) = prev
            && d <= p
        {
            return Err(ProtocolError::invalid("domains must be sorted and unique"));
        }
        prev = Some(d);
        n += 1;
        if n > max {
            return Err(ProtocolError::invalid("too many domains"));
        }
    }
    if n == 0 {
        return Err(ProtocolError::invalid("no domains"));
    }
    Ok(n)
}

/// Engine name/version and evidence pin shape checks shared by all task kinds.
pub(crate) fn check_engine_and_evidence(
    engine: &crate::messages::EngineSpec,
    evidence: &EvidencePins,
    limits: &Limits,
) -> Result<(), ProtocolError> {
    check_engine_strings(&engine.name, &engine.version)?;
    check_evidence(evidence, limits)
}

/// Reads the payload type of an envelope without verifying it (for dispatch only).
#[must_use]
pub fn peek_payload_type(bytes: &[u8], limits: &Limits) -> Option<String> {
    Envelope::parse(bytes, limits.max_envelope_bytes)
        .ok()
        .map(|e| e.payload_type)
}

fn check_engine_strings(name: &str, version: &str) -> Result<(), ProtocolError> {
    if name.is_empty() || name.len() > 64 || version.is_empty() || version.len() > 64 {
        return Err(ProtocolError::invalid("invalid engine name or version"));
    }
    Ok(())
}

/// Verifies a task announcement: issuer authorisation, freshness and shape.
pub fn verify_task(
    bytes: &[u8],
    manifest: &TrustManifest,
    now: u64,
    limits: &Limits,
) -> Result<Verified<TaskAnnouncement>, ProtocolError> {
    let v: Verified<TaskAnnouncement> =
        verify_signed(bytes, payload_type::TASK, Role::Issuer, manifest, limits)?;
    let t = &v.message;
    check_header(t.v, &t.network_id, manifest)?;
    if v.signer != t.issuer {
        return Err(ProtocolError::SignerMismatch);
    }
    if t.kind != crate::messages::TaskKind::DomainRiskAssessment {
        return Err(ProtocolError::invalid(
            "domain task announcements carry only domain-risk-assessment",
        ));
    }
    if !is_hex_id(&t.task_id) || !is_hex_id(&t.nonce) {
        return Err(ProtocolError::invalid(
            "task_id and nonce must be 32 hex chars",
        ));
    }
    if t.issued_at > now.saturating_add(limits.max_clock_skew_secs) {
        return Err(ProtocolError::NotYetValid);
    }
    if t.expires_at <= now {
        return Err(ProtocolError::Expired);
    }
    if t.expires_at <= t.issued_at || t.expires_at - t.issued_at > limits.max_task_ttl_secs {
        return Err(ProtocolError::TtlTooLong);
    }
    check_engine_strings(&t.engine.name, &t.engine.version)?;
    check_evidence(&t.evidence, limits)?;
    check_sorted_domains(
        t.domains.iter().map(String::as_str),
        limits.max_domains_per_task,
    )?;
    if t.assignees.is_empty() || t.assignees.len() > limits.max_assignees {
        return Err(ProtocolError::invalid("assignee count out of range"));
    }
    let mut seen = BTreeSet::new();
    let mut operators = BTreeSet::new();
    for a in &t.assignees {
        if !seen.insert(a) {
            return Err(ProtocolError::invalid("duplicate assignee"));
        }
        if manifest.key_with_role(a, Role::Worker).is_none() {
            return Err(ProtocolError::invalid("assignee is not an enrolled worker"));
        }
        if let Some(op) = manifest.operator_of(a) {
            operators.insert(op.clone());
        }
    }
    if t.min_operators == 0 || usize::from(t.min_operators) > operators.len() {
        return Err(ProtocolError::invalid(
            "min_operators must be between 1 and the number of distinct assigned operators",
        ));
    }
    Ok(v)
}

/// Verifies a task result: worker authorisation, operator binding and shape. Binding to a
/// specific task (digest, assignment, deadlines) is checked by the verifier, which holds the
/// task.
pub fn verify_result(
    bytes: &[u8],
    manifest: &TrustManifest,
    now: u64,
    limits: &Limits,
) -> Result<Verified<TaskResult>, ProtocolError> {
    let v: Verified<TaskResult> =
        verify_signed(bytes, payload_type::RESULT, Role::Worker, manifest, limits)?;
    let r = &v.message;
    check_header(r.v, &r.network_id, manifest)?;
    if v.signer != r.worker {
        return Err(ProtocolError::SignerMismatch);
    }
    if manifest.operator_of(&r.worker) != Some(&r.operator) {
        return Err(ProtocolError::SignerMismatch);
    }
    if !is_hex_id(&r.task_id) || !is_hex_id(&r.nonce) {
        return Err(ProtocolError::invalid(
            "task_id and nonce must be 32 hex chars",
        ));
    }
    if r.completed_at > now.saturating_add(limits.max_clock_skew_secs) {
        return Err(ProtocolError::NotYetValid);
    }
    check_engine_strings(&r.engine.name, &r.engine.version)?;
    check_evidence(&r.evidence, limits)?;
    check_sorted_domains(
        r.assessments.iter().map(|a| a.domain.as_str()),
        limits.max_domains_per_task,
    )?;
    for a in &r.assessments {
        if a.risk_score_bp > 10_000 || a.confidence_bp > 10_000 {
            return Err(ProtocolError::invalid("score out of range"));
        }
        if a.findings.len() > limits.max_findings {
            return Err(ProtocolError::invalid("too many findings"));
        }
        if a.findings
            .iter()
            .any(|f| f.detail.len() > limits.max_detail_len)
        {
            return Err(ProtocolError::invalid("finding detail too long"));
        }
    }
    Ok(v)
}

/// Verifies a heartbeat.
pub fn verify_heartbeat(
    bytes: &[u8],
    manifest: &TrustManifest,
    now: u64,
    limits: &Limits,
) -> Result<Verified<Heartbeat>, ProtocolError> {
    let v: Verified<Heartbeat> = verify_signed(
        bytes,
        payload_type::HEARTBEAT,
        Role::Worker,
        manifest,
        limits,
    )?;
    let h = &v.message;
    check_header(h.v, &h.network_id, manifest)?;
    if v.signer != h.worker || manifest.operator_of(&h.worker) != Some(&h.operator) {
        return Err(ProtocolError::SignerMismatch);
    }
    if !is_hex_id(&h.nonce) {
        return Err(ProtocolError::invalid("nonce must be 32 hex chars"));
    }
    if h.sent_at > now.saturating_add(limits.max_clock_skew_secs) {
        return Err(ProtocolError::NotYetValid);
    }
    if h.sent_at.saturating_add(limits.max_heartbeat_age_secs) < now {
        return Err(ProtocolError::Expired);
    }
    check_engine_strings(&h.engine.name, &h.engine.version)?;
    check_evidence(&h.evidence, limits)?;
    Ok(v)
}
