//! Verification records: the auditable output of verifying one task.

use cybermesh_crypto::{Digest, Envelope, KeyId, canonical};
use cybermesh_protocol::{
    EngineSpec, EvidencePins, Finding, OperatorId, ProtocolError, Role, TrustManifest, Verdict,
    payload_type,
};
use serde::{Deserialize, Serialize};

use crate::policy::Classification;

/// Rejections stored per task; further ones are only counted (bounds memory under flooding).
pub const MAX_REJECTED: usize = 64;

/// Overall status of a task after verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskStatus {
    /// At least `min_operators` operators produced the accepted assessment.
    Verified,
    /// Operators disagreed and the verifier could not settle it by recomputation.
    Disputed,
    /// Too few valid results from distinct operators.
    Insufficient,
}

/// A result that passed authentication and binding checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedResult {
    pub worker: KeyId,
    pub operator: OperatorId,
    pub result_digest: Digest,
    pub assessments_digest: Digest,
    /// Whether this result matched the accepted assessment.
    pub agreed: bool,
}

/// A result that was refused before comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedResult {
    pub worker: Option<KeyId>,
    pub result_digest: Digest,
    pub reason: String,
}

/// Kinds of provable misbehaviour. Each is backed by worker-signed data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FaultKind {
    /// Signed assessment differs from the verifier's deterministic recomputation.
    IncorrectResult,
    /// Two different signed results for the same task.
    Equivocation,
    /// Signed result with an input digest that does not match the task.
    WrongInputDigest,
    /// Signed result that omits or adds domains relative to the task.
    DomainSetMismatch,
}

/// A fault and the digests of the signed results that prove it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultRecord {
    pub worker: KeyId,
    pub operator: OperatorId,
    pub kind: FaultKind,
    pub evidence: Vec<Digest>,
}

/// Verified outcome for one domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainOutcome {
    pub domain: String,
    pub classification: Classification,
    pub verdict: Verdict,
    pub risk_score_bp: u16,
    pub confidence_bp: u16,
    pub findings: Vec<Finding>,
    pub agreeing_operators: Vec<OperatorId>,
    /// The verifier's own evidence lists this domain (independent of workers).
    pub feed_corroborated: bool,
    pub rationale: String,
}

/// The verifier that produced a record. It is part of the signed payload, so records from
/// different verifiers never share a digest, and loaders check it against the envelope's
/// signer and the trust manifest. Release quorums count `operator`s, not keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierId {
    pub key: KeyId,
    pub operator: OperatorId,
}

/// Auditable result of verifying one task. Signed by the verifier when persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRecord {
    pub v: u16,
    pub network_id: String,
    /// Who verified (must equal the envelope signer when loaded).
    pub verifier: VerifierId,
    pub task_id: String,
    pub attempt: u32,
    pub task_digest: Digest,
    pub input_digest: Digest,
    pub engine: EngineSpec,
    pub evidence: EvidencePins,
    pub status: TaskStatus,
    pub recomputed: bool,
    pub accepted_assessments_digest: Option<Digest>,
    pub accepted: Vec<AcceptedResult>,
    pub rejected: Vec<RejectedResult>,
    /// Rejections beyond the per-task cap of [`MAX_REJECTED`] (counted, not stored).
    pub rejected_overflow: u64,
    pub faults: Vec<FaultRecord>,
    pub outcomes: Vec<DomainOutcome>,
    pub verified_at: u64,
    /// Present for `ct-shard-scan` tasks.
    pub ct: Option<crate::ct::CtScanDetail>,
}

/// Authenticates a signed verification record (a DSSE envelope, as written to disk and sent
/// over the network) against the trust manifest.
///
/// - The envelope is at most `max_bytes` and carries a valid signature from an enrolled,
///   non-revoked key with the verifier role.
/// - The payload is a canonical `VerificationRecord` for this manifest's network.
/// - `record.verifier.key` is one of those signers and `record.verifier.operator` is that
///   key's operator, so one verifier cannot pass its records off as another organisation's.
///
/// Returns the payload digest (what releases cite) and the record.
pub fn verify_record_envelope(
    bytes: &[u8],
    manifest: &TrustManifest,
    max_bytes: usize,
) -> Result<(Digest, VerificationRecord), ProtocolError> {
    let env = Envelope::parse(bytes, max_bytes)?;
    let v = env.verify(payload_type::VERIFICATION, 1, |id| {
        manifest.key_with_role(id, Role::Verifier)
    })?;
    let rec: VerificationRecord = canonical::from_slice(&v.payload)?;
    if rec.network_id != manifest.network_id {
        return Err(ProtocolError::WrongNetwork {
            expected: manifest.network_id.clone(),
            actual: rec.network_id,
        });
    }
    if !v.signers.contains(&rec.verifier.key)
        || manifest.operator_of(&rec.verifier.key) != Some(&rec.verifier.operator)
    {
        return Err(ProtocolError::Invalid(format!(
            "record claims verifier {} ({}), which did not sign it or belongs to another operator",
            rec.verifier.key, rec.verifier.operator
        )));
    }
    Ok((Digest::of(&v.payload), rec))
}
