//! Verification records: the auditable output of verifying one task.

use cybermesh_crypto::{Digest, KeyId};
use cybermesh_protocol::{EngineSpec, EvidencePins, Finding, OperatorId, Verdict};
use serde::{Deserialize, Serialize};

use crate::policy::Classification;

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

/// Auditable result of verifying one task. Signed by the verifier when persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRecord {
    pub v: u16,
    pub network_id: String,
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
    pub faults: Vec<FaultRecord>,
    pub outcomes: Vec<DomainOutcome>,
    pub verified_at: u64,
}
