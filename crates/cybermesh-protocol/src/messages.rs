//! Version-1 message payloads. All structs use `deny_unknown_fields`, fixed field order and
//! `BTreeMap` for maps, so their JSON encoding is canonical.

use std::collections::BTreeMap;
use std::fmt;

use cybermesh_crypto::{Digest, KeyId, canonical};
use serde::{Deserialize, Deserializer, Serialize};

use crate::ProtocolError;

/// An organisation identifier: 2-32 chars of `[a-z0-9-]`. One operator may run many
/// workers; diversity requirements count operators, never workers or peer IDs.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct OperatorId(String);

impl OperatorId {
    pub fn new(s: &str) -> Result<Self, ProtocolError> {
        let ok = (2..=32).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(ProtocolError::invalid(
                "operator id must be 2-32 chars of [a-z0-9-]",
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for OperatorId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        OperatorId::new(&s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for OperatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OperatorId({})", self.0)
    }
}

impl fmt::Display for OperatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Allowlisted task kinds. Workers execute only built-in analysis for these kinds; a task
/// never carries code, scripts, URLs to fetch or commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskKind {
    DomainRiskAssessment,
    /// Certificate Transparency shard scan (see [`crate::ct`]). Opt-in per worker.
    CtShardScan,
}

/// Name and version of the analysis engine that must be used.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineSpec {
    pub name: String,
    pub version: String,
}

impl fmt::Display for EngineSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.name, self.version)
    }
}

/// Pinned evidence snapshots: source id -> SHA-256 of the snapshot file.
pub type EvidencePins = BTreeMap<String, Digest>;

/// A signed task announcement published by an approved issuer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAnnouncement {
    pub v: u16,
    pub network_id: String,
    /// 16 random bytes, hex.
    pub task_id: String,
    /// Incremented when the issuer re-assigns a task after a timeout.
    pub attempt: u32,
    pub kind: TaskKind,
    pub issuer: KeyId,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub engine: EngineSpec,
    pub evidence: EvidencePins,
    /// Normalised domains to assess.
    pub domains: Vec<String>,
    /// Workers asked to compute this task.
    pub assignees: Vec<KeyId>,
    /// Minimum number of distinct operators whose results are required.
    pub min_operators: u8,
}

#[derive(Serialize)]
struct InputCommitment<'a> {
    kind: TaskKind,
    engine: &'a EngineSpec,
    evidence: &'a EvidencePins,
    domains: &'a [String],
}

impl TaskAnnouncement {
    /// Digest of exactly what determines the analysis output: kind, engine, evidence pins
    /// and domains. Two honest workers given the same input digest produce identical
    /// assessments.
    pub fn input_digest(&self) -> Result<Digest, ProtocolError> {
        let c = InputCommitment {
            kind: self.kind,
            engine: &self.engine,
            evidence: &self.evidence,
            domains: &self.domains,
        };
        Ok(Digest::tagged(
            "cybermesh/task-input/v1",
            &[&canonical::to_vec(&c)?],
        ))
    }
}

/// Analysis verdict for one domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Strong evidence of malicious use.
    Malicious,
    /// Risk signals present but not conclusive.
    Suspicious,
    /// No meaningful risk signal. This is not a statement that the domain is safe.
    NoSignal,
    /// Appears on the pinned popularity allowlist.
    KnownBenign,
}

/// Machine-readable finding codes produced by the analysis engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingCode {
    /// Host or registrable domain is listed in a pinned reference feed.
    FeedMatch,
    /// Registrable domain is on the pinned popularity list.
    PopularDomain,
    /// A protected brand name appears outside that brand's legitimate domains.
    BrandImpersonation,
    /// Registrable label is a near-miss spelling of a protected brand.
    BrandLookalike,
    /// Internationalised label that renders like a protected brand.
    IdnHomograph,
    /// Label mixes Latin with Cyrillic or Greek letters.
    MixedScript,
    /// Credential-phishing vocabulary (login, verify, ...).
    SuspiciousKeywords,
    ManyHyphens,
    DeepSubdomain,
    LongHostname,
    /// Character distribution typical of algorithmically generated names.
    HighEntropy,
    DigitHeavy,
    /// TLD frequently abused according to public reporting.
    SuspiciousTld,
}

/// One explainable piece of evidence contributing to a score.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub code: FindingCode,
    /// Signed contribution to the risk score in basis points.
    pub points: i32,
    /// Short human-readable explanation.
    pub detail: String,
}

/// Engine output for one domain.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainAssessment {
    pub domain: String,
    /// 0..=10000.
    pub risk_score_bp: u16,
    /// 0..=10000. How strongly the evidence supports the verdict.
    pub confidence_bp: u16,
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
}

/// Self-reported resource usage for one task (informational, not trusted).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceUsage {
    pub cpu_micros: u64,
    pub wall_micros: u64,
}

/// A worker's signed result for one task.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskResult {
    pub v: u16,
    pub network_id: String,
    pub task_id: String,
    pub attempt: u32,
    /// SHA-256 of the exact task payload bytes this result answers.
    pub task_digest: Digest,
    pub input_digest: Digest,
    pub worker: KeyId,
    pub operator: OperatorId,
    pub engine: EngineSpec,
    /// Evidence snapshots actually used.
    pub evidence: EvidencePins,
    pub assessments: Vec<DomainAssessment>,
    pub completed_at: u64,
    pub nonce: String,
    pub usage: ResourceUsage,
}

impl TaskResult {
    /// Digest of the deterministic part of the result (the assessments). Honest workers
    /// assessing the same input digest produce the same value.
    pub fn assessments_digest(&self) -> Result<Digest, ProtocolError> {
        Ok(Digest::tagged(
            "cybermesh/assessments/v1",
            &[&canonical::to_vec(&self.assessments)?],
        ))
    }
}

/// Worker availability state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkerState {
    Active,
    Paused,
}

/// Signed liveness announcement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub v: u16,
    pub network_id: String,
    pub worker: KeyId,
    pub operator: OperatorId,
    pub sent_at: u64,
    pub nonce: String,
    pub state: WorkerState,
    pub engine: EngineSpec,
    pub evidence: EvidencePins,
    pub queue_depth: u16,
    /// Task kinds this worker accepts (CT scanning makes outbound requests to CT logs and is
    /// opt-in per operator).
    pub capabilities: Vec<TaskKind>,
}

/// Outcome of a reviewed false-positive appeal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppealOutcome {
    /// The listing was wrong; remove it and suppress re-listing from worker evidence alone.
    Upheld,
    /// The listing stands.
    Rejected,
}

/// A governance-signed decision on a false-positive appeal.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppealDecision {
    pub v: u16,
    pub network_id: String,
    pub appeal_id: String,
    pub indicator: String,
    pub outcome: AppealOutcome,
    pub rationale: String,
    pub decided_at: u64,
}

/// An unsigned appeal as submitted by a user or site owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Appeal {
    pub appeal_id: String,
    pub indicator: String,
    pub release_sequence: u64,
    pub reason: String,
    pub submitted_at: u64,
}
