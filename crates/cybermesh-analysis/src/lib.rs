//! Deterministic domain risk engine (`DomainRiskAssessment`).
//!
//! Design constraints:
//! * **No network access.** The engine never resolves, fetches or contacts a domain. It
//!   works only on the domain string and on pinned, locally cached evidence snapshots.
//! * **Deterministic.** Integer arithmetic only (fixed-point entropy), sorted outputs, no
//!   clocks or randomness. Two workers with the same engine version and evidence digests
//!   produce byte-identical assessments, so disagreement is evidence of a fault.
//! * **Explainable.** Every point added to a score is a [`Finding`](cybermesh_protocol::Finding)
//!   with a code and a human-readable reason.
//! * **Conservative.** Lexical signals alone can reach `suspicious` or `malicious`, but the
//!   release policy (in `cybermesh-verifier`) only permits blocking with independent
//!   reference-feed corroboration.

#![forbid(unsafe_code)]

mod engine;
pub mod eval;
mod evidence;
pub mod features;
mod normalize;

pub use engine::{ENGINE_NAME, ENGINE_VERSION, Engine, engine_spec, scoring};
pub use evidence::{
    Brand, BundleManifest, CtLogApi, CtLogInfo, EvidenceBundle, EvidenceError, P256_SPKI_PREFIX,
    SourceKind, SourceMeta, source_pin,
};
pub use normalize::{NormalizeError, normalize_domain};

/// Errors from running an analysis task.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AnalysisError {
    #[error("task requires engine {required}, this worker runs {actual}")]
    EngineMismatch { required: String, actual: String },
    #[error("task pins evidence {source_id}={pinned}, local snapshot is {local}")]
    EvidenceMismatch {
        source_id: String,
        pinned: String,
        local: String,
    },
    #[error("task pins unknown evidence source {0}")]
    UnknownEvidence(String),
    #[error("invalid domain {0}")]
    InvalidDomain(String),
}
