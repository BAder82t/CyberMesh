//! Independent verification of worker results.
//!
//! The analysis engine is deterministic and every task pins its engine version and evidence
//! digests, so honest workers produce byte-identical assessments. Verification therefore
//! does **not** use majority voting:
//!
//! 1. every result is authenticated and bound to the exact task (digest, assignment,
//!    deadline, input digest, domain list);
//! 2. results are grouped by *operator* (organisation), never by worker or peer id;
//! 3. whenever the verifier holds the pinned engine and evidence it **always** recomputes
//!    the task and classifies from its own result only. Any worker whose signed assessment
//!    differs has committed a provable fault (the signed result is the proof). Lexical
//!    analysis is cheap, so this costs microseconds per domain; it also means worker
//!    compute is redundant for this task type (see `docs/evaluation.md`);
//! 4. a verifier without matching evidence cannot recompute: disagreement is recorded as
//!    `disputed` and nothing is published (consensus is never manufactured), and unanimous
//!    results can at most produce advisory warnings.
//!
//! Classification is evidence-based (see [`policy`]): worker agreement can at most produce an
//! advisory `warn`. `block` additionally requires the verifier's *own* reference-feed check,
//! so colluding workers cannot cause high-confidence blocking by submitting matching claims.

#![forbid(unsafe_code)]

pub mod ct;
pub mod policy;
pub mod record;
pub mod reputation;
mod task;

pub use policy::{Classification, Policy};
pub use record::{
    AcceptedResult, DomainOutcome, FaultKind, FaultRecord, RejectedResult, TaskStatus,
    VerificationRecord, VerifierId,
};
pub use reputation::{ReputationBook, WorkerStanding};
pub use task::{SubmitOutcome, TaskVerifier};
