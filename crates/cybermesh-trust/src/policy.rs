//! Trust policy: who may authorise what (EXPERIMENTAL, unaudited).
//!
//! * [`Registry`]: participants, the administrative domains they belong to, revocation and
//!   domain compromise, with an epoch that advances on every security-relevant change.
//! * [`Policy`] and [`Structure`]: which sets of **domains** are qualified to authorise an
//!   action, as a threshold or as explicit minimal qualified sets. Many participants of one
//!   domain count as one vote: administrative-domain isolation.
//! * [`check_safety`], [`check_liveness`], [`q_condition`]: analysis of a policy against a stated
//!   adversary (which domain sets may be corrupt, or unavailable), with counterexamples.
//! * [`ApprovalIssuer`], [`Authoriser`]: approvals authenticated with the pairwise
//!   Wegman-Carter MAC, bound to an action, a session and an epoch, with replay prevention and
//!   per-participant failure budgets.
//!
//! # What this is and is not
//!
//! The decision is **private to the verifier that makes it**: approvals are MAC-tagged under
//! pairwise keys, so no third party can check them and the verifier could fabricate them. This is
//! not a publicly verifiable certificate and gives no non-repudiation. The registry is plain
//! in-memory state: persisting it, protecting it against rollback and agreeing on it between
//! several verifiers are not built, and a verifier with a stale registry may honour a revoked
//! participant. Domain isolation counts domains the registry assigns; it does not make
//! participants of different domains independent (shared infrastructure, common owners, legal
//! compulsion), which is an assumption the operator makes when drawing the domains.

mod approvals;
mod registry;
mod structure;

pub use approvals::{
    Approval, ApprovalError, ApprovalIssuer, Authoriser, Decision, Ignored, TaggedApproval,
};
pub use registry::{DomainId, ParticipantId, PolicyError, Registry, Standing, Status};
pub use structure::{
    Adversary, MAX_ANALYSIS_DOMAINS, Policy, Structure, check_liveness, check_safety,
    max_safe_corruption, max_tolerable_loss, q_condition,
};

#[cfg(test)]
mod tests;
