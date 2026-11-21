//! Fault proofs: a verifier's self-contained evidence that a worker misbehaved, which another
//! organisation can check before acting on it.
//!
//! A verification record names a fault with the digests of the worker's signed results, which
//! nobody can check without the results themselves. A [`FaultProof`] carries the signed task
//! and the worker's signed result(s), so a coordinator can confirm the fault itself
//! ([`check_fault_proof`]):
//! - **from the signatures alone**: equivocation (two different signed results for one task
//!   attempt), a result whose input digest does not match the task, a result for other
//!   domains or tiles than the task's;
//! - **by recomputation**: an incorrect domain result, with the checker's own engine and
//!   evidence (which must be the ones the task pins);
//! - **by re-scanning the log**: an incorrect CT result, with the checker's own log access,
//!   comparing only tiles whose data the log's signed checkpoint vouches for.
//!
//! The proof is signed by the reporting verifier, but the reporter is not trusted: a claim the
//! checker cannot confirm changes nothing.

use std::collections::BTreeSet;

use cybermesh_analysis::{Engine, engine_spec};
use cybermesh_crypto::{Digest, Envelope, KeyId, SecretKey, canonical};
use cybermesh_protocol::ct::{CtScanTask, verify_ct_result, verify_ct_task};
use cybermesh_protocol::validate::{
    Limits, Verified, peek_payload_type, verify_result, verify_signed, verify_task,
};
use cybermesh_protocol::{
    PROTOCOL_VERSION, ProtocolError, Role, TaskAnnouncement, TrustManifest, payload_type,
};
use serde::{Deserialize, Serialize};

use crate::ct::CtOracle;
use crate::record::{FaultKind, FaultRecord};

/// Proofs older than this are refused (the worker's standing is judged on recent evidence).
pub const MAX_PROOF_AGE_SECS: u64 = 7 * 86_400;

/// A verifier's proof that a worker misbehaved on one task attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultProof {
    pub v: u16,
    pub network_id: String,
    /// The verifier that proved the fault (the envelope signer).
    pub reporter: KeyId,
    pub reported_at: u64,
    /// The fault as it appears in the reporter's verification record.
    pub fault: FaultRecord,
    /// The issuer-signed task envelope (JSON).
    pub task: String,
    /// The worker's signed result envelopes (JSON): two for equivocation, one otherwise.
    pub results: Vec<String>,
}

/// Signs a fault proof as `key` (an enrolled verifier).
pub fn sign_fault_proof(p: &FaultProof, key: &SecretKey) -> Result<Vec<u8>, ProtocolError> {
    let payload = canonical::to_vec(p)?;
    Ok(Envelope::sign(payload_type::FAULT_PROOF, &payload, key).to_vec()?)
}

/// Authenticates a fault proof: signed by an enrolled verifier naming itself, for this
/// network, recent, with one or two results.
pub fn verify_fault_proof(
    bytes: &[u8],
    manifest: &TrustManifest,
    now: u64,
    limits: &Limits,
) -> Result<Verified<FaultProof>, ProtocolError> {
    let v: Verified<FaultProof> = verify_signed(
        bytes,
        payload_type::FAULT_PROOF,
        Role::Verifier,
        manifest,
        limits,
    )?;
    let p = &v.message;
    if p.v != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(p.v));
    }
    if p.network_id != manifest.network_id {
        return Err(ProtocolError::WrongNetwork {
            expected: manifest.network_id.clone(),
            actual: p.network_id.clone(),
        });
    }
    if v.signer != p.reporter {
        return Err(ProtocolError::SignerMismatch);
    }
    if p.reported_at > now.saturating_add(limits.max_clock_skew_secs) {
        return Err(ProtocolError::NotYetValid);
    }
    if p.reported_at.saturating_add(MAX_PROOF_AGE_SECS) < now {
        return Err(ProtocolError::Expired);
    }
    if p.results.is_empty() || p.results.len() > 2 {
        return Err(ProtocolError::Invalid(
            "a fault proof carries one or two results".into(),
        ));
    }
    Ok(v)
}

/// The outcome of checking a fault proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// The checker established the fault itself.
    Confirmed(FaultRecord),
    /// The evidence does not show the claimed fault.
    Refuted(String),
    /// The checker cannot decide (its manifest, engine or log access differs).
    Unconfirmed(String),
}

/// The task's `issued_at`, read before verification so it can be checked as of its issue.
fn issued_at(task: &[u8], limits: &Limits) -> Option<u64> {
    let env = Envelope::parse(task, limits.max_envelope_bytes).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&env.payload_bytes().ok()?).ok()?;
    v.get("issued_at")?.as_u64()
}

enum Task {
    Domain(TaskAnnouncement),
    Ct(CtScanTask),
}

impl Task {
    fn id(&self) -> (&str, u32, u64) {
        match self {
            Task::Domain(t) => (&t.task_id, t.attempt, t.expires_at),
            Task::Ct(t) => (&t.task_id, t.attempt, t.expires_at),
        }
    }

    fn assigned(&self, w: &KeyId) -> bool {
        match self {
            Task::Domain(t) => t.assignees.contains(w),
            Task::Ct(t) => t.assignees.contains(w),
        }
    }
}

/// Checks a fault proof against this node's own view: its manifest, its engine and evidence,
/// and (for CT) its own log access. The proof's envelope must already be verified. Evidence
/// from a task that expired more than [`MAX_PROOF_AGE_SECS`] before `now` is not acted on.
#[must_use]
pub fn check_fault_proof(
    p: &FaultProof,
    manifest: &TrustManifest,
    engine: Option<&Engine>,
    oracle: Option<&dyn CtOracle>,
    limits: &Limits,
    now: u64,
) -> Check {
    let unconfirmed = |m: String| Check::Unconfirmed(m);
    let refuted = |m: &str| Check::Refuted(m.to_owned());
    let task_bytes = p.task.as_bytes();
    let Some(at) = issued_at(task_bytes, limits) else {
        return refuted("the task envelope is malformed");
    };
    // The task as of its issue (an old task has expired since).
    let (task, task_digest) =
        if peek_payload_type(task_bytes, limits).as_deref() == Some(payload_type::CT_TASK) {
            match verify_ct_task(task_bytes, manifest, at, limits) {
                Ok(v) => (Task::Ct(v.message), v.payload_digest),
                Err(e) => return unconfirmed(format!("the task does not verify here: {e}")),
            }
        } else {
            match verify_task(task_bytes, manifest, at, limits) {
                Ok(v) => (Task::Domain(v.message), v.payload_digest),
                Err(e) => return unconfirmed(format!("the task does not verify here: {e}")),
            }
        };
    let (task_id, attempt, expires_at) = task.id();
    if expires_at.saturating_add(MAX_PROOF_AGE_SECS) < now {
        return unconfirmed("the evidence is too old to act on".into());
    }
    // Results only need to be no later than plausible for this task.
    let results_now = expires_at.saturating_add(MAX_PROOF_AGE_SECS);
    let worker = &p.fault.worker;
    if !task.assigned(worker) {
        return refuted("the accused worker was not assigned this task");
    }
    let mut digests = BTreeSet::new();
    let mut domain_results = Vec::new();
    let mut ct_results = Vec::new();
    for r in &p.results {
        let bytes = r.as_bytes();
        match &task {
            Task::Domain(_) => match verify_result(bytes, manifest, results_now, limits) {
                Ok(v) => {
                    let m = &v.message;
                    if &m.worker != worker
                        || m.operator != p.fault.operator
                        || m.task_id != task_id
                        || m.attempt != attempt
                        || m.task_digest != task_digest
                    {
                        return refuted("a result is not the accused worker's for this task");
                    }
                    digests.insert(v.payload_digest);
                    domain_results.push(v.message);
                }
                Err(e) => return unconfirmed(format!("a result does not verify here: {e}")),
            },
            Task::Ct(_) => match verify_ct_result(bytes, manifest, results_now, limits) {
                Ok(v) => {
                    let m = &v.message;
                    if &m.worker != worker
                        || m.operator != p.fault.operator
                        || m.task_id != task_id
                        || m.attempt != attempt
                        || m.task_digest != task_digest
                    {
                        return refuted("a result is not the accused worker's for this task");
                    }
                    digests.insert(v.payload_digest);
                    ct_results.push(v.message);
                }
                Err(e) => return unconfirmed(format!("a result does not verify here: {e}")),
            },
        }
    }
    let evidence: BTreeSet<Digest> = p.fault.evidence.iter().copied().collect();
    if digests != evidence {
        return refuted("the results are not the ones the fault names");
    }
    let confirmed = || Check::Confirmed(p.fault.clone());
    match (&task, p.fault.kind) {
        (_, FaultKind::Equivocation) => {
            // Two different claims, not merely the same answer signed twice (a worker that
            // re-ran the task after a restart picks a new nonce).
            let claims: BTreeSet<Option<Digest>> = domain_results
                .iter()
                .map(|r| r.assessments_digest().ok())
                .chain(ct_results.iter().map(|r| r.tiles_digest().ok()))
                .collect();
            if p.results.len() != 2 || digests.len() != 2 {
                refuted("equivocation needs two different signed results")
            } else if claims.len() < 2 || claims.contains(&None) {
                refuted("both results assert the same: a re-sent answer, not equivocation")
            } else {
                confirmed()
            }
        }
        (Task::Domain(t), kind) => {
            let [r] = domain_results.as_slice() else {
                return refuted("this fault is proven by one result");
            };
            match kind {
                FaultKind::WrongInputDigest => match t.input_digest() {
                    Ok(d) if d != r.input_digest => confirmed(),
                    Ok(_) => refuted("the input digest matches the task"),
                    Err(e) => unconfirmed(e.to_string()),
                },
                FaultKind::DomainSetMismatch => {
                    let got: Vec<&str> = r.assessments.iter().map(|a| a.domain.as_str()).collect();
                    let want: Vec<&str> = t.domains.iter().map(String::as_str).collect();
                    if got == want {
                        refuted("the result covers exactly the task's domains")
                    } else {
                        confirmed()
                    }
                }
                FaultKind::IncorrectResult => {
                    let Some(e) = engine.filter(|e| e.check_task(t).is_ok()) else {
                        return unconfirmed(
                            "this node does not hold the engine and evidence the task pins".into(),
                        );
                    };
                    let local = e.assess_task(t).ok().and_then(|list| {
                        canonical::to_vec(&list)
                            .ok()
                            .map(|b| Digest::tagged("cybermesh/assessments/v1", &[&b]))
                    });
                    match (local, r.assessments_digest()) {
                        (Some(mine), Ok(theirs)) if mine != theirs => confirmed(),
                        (Some(_), Ok(_)) => refuted("recomputation agrees with the worker"),
                        _ => unconfirmed("recomputation failed".into()),
                    }
                }
                FaultKind::Equivocation => unreachable_equivocation(),
            }
        }
        (Task::Ct(t), kind) => {
            let [r] = ct_results.as_slice() else {
                return refuted("this fault is proven by one result");
            };
            match kind {
                FaultKind::WrongInputDigest => match t.input_digest() {
                    Ok(d) if d != r.input_digest => confirmed(),
                    Ok(_) => refuted("the input digest matches the task"),
                    Err(e) => unconfirmed(e.to_string()),
                },
                FaultKind::DomainSetMismatch => {
                    let got: Vec<u64> = r.tiles.iter().map(|x| x.tile_index).collect();
                    let want: Vec<u64> = t.tiles().collect();
                    if got == want {
                        refuted("the result covers exactly the task's tiles")
                    } else {
                        confirmed()
                    }
                }
                FaultKind::IncorrectResult => {
                    let compatible = engine.is_some_and(|e| {
                        t.engine == engine_spec() && t.evidence == e.evidence().pins
                    });
                    let (Some(o), true) = (oracle, compatible) else {
                        return unconfirmed(
                            "this node cannot re-scan the log with the engine and evidence the task pins"
                                .into(),
                        );
                    };
                    let mut all_compared = true;
                    for claimed in &r.tiles {
                        let i = claimed.tile_index;
                        let (Some(mine), Some(root)) =
                            (o.rescan(&t.log_id, i), o.tile_root(&t.log_id, i))
                        else {
                            all_compared = false;
                            continue;
                        };
                        if mine.root != root {
                            // The log's data contradicts its own signed hashes: nobody can be
                            // proven wrong from it.
                            return unconfirmed(format!("the log is inconsistent at tile {i}"));
                        }
                        if &mine != claimed {
                            return confirmed();
                        }
                    }
                    if all_compared {
                        refuted("a re-scan of every tile agrees with the worker")
                    } else {
                        unconfirmed("some tiles could not be re-scanned".into())
                    }
                }
                FaultKind::Equivocation => unreachable_equivocation(),
            }
        }
    }
}

/// Equivocation is decided before the per-task-type checks.
fn unreachable_equivocation() -> Check {
    Check::Refuted("equivocation needs two different signed results".into())
}
