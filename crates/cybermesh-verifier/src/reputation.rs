//! Reputation tracking.
//!
//! Reputation is operational metadata: it orders task assignment and triggers quarantine.
//! It is **never** used as evidence that a domain is malicious, and it is tracked per worker
//! key and aggregated per operator, because operators (not keys) are the unit of
//! independence. A single provable fault quarantines the worker until governance review:
//! the engine is deterministic, so an honest worker never produces a provable fault unless
//! it is misconfigured or compromised.

use std::collections::BTreeMap;

use cybermesh_crypto::KeyId;
use cybermesh_protocol::OperatorId;
use serde::{Deserialize, Serialize};

use crate::record::{FaultKind, TaskStatus, VerificationRecord};

/// Counters for one worker key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerStanding {
    pub operator: Option<OperatorId>,
    pub agreed: u64,
    pub unconfirmed: u64,
    pub faults: u64,
    /// Assignments not answered before the deadline (not a fault: hosts go offline).
    #[serde(default)]
    pub missed: u64,
    /// Consecutive missed assignments; reset by any accepted result.
    #[serde(default)]
    pub missed_streak: u64,
    pub last_fault: Option<FaultKind>,
    pub quarantined: bool,
    pub quarantine_reason: Option<String>,
}

impl WorkerStanding {
    /// Beta-style score in per mille: (agreed + 1) / (agreed + unconfirmed + 10*faults + 2).
    #[must_use]
    pub fn score_per_mille(&self) -> u64 {
        let num = (self.agreed + 1) * 1000;
        let den = self.agreed + self.unconfirmed + 10 * self.faults + 2;
        num / den
    }
}

/// Reputation for all workers known to a verifier.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationBook {
    pub workers: BTreeMap<KeyId, WorkerStanding>,
    /// `task_id/attempt` of records already applied (makes `apply` idempotent).
    #[serde(default)]
    pub applied: std::collections::BTreeSet<String>,
}

impl ReputationBook {
    /// Applies one verification record.
    pub fn apply(&mut self, record: &VerificationRecord) {
        if !self
            .applied
            .insert(format!("{}/{}", record.task_id, record.attempt))
        {
            return;
        }
        for a in &record.accepted {
            let s = self.workers.entry(a.worker.clone()).or_default();
            s.operator = Some(a.operator.clone());
            s.missed_streak = 0;
            if a.agreed && record.status == TaskStatus::Verified {
                s.agreed += 1;
            } else if record.status != TaskStatus::Verified {
                s.unconfirmed += 1;
            }
        }
        for f in &record.faults {
            let s = self.workers.entry(f.worker.clone()).or_default();
            s.operator = Some(f.operator.clone());
            s.faults += 1;
            s.last_fault = Some(f.kind);
            s.quarantined = true;
            s.quarantine_reason = Some(format!(
                "{:?} on task {} (evidence {})",
                f.kind,
                record.task_id,
                f.evidence
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    /// Records assignees that did not answer before the deadline.
    pub fn record_missed(&mut self, workers: &[KeyId]) {
        for w in workers {
            let s = self.workers.entry(w.clone()).or_default();
            s.missed += 1;
            s.missed_streak += 1;
        }
    }

    /// Workers that missed several assignments in a row are avoided when alternatives exist.
    #[must_use]
    pub fn is_unresponsive(&self, kid: &KeyId) -> bool {
        self.workers.get(kid).is_some_and(|s| s.missed_streak >= 3)
    }

    /// Records a provable fault established outside a verification record (e.g. an
    /// equivocating result that arrived after the task was settled).
    pub fn record_fault(&mut self, f: &crate::record::FaultRecord, context: &str) {
        let s = self.workers.entry(f.worker.clone()).or_default();
        s.operator = Some(f.operator.clone());
        s.faults += 1;
        s.last_fault = Some(f.kind);
        s.quarantined = true;
        s.quarantine_reason = Some(format!("{:?} ({context})", f.kind));
    }

    #[must_use]
    pub fn is_quarantined(&self, kid: &KeyId) -> bool {
        self.workers.get(kid).is_some_and(|s| s.quarantined)
    }

    #[must_use]
    pub fn score_per_mille(&self, kid: &KeyId) -> u64 {
        self.workers
            .get(kid)
            .map_or(500, WorkerStanding::score_per_mille)
    }

    /// Lifts a quarantine after governance review. Fault history is kept.
    pub fn reinstate(&mut self, kid: &KeyId) -> bool {
        match self.workers.get_mut(kid) {
            Some(s) if s.quarantined => {
                s.quarantined = false;
                s.quarantine_reason = None;
                true
            }
            _ => false,
        }
    }
}
