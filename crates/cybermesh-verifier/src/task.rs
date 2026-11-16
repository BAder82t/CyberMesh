use std::collections::{BTreeMap, BTreeSet};

use cybermesh_analysis::Engine;
use cybermesh_crypto::{Digest, KeyId, canonical};
use cybermesh_protocol::validate::verify_result;
use cybermesh_protocol::{
    DomainAssessment, Limits, OperatorId, PROTOCOL_VERSION, TaskAnnouncement, TaskResult,
    TrustManifest,
};

use crate::policy::{Classification, Policy};
use crate::record::{
    AcceptedResult, DomainOutcome, FaultKind, FaultRecord, MAX_REJECTED, RejectedResult,
    TaskStatus, VerificationRecord,
};

/// What happened to a submitted result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    Accepted,
    /// Byte-identical re-delivery of an already accepted result.
    Duplicate,
    Rejected(String),
    Fault(FaultKind),
}

#[derive(Debug, Clone)]
struct Held {
    result: TaskResult,
    result_digest: Digest,
    assessments_digest: Digest,
}

/// Collects and verifies results for one task attempt.
#[derive(Debug)]
pub struct TaskVerifier {
    task: TaskAnnouncement,
    task_digest: Digest,
    input_digest: Digest,
    policy: Policy,
    limits: Limits,
    held: BTreeMap<KeyId, Held>,
    rejected: Vec<RejectedResult>,
    rejected_overflow: u64,
    faults: Vec<FaultRecord>,
    faulted: BTreeSet<KeyId>,
}

impl TaskVerifier {
    /// `task_digest` is the SHA-256 of the exact task payload bytes that were published.
    pub fn new(
        task: TaskAnnouncement,
        task_digest: Digest,
        policy: Policy,
        limits: Limits,
    ) -> Result<Self, cybermesh_protocol::ProtocolError> {
        policy
            .validate()
            .map_err(cybermesh_protocol::ProtocolError::Invalid)?;
        let input_digest = task.input_digest()?;
        Ok(Self {
            task,
            task_digest,
            input_digest,
            policy,
            limits,
            held: BTreeMap::new(),
            rejected: Vec::new(),
            rejected_overflow: 0,
            faults: Vec::new(),
            faulted: BTreeSet::new(),
        })
    }

    #[must_use]
    pub fn task(&self) -> &TaskAnnouncement {
        &self.task
    }

    fn reject(&mut self, worker: Option<KeyId>, digest: Digest, reason: &str) -> SubmitOutcome {
        if self.rejected.len() < MAX_REJECTED {
            self.rejected.push(RejectedResult {
                worker,
                result_digest: digest,
                reason: reason.to_owned(),
            });
        } else {
            self.rejected_overflow += 1;
        }
        SubmitOutcome::Rejected(reason.to_owned())
    }

    fn fault(
        &mut self,
        worker: &KeyId,
        operator: &OperatorId,
        kind: FaultKind,
        evidence: Vec<Digest>,
    ) -> SubmitOutcome {
        self.faults.push(FaultRecord {
            worker: worker.clone(),
            operator: operator.clone(),
            kind,
            evidence,
        });
        self.faulted.insert(worker.clone());
        self.held.remove(worker);
        SubmitOutcome::Fault(kind)
    }

    /// Authenticates a result envelope and binds it to this task.
    pub fn submit(
        &mut self,
        bytes: &[u8],
        manifest: &TrustManifest,
        now: u64,
    ) -> SubmitOutcome {
        let raw_digest = Digest::of(bytes);
        let v = match verify_result(bytes, manifest, now, &self.limits) {
            Ok(v) => v,
            Err(e) => return self.reject(None, raw_digest, &format!("invalid result: {e}")),
        };
        let r = v.message;
        let digest = v.payload_digest;
        let worker = r.worker.clone();
        if r.task_id != self.task.task_id || r.attempt != self.task.attempt {
            return self.reject(Some(worker), digest, "result is for a different task or attempt");
        }
        if r.task_digest != self.task_digest {
            return self.reject(Some(worker), digest, "result answers a different task payload");
        }
        if !self.task.assignees.contains(&worker) {
            return self.reject(Some(worker), digest, "worker was not assigned this task");
        }
        if now > self.task.expires_at.saturating_add(self.policy.result_grace_secs) {
            return self.reject(Some(worker), digest, "result arrived after the deadline");
        }
        if self.faulted.contains(&worker) {
            return self.reject(Some(worker), digest, "worker already faulted on this task");
        }
        if let Some(prev) = self.held.get(&worker) {
            if prev.result_digest == digest {
                return SubmitOutcome::Duplicate;
            }
            let evidence = vec![prev.result_digest, digest];
            return self.fault(&worker, &r.operator, FaultKind::Equivocation, evidence);
        }
        if r.input_digest != self.input_digest {
            return self.fault(&worker, &r.operator, FaultKind::WrongInputDigest, vec![digest]);
        }
        if r.engine != self.task.engine || r.evidence != self.task.evidence {
            return self.reject(
                Some(worker),
                digest,
                "result used a different engine or evidence than the task pins",
            );
        }
        let domains: Vec<&str> = r.assessments.iter().map(|a| a.domain.as_str()).collect();
        let expected: Vec<&str> = self.task.domains.iter().map(String::as_str).collect();
        if domains != expected {
            return self.fault(&worker, &r.operator, FaultKind::DomainSetMismatch, vec![digest]);
        }
        let assessments_digest = match r.assessments_digest() {
            Ok(d) => d,
            Err(e) => return self.reject(Some(worker), digest, &e.to_string()),
        };
        self.held.insert(
            worker,
            Held {
                result: r,
                result_digest: digest,
                assessments_digest,
            },
        );
        SubmitOutcome::Accepted
    }

    /// True once every assignee has either delivered an accepted result or faulted.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.task
            .assignees
            .iter()
            .all(|a| self.held.contains_key(a) || self.faulted.contains(a))
    }

    /// Number of distinct operators with an accepted result so far.
    #[must_use]
    pub fn operators_responded(&self) -> usize {
        self.held
            .values()
            .map(|h| &h.result.operator)
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Assignees that have not yet delivered a result.
    #[must_use]
    pub fn missing(&self) -> Vec<KeyId> {
        self.task
            .assignees
            .iter()
            .filter(|a| !self.held.contains_key(*a) && !self.faulted.contains(*a))
            .cloned()
            .collect()
    }

    /// Settles the task.
    ///
    /// `engine` is the verifier's own engine. When it is present and its evidence matches
    /// the task pins, the verifier recomputes every domain and classifies **only** from its
    /// own result; workers whose signed assessments differ are recorded as provable faults.
    /// Without a matching engine the verifier cannot recompute, never classifies `block`,
    /// and records disagreement as `disputed`.
    pub fn finalize(mut self, engine: Option<&Engine>, now: u64) -> VerificationRecord {
        let engine = engine.filter(|e| e.check_task(&self.task).is_ok());

        // Per operator, the set of distinct assessment digests its workers signed.
        let mut by_operator: BTreeMap<OperatorId, BTreeSet<Digest>> = BTreeMap::new();
        for h in self.held.values() {
            by_operator
                .entry(h.result.operator.clone())
                .or_default()
                .insert(h.assessments_digest);
        }
        let distinct: BTreeSet<Digest> = by_operator.values().flatten().copied().collect();

        let mut recomputed = false;
        let mut accepted_digest: Option<Digest> = None;
        let mut accepted_assessments: Option<Vec<DomainAssessment>> = None;
        let mut status;

        let local = engine.and_then(|e| {
            let list = e.assess_task(&self.task).ok()?;
            let bytes = canonical::to_vec(&list).ok()?;
            Some((Digest::tagged("cybermesh/assessments/v1", &[&bytes]), list))
        });
        if let Some((local_digest, list)) = local {
            recomputed = true;
            accepted_digest = Some(local_digest);
            accepted_assessments = Some(list);
            // Every worker whose signed assessments differ has provably faulted.
            let wrong: Vec<(KeyId, OperatorId, Digest)> = self
                .held
                .iter()
                .filter(|(_, h)| h.assessments_digest != local_digest)
                .map(|(k, h)| (k.clone(), h.result.operator.clone(), h.result_digest))
                .collect();
            for (k, op, d) in wrong {
                self.faults.push(FaultRecord {
                    worker: k.clone(),
                    operator: op,
                    kind: FaultKind::IncorrectResult,
                    evidence: vec![d],
                });
                self.faulted.insert(k);
            }
        } else if distinct.len() == 1 {
            accepted_digest = distinct.iter().next().copied();
            accepted_assessments = self
                .held
                .values()
                .find(|h| Some(h.assessments_digest) == accepted_digest)
                .map(|h| h.result.assessments.clone());
        }

        // Operators all of whose workers signed the accepted digest.
        let agreeing: Vec<OperatorId> = by_operator
            .iter()
            .filter(|(_, ds)| ds.len() == 1 && ds.iter().next() == accepted_digest.as_ref())
            .map(|(op, _)| op.clone())
            .collect();
        let required = self
            .policy
            .min_operators
            .max(usize::from(self.task.min_operators));
        if accepted_digest.is_none() && distinct.len() > 1 {
            status = TaskStatus::Disputed;
        } else if agreeing.len() >= required {
            status = TaskStatus::Verified;
        } else {
            status = TaskStatus::Insufficient;
        }
        if accepted_assessments.is_none() && status == TaskStatus::Verified {
            status = TaskStatus::Insufficient;
        }

        let outcomes = match (&accepted_assessments, status) {
            (Some(list), TaskStatus::Verified) => list
                .iter()
                .map(|a| {
                    // Corroboration comes from the verifier's own evidence; when the engine
                    // is present `a` is also the verifier's own assessment.
                    let corroborated = recomputed && engine.is_some_and(|e| {
                        cybermesh_analysis::features::host_parts(&a.domain).is_some_and(|p| {
                            !e.evidence().blocklist_hits(p.host, p.registrable).is_empty()
                        })
                    });
                    let (classification, why) =
                        self.policy.classify(a, agreeing.len(), corroborated);
                    DomainOutcome {
                        domain: a.domain.clone(),
                        classification,
                        verdict: a.verdict,
                        risk_score_bp: a.risk_score_bp,
                        confidence_bp: a.confidence_bp,
                        findings: a.findings.clone(),
                        agreeing_operators: agreeing.clone(),
                        feed_corroborated: corroborated,
                        rationale: why.to_owned(),
                    }
                })
                .collect(),
            _ => Vec::new(),
        };

        let accepted = self
            .held
            .iter()
            .map(|(k, h)| AcceptedResult {
                worker: k.clone(),
                operator: h.result.operator.clone(),
                result_digest: h.result_digest,
                assessments_digest: h.assessments_digest,
                agreed: Some(h.assessments_digest) == accepted_digest,
            })
            .collect();

        VerificationRecord {
            v: PROTOCOL_VERSION,
            network_id: self.task.network_id.clone(),
            task_id: self.task.task_id.clone(),
            attempt: self.task.attempt,
            task_digest: self.task_digest,
            input_digest: self.input_digest,
            engine: self.task.engine.clone(),
            evidence: self.task.evidence.clone(),
            status,
            recomputed,
            accepted_assessments_digest: accepted_digest,
            accepted,
            rejected: self.rejected,
            rejected_overflow: self.rejected_overflow,
            faults: self.faults,
            outcomes,
            verified_at: now,
        }
    }
}

impl VerificationRecord {
    /// Outcomes eligible for publication.
    pub fn publishable(&self) -> impl Iterator<Item = &DomainOutcome> {
        self.outcomes
            .iter()
            .filter(|o| o.classification != Classification::None)
    }
}
