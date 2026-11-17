//! Verification of Certificate Transparency shard scans.
//!
//! Recomputing every shard would make the workers pointless, so verification combines:
//!
//! 1. **Binding**: authenticated results bound to the exact task (digest, attempt,
//!    assignee, deadline, input digest, log id, tile list). Equivocation is a fault.
//! 2. **Log commitments**: each worker's per-tile root must equal the log's own level-1
//!    hash for that tile (32 bytes per tile from the log). A mismatch proves the worker did
//!    not process the log's entries.
//! 3. **Spot checks**: the verifier re-scans a sample of tiles chosen from a secret seed
//!    (workers cannot predict them). Any worker whose signed tile result differs is faulted.
//! 4. **Cross-operator agreement**: tiles must agree across at least `min_operators`
//!    operators; on any disagreement the verifier re-scans *all* tiles and its own result
//!    becomes authoritative (disagreement is rare and justifies the cost).
//!
//! Without an oracle (no access to the log) the verifier cannot settle disagreement and
//! records `disputed`. CT-derived outcomes are capped at `warn`: a certificate for a
//! lookalike name is a signal of possible impersonation, not proof of phishing.

use std::collections::{BTreeMap, BTreeSet};

use cybermesh_analysis::Engine;
use cybermesh_crypto::{Digest, KeyId};
use cybermesh_protocol::ct::{CtMatch, CtScanResult, CtScanTask, TileScanResult, verify_ct_result};
use cybermesh_protocol::{Limits, OperatorId, PROTOCOL_VERSION, ProtocolError, TrustManifest};
use serde::{Deserialize, Serialize};

use crate::policy::{Classification, Policy};
use crate::record::{
    AcceptedResult, DomainOutcome, FaultKind, FaultRecord, MAX_REJECTED, RejectedResult,
    TaskStatus, VerificationRecord,
};
use crate::task::SubmitOutcome;

/// Access to the CT log for verification (provided by the verifier's node).
pub trait CtOracle {
    /// The log's own root for a full data tile (level-1 hash tile entry).
    fn tile_root(&self, log_id: &str, tile: u64) -> Option<Digest>;
    /// The verifier's own scan of a tile with its own engine and evidence.
    fn rescan(&self, log_id: &str, tile: u64) -> Option<TileScanResult>;
}

/// CT verification policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CtPolicy {
    /// Distinct operators that must agree on a shard (default 2: CT is advisory-only).
    pub min_operators: usize,
    /// Tiles re-scanned per task by the verifier.
    pub spot_check_tiles: usize,
    /// Check every tile root against the log's hash tiles.
    pub check_log_roots: bool,
    pub result_grace_secs: u64,
    /// Publish CT findings as advisory warnings in releases. Off by default: on real CT data
    /// most brand signals are the brand owners' own infrastructure, so findings go to the
    /// investigation report for triage instead.
    #[serde(default)]
    pub publish_warnings: bool,
    /// When publishing: minimum score (verifier's own assessment).
    #[serde(default = "default_publish_min")]
    pub publish_min_score_bp: u16,
}

fn default_publish_min() -> u16 {
    7000
}

/// Signals strong enough to publish from CT alone: a typosquat or a homograph, not merely a
/// brand token appearing inside a name (which brand owners use for their own services).
fn publishable_signal(a: &cybermesh_protocol::DomainAssessment) -> bool {
    a.findings.iter().any(|f| {
        matches!(
            f.code,
            cybermesh_protocol::FindingCode::BrandLookalike
                | cybermesh_protocol::FindingCode::IdnHomograph
        )
    })
}

impl Default for CtPolicy {
    fn default() -> Self {
        Self {
            min_operators: 2,
            spot_check_tiles: 1,
            check_log_roots: true,
            result_grace_secs: 60,
            publish_warnings: false,
            publish_min_score_bp: default_publish_min(),
        }
    }
}

/// CT-specific details stored in the verification record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CtScanDetail {
    pub log_id: String,
    pub first_tile: u64,
    pub tile_count: u32,
    /// Tiles whose roots were checked against the log.
    pub tiles_checked_against_log: u32,
    /// Tiles the verifier re-scanned itself.
    pub tiles_rescanned: Vec<u64>,
    pub entries: u64,
    pub unparsed: u64,
    /// All matches in the accepted tiles (brand signals, including below warn threshold),
    /// for investigation reports.
    pub matches: Vec<CtMatch>,
}

#[derive(Debug, Clone)]
struct Held {
    result: CtScanResult,
    result_digest: Digest,
    tiles_digest: Digest,
}

/// Collects and verifies results for one CT task attempt.
#[derive(Debug)]
pub struct CtTaskVerifier {
    task: CtScanTask,
    task_digest: Digest,
    input_digest: Digest,
    policy: CtPolicy,
    classify: Policy,
    limits: Limits,
    held: BTreeMap<KeyId, Held>,
    rejected: Vec<RejectedResult>,
    rejected_overflow: u64,
    faults: Vec<FaultRecord>,
    faulted: BTreeSet<KeyId>,
}

impl CtTaskVerifier {
    pub fn new(
        task: CtScanTask,
        task_digest: Digest,
        policy: CtPolicy,
        classify: Policy,
        limits: Limits,
    ) -> Result<Self, ProtocolError> {
        if policy.min_operators == 0 {
            return Err(ProtocolError::Invalid(
                "min_operators must be at least 1".into(),
            ));
        }
        classify.validate().map_err(ProtocolError::Invalid)?;
        let input_digest = task.input_digest()?;
        Ok(Self {
            task,
            task_digest,
            input_digest,
            policy,
            classify,
            limits,
            held: BTreeMap::new(),
            rejected: Vec::new(),
            rejected_overflow: 0,
            faults: Vec::new(),
            faulted: BTreeSet::new(),
        })
    }

    #[must_use]
    pub fn task(&self) -> &CtScanTask {
        &self.task
    }

    #[must_use]
    pub fn task_digest(&self) -> Digest {
        self.task_digest
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

    /// Authenticates a CT result envelope and binds it to this task.
    pub fn submit(&mut self, bytes: &[u8], manifest: &TrustManifest, now: u64) -> SubmitOutcome {
        let raw = Digest::of(bytes);
        let v = match verify_ct_result(bytes, manifest, now, &self.limits) {
            Ok(v) => v,
            Err(e) => return self.reject(None, raw, &format!("invalid result: {e}")),
        };
        let r = v.message;
        let digest = v.payload_digest;
        let worker = r.worker.clone();
        if r.task_id != self.task.task_id
            || r.attempt != self.task.attempt
            || r.task_digest != self.task_digest
        {
            return self.reject(Some(worker), digest, "result answers a different task");
        }
        if !self.task.assignees.contains(&worker) {
            return self.reject(Some(worker), digest, "worker was not assigned this task");
        }
        if now
            > self
                .task
                .expires_at
                .saturating_add(self.policy.result_grace_secs)
        {
            return self.reject(Some(worker), digest, "result arrived after the deadline");
        }
        if self.faulted.contains(&worker) {
            return self.reject(Some(worker), digest, "worker already faulted on this task");
        }
        if let Some(prev) = self.held.get(&worker) {
            if prev.result_digest == digest {
                return SubmitOutcome::Duplicate;
            }
            let ev = vec![prev.result_digest, digest];
            return self.fault(&worker, &r.operator, FaultKind::Equivocation, ev);
        }
        if r.input_digest != self.input_digest {
            return self.fault(
                &worker,
                &r.operator,
                FaultKind::WrongInputDigest,
                vec![digest],
            );
        }
        if r.engine != self.task.engine
            || r.evidence != self.task.evidence
            || r.log_id != self.task.log_id
        {
            return self.reject(
                Some(worker),
                digest,
                "result used a different engine, evidence or log",
            );
        }
        let tiles: Vec<u64> = r.tiles.iter().map(|t| t.tile_index).collect();
        let expected: Vec<u64> = self.task.tiles().collect();
        if tiles != expected {
            return self.fault(
                &worker,
                &r.operator,
                FaultKind::DomainSetMismatch,
                vec![digest],
            );
        }
        let tiles_digest = match r.tiles_digest() {
            Ok(d) => d,
            Err(e) => return self.reject(Some(worker), digest, &e.to_string()),
        };
        self.held.insert(
            worker,
            Held {
                result: r,
                result_digest: digest,
                tiles_digest,
            },
        );
        SubmitOutcome::Accepted
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.task
            .assignees
            .iter()
            .all(|a| self.held.contains_key(a) || self.faulted.contains(a))
    }

    #[must_use]
    pub fn missing(&self) -> Vec<KeyId> {
        self.task
            .assignees
            .iter()
            .filter(|a| !self.held.contains_key(*a) && !self.faulted.contains(*a))
            .cloned()
            .collect()
    }

    fn fault_workers_where<F: Fn(&Held) -> bool>(&mut self, pred: F, kind: FaultKind) {
        let bad: Vec<(KeyId, OperatorId, Digest)> = self
            .held
            .iter()
            .filter(|(_, h)| pred(h))
            .map(|(k, h)| (k.clone(), h.result.operator.clone(), h.result_digest))
            .collect();
        for (k, op, d) in bad {
            self.faults.push(FaultRecord {
                worker: k.clone(),
                operator: op,
                kind,
                evidence: vec![d],
            });
            self.faulted.insert(k.clone());
            self.held.remove(&k);
        }
    }

    /// Settles the task. `engine` is the verifier's engine (used to classify matched names
    /// from its own assessment); `oracle` gives access to the log; `seed` is secret.
    ///
    /// Publication is "pay for what you publish": before any match becomes an advisory
    /// warning, the verifier re-scans the tiles containing publishable matches. Fabricated or
    /// altered matches are therefore never published, at a cost proportional to findings
    /// rather than to the scanned volume.
    pub fn finalize(
        mut self,
        engine: Option<&Engine>,
        oracle: Option<&dyn CtOracle>,
        seed: &[u8],
        now: u64,
    ) -> VerificationRecord {
        let log_id = self.task.log_id.clone();
        let tiles: Vec<u64> = self.task.tiles().collect();
        let mut checked_against_log = 0u32;
        let mut rescanned: BTreeMap<u64, TileScanResult> = BTreeMap::new();
        let rescan =
            |t: u64, cache: &mut BTreeMap<u64, TileScanResult>| -> Option<TileScanResult> {
                if let Some(r) = cache.get(&t) {
                    return Some(r.clone());
                }
                let r = oracle?.rescan(&log_id, t)?;
                cache.insert(t, r.clone());
                Some(r)
            };

        if let Some(o) = oracle {
            // (2) Commitments against the log's own hashes.
            if self.policy.check_log_roots {
                let mut roots: BTreeMap<u64, Digest> = BTreeMap::new();
                for t in &tiles {
                    if let Some(r) = o.tile_root(&log_id, *t) {
                        roots.insert(*t, r);
                        checked_against_log += 1;
                    }
                }
                self.fault_workers_where(
                    |h| {
                        h.result
                            .tiles
                            .iter()
                            .any(|t| roots.get(&t.tile_index).is_some_and(|r| *r != t.root))
                    },
                    FaultKind::IncorrectResult,
                );
            }
            // (3) Unpredictable spot checks (catch omitted matches).
            let mut picks = BTreeSet::new();
            for i in 0..self.policy.spot_check_tiles.min(tiles.len()) {
                let d = Digest::tagged(
                    "cybermesh/ct-spot-check/v1",
                    &[
                        seed,
                        self.task.task_id.as_bytes(),
                        &(i as u64).to_be_bytes(),
                    ],
                );
                let r = u64::from_be_bytes(d.0[..8].try_into().unwrap_or([0u8; 8]));
                picks.insert(tiles[usize::try_from(r % tiles.len() as u64).unwrap_or(0)]);
            }
            for t in picks {
                let _ = rescan(t, &mut rescanned);
            }
            let snapshot = rescanned.clone();
            self.fault_workers_where(
                |h| {
                    h.result
                        .tiles
                        .iter()
                        .any(|t| snapshot.get(&t.tile_index).is_some_and(|m| m != t))
                },
                FaultKind::IncorrectResult,
            );
        }

        // (4) Agreement between the remaining operators.
        let operator_digests = |held: &BTreeMap<KeyId, Held>| {
            let mut m: BTreeMap<OperatorId, BTreeSet<Digest>> = BTreeMap::new();
            for h in held.values() {
                m.entry(h.result.operator.clone())
                    .or_default()
                    .insert(h.tiles_digest);
            }
            m
        };
        let digest_of = |t: &Vec<TileScanResult>| {
            cybermesh_crypto::canonical::to_vec(t)
                .ok()
                .map(|b| Digest::tagged("cybermesh/ct-tiles/v1", &[&b]))
        };
        let full_rescan =
            |cache: &mut BTreeMap<u64, TileScanResult>| -> Option<Vec<TileScanResult>> {
                let mut mine = Vec::with_capacity(tiles.len());
                for t in &tiles {
                    mine.push(rescan(*t, cache)?);
                }
                Some(mine)
            };
        let distinct: BTreeSet<Digest> = operator_digests(&self.held)
            .values()
            .flatten()
            .copied()
            .collect();
        let mut authoritative: Option<Vec<TileScanResult>> = if distinct.len() > 1 {
            full_rescan(&mut rescanned)
        } else {
            distinct.iter().next().and_then(|d| {
                self.held
                    .values()
                    .find(|h| h.tiles_digest == *d)
                    .map(|h| h.result.tiles.clone())
            })
        };

        // (5) Confirm every tile that would produce a published warning.
        let mut verifier_view: BTreeMap<String, cybermesh_protocol::DomainAssessment> =
            BTreeMap::new();
        let publish = self.policy.publish_warnings;
        let min_score = self.policy.publish_min_score_bp;
        let publishable = |a: &cybermesh_protocol::DomainAssessment, c: Classification| {
            publish
                && c != Classification::None
                && a.risk_score_bp >= min_score
                && publishable_signal(a)
        };
        if let (Some(auth), Some(e)) = (&authoritative, engine) {
            let mut need = BTreeSet::new();
            for t in auth {
                for m in &t.matches {
                    if let Ok(a) = e.assess(&m.name) {
                        let (c, _) = self.classify.classify(&a, usize::MAX, false);
                        if publishable(&a, c) {
                            need.insert(t.tile_index);
                        }
                        verifier_view.insert(m.name.clone(), a);
                    }
                }
            }
            let mut mismatch = false;
            for t in &need {
                match rescan(*t, &mut rescanned) {
                    Some(mine) => {
                        if auth.iter().find(|x| x.tile_index == *t) != Some(&mine) {
                            mismatch = true;
                        }
                    }
                    None => mismatch = true, // cannot confirm: do not publish from claims
                }
            }
            if mismatch {
                authoritative = full_rescan(&mut rescanned);
            }
        }
        if let Some(auth) = &authoritative {
            let d = digest_of(auth);
            self.fault_workers_where(|h| Some(h.tiles_digest) != d, FaultKind::IncorrectResult);
        }

        let auth_digest = authoritative.as_ref().and_then(digest_of);
        let agreeing: Vec<OperatorId> = operator_digests(&self.held)
            .iter()
            .filter(|(_, ds)| ds.len() == 1 && ds.iter().next() == auth_digest.as_ref())
            .map(|(op, _)| op.clone())
            .collect();
        let required = self
            .policy
            .min_operators
            .max(usize::from(self.task.min_operators));
        let status = if authoritative.is_none() && distinct.len() > 1 {
            TaskStatus::Disputed
        } else if authoritative.is_some() && agreeing.len() >= required {
            TaskStatus::Verified
        } else {
            TaskStatus::Insufficient
        };

        let mut outcomes = Vec::new();
        let mut detail_matches = Vec::new();
        let (mut entries, mut unparsed) = (0u64, 0u64);
        if let (TaskStatus::Verified, Some(auth)) = (status, &authoritative) {
            let classify = Policy {
                min_operators: self.policy.min_operators,
                ..self.classify.clone()
            };
            let mut seen = BTreeSet::new();
            for t in auth {
                entries += u64::from(t.leaf_count);
                unparsed += u64::from(t.unparsed);
                let confirmed = rescanned.contains_key(&t.tile_index);
                for m in &t.matches {
                    detail_matches.push(m.clone());
                    if !confirmed || !seen.insert(m.name.clone()) {
                        continue;
                    }
                    // Classify from the verifier's own assessment, never the worker's claim;
                    // CT evidence alone is capped at an advisory warning.
                    let Some(a) = verifier_view.get(&m.name) else {
                        continue;
                    };
                    let (c, why) = classify.classify(a, agreeing.len(), false);
                    if !publishable(a, c) {
                        continue;
                    }
                    outcomes.push(DomainOutcome {
                        domain: a.domain.clone(),
                        classification: Classification::Warn,
                        verdict: a.verdict,
                        risk_score_bp: a.risk_score_bp,
                        confidence_bp: a.confidence_bp,
                        findings: a.findings.clone(),
                        agreeing_operators: agreeing.clone(),
                        feed_corroborated: false,
                        rationale: format!(
                            "newly certified name in CT log {log_id} entry {}; {why} (CT evidence is advisory only)",
                            m.index
                        ),
                    });
                }
            }
            outcomes.sort_by(|a, b| a.domain.cmp(&b.domain));
        }

        let accepted = self
            .held
            .iter()
            .map(|(k, h)| AcceptedResult {
                worker: k.clone(),
                operator: h.result.operator.clone(),
                result_digest: h.result_digest,
                assessments_digest: h.tiles_digest,
                agreed: Some(h.tiles_digest) == auth_digest,
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
            recomputed: !rescanned.is_empty(),
            accepted_assessments_digest: auth_digest,
            accepted,
            rejected: self.rejected,
            rejected_overflow: self.rejected_overflow,
            faults: self.faults,
            outcomes,
            verified_at: now,
            ct: Some(CtScanDetail {
                log_id,
                first_tile: self.task.first_tile,
                tile_count: self.task.tile_count,
                tiles_checked_against_log: checked_against_log,
                tiles_rescanned: rescanned.keys().copied().collect(),
                entries,
                unparsed,
                matches: detail_matches,
            }),
        }
    }
}
