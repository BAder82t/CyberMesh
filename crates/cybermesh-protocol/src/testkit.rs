//! Deterministic fixtures for tests and simulations: a small permissioned network with
//! governance keys, operators, workers, an issuer, a verifier and release signers.
//!
//! Keys are derived from labels, so they are reproducible and MUST NOT be used outside
//! tests and local demonstrations.

use cybermesh_crypto::{Digest, Envelope, KeyId, SecretKey, canonical};
use serde::Serialize;

use crate::manifest::{GovernanceRoot, KeySet, Member, Operator, Role, SignerEntry, TrustManifest};
use crate::messages::{EngineSpec, EvidencePins, OperatorId, TaskAnnouncement, TaskKind};
use crate::{PROTOCOL_VERSION, payload_type};

/// Deterministic key derived from a label (tests only).
#[must_use]
pub fn test_key(label: &str) -> SecretKey {
    SecretKey::from_seed(Digest::tagged("cybermesh/testkit/key", &[label.as_bytes()]).as_bytes())
}

/// Signs a canonical payload into an envelope. Panics on encoding failure (test code).
#[allow(clippy::expect_used)]
pub fn sign<T: Serialize>(ptype: &str, value: &T, key: &SecretKey) -> Envelope {
    let bytes = canonical::to_vec(value).expect("test fixture must encode");
    Envelope::sign(ptype, &bytes, key)
}

/// Envelope bytes for a signed payload. Panics on encoding failure (test code).
#[allow(clippy::expect_used)]
pub fn sign_bytes<T: Serialize>(ptype: &str, value: &T, key: &SecretKey) -> Vec<u8> {
    sign(ptype, value, key)
        .to_vec()
        .expect("test envelope must encode")
}

/// One enrolled worker.
#[derive(Debug)]
pub struct TestWorker {
    pub key: SecretKey,
    pub operator: OperatorId,
    pub label: String,
}

/// A complete test network.
#[derive(Debug)]
pub struct TestNetwork {
    pub network_id: String,
    pub governance: Vec<SecretKey>,
    pub root: GovernanceRoot,
    pub issuer: SecretKey,
    pub verifier: SecretKey,
    pub workers: Vec<TestWorker>,
    pub release_signers: Vec<(SecretKey, OperatorId)>,
    pub manifest: TrustManifest,
    pub manifest_envelope: Envelope,
}

impl TestNetwork {
    /// Builds a network. `operators` lists `(operator_id, worker_count)`. Operator 0 also
    /// runs the issuer/verifier. The first three operators hold release-signing keys with a
    /// 2-of-3 threshold (or fewer if there are fewer operators).
    #[must_use]
    pub fn new(operators: &[(&str, usize)], now: u64) -> Self {
        let network_id = "cybermesh-test".to_owned();
        let governance: Vec<SecretKey> = (0..3).map(|i| test_key(&format!("gov-{i}"))).collect();
        let root = GovernanceRoot {
            network_id: network_id.clone(),
            threshold: 2,
            keys: governance.iter().map(SecretKey::public_key).collect(),
        };
        let ops: Vec<Operator> = operators
            .iter()
            .filter_map(|(id, _)| {
                Some(Operator {
                    id: OperatorId::new(id).ok()?,
                    name: format!("Organisation {id}"),
                })
            })
            .collect();
        let first_op = ops.first().map(|o| o.id.clone());
        let issuer = test_key("issuer");
        let verifier = test_key("verifier");
        let mut members = Vec::new();
        if let Some(op) = &first_op {
            members.push(Member {
                label: "issuer".into(),
                operator: op.clone(),
                public_key: issuer.public_key(),
                roles: vec![Role::Issuer],
            });
            members.push(Member {
                label: "verifier".into(),
                operator: op.clone(),
                public_key: verifier.public_key(),
                roles: vec![Role::Verifier],
            });
        }
        let mut workers = Vec::new();
        for (op, (id, n)) in ops.iter().zip(operators) {
            for i in 0..*n {
                let label = format!("{id}-worker-{i}");
                let key = test_key(&label);
                members.push(Member {
                    label: label.clone(),
                    operator: op.id.clone(),
                    public_key: key.public_key(),
                    roles: vec![Role::Worker],
                });
                workers.push(TestWorker {
                    key,
                    operator: op.id.clone(),
                    label,
                });
            }
        }
        let release_signers: Vec<(SecretKey, OperatorId)> = ops
            .iter()
            .take(3)
            .map(|o| (test_key(&format!("{}-release", o.id)), o.id.clone()))
            .collect();
        let threshold = u8::try_from(release_signers.len().min(2)).unwrap_or(1);
        let manifest = TrustManifest {
            v: PROTOCOL_VERSION,
            network_id: network_id.clone(),
            sequence: 1,
            issued_at: now,
            expires_at: now + 365 * 86_400,
            operators: ops,
            members,
            release_signers: KeySet {
                threshold,
                keys: release_signers
                    .iter()
                    .map(|(k, op)| SignerEntry {
                        label: format!("{op}-release"),
                        operator: op.clone(),
                        public_key: k.public_key(),
                    })
                    .collect(),
            },
            revocations: vec![],
        };
        let manifest_envelope = Self::sign_manifest_with(&governance, &manifest);
        Self {
            network_id,
            governance,
            root,
            issuer,
            verifier,
            workers,
            release_signers,
            manifest,
            manifest_envelope,
        }
    }

    /// Signs a manifest with the first two governance keys.
    #[must_use]
    pub fn sign_manifest_with(gov: &[SecretKey], m: &TrustManifest) -> Envelope {
        let mut env = sign(payload_type::MANIFEST, m, &gov[0]);
        for k in gov.iter().skip(1).take(1) {
            let _ = env.add_signature(k);
        }
        env
    }

    /// Re-signs the current manifest (after mutating it in a test).
    pub fn resign_manifest(&mut self) {
        self.manifest_envelope = Self::sign_manifest_with(&self.governance, &self.manifest);
    }

    /// A task for the given domains (sorted internally) assigned to the given workers.
    #[must_use]
    pub fn task(
        &self,
        domains: &[&str],
        assignees: &[usize],
        engine: EngineSpec,
        evidence: EvidencePins,
        now: u64,
    ) -> TaskAnnouncement {
        let mut ds: Vec<String> = domains.iter().map(|s| (*s).to_owned()).collect();
        ds.sort();
        ds.dedup();
        let ops: std::collections::BTreeSet<_> = assignees
            .iter()
            .map(|i| &self.workers[*i].operator)
            .collect();
        let task_id = Digest::tagged(
            "testkit/task",
            &[ds.join(",").as_bytes(), &now.to_be_bytes()],
        );
        TaskAnnouncement {
            v: PROTOCOL_VERSION,
            network_id: self.network_id.clone(),
            task_id: task_id.hex()[..32].to_owned(),
            attempt: 0,
            kind: TaskKind::DomainRiskAssessment,
            issuer: self.issuer.key_id(),
            issued_at: now,
            expires_at: now + 600,
            nonce: task_id.hex()[32..].to_owned(),
            engine,
            evidence,
            domains: ds,
            assignees: assignees
                .iter()
                .map(|i| self.workers[*i].key.key_id())
                .collect(),
            min_operators: u8::try_from(ops.len().min(3)).unwrap_or(1),
        }
    }

    #[must_use]
    pub fn worker_id(&self, i: usize) -> KeyId {
        self.workers[i].key.key_id()
    }
}
