//! The governance-signed trust manifest: who may participate, in which role, and which keys
//! have been revoked. Nodes pin a [`GovernanceRoot`] in configuration and accept a manifest
//! only if it carries a threshold of governance signatures and is not older than the last
//! manifest they accepted.

use std::collections::{BTreeMap, BTreeSet};

use cybermesh_crypto::{Envelope, KeyId, PublicKey, canonical};
use serde::{Deserialize, Serialize};

use crate::messages::OperatorId;
use crate::{PROTOCOL_VERSION, ProtocolError, payload_type};

/// Allowed clock skew for a manifest's `issued_at`.
pub const MAX_MANIFEST_SKEW_SECS: u64 = 300;
/// Maximum manifest lifetime (forces periodic re-signing by governance).
pub const MAX_MANIFEST_LIFETIME_SECS: u64 = 400 * 86_400;

/// Roles a member key can hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Executes analysis tasks.
    Worker,
    /// Publishes task announcements.
    Issuer,
    /// Verifies results and produces verification records.
    Verifier,
}

impl Role {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Worker => "worker",
            Role::Issuer => "issuer",
            Role::Verifier => "verifier",
        }
    }
}

/// A participating organisation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operator {
    pub id: OperatorId,
    pub name: String,
}

/// A node key enrolled by an operator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub label: String,
    pub operator: OperatorId,
    pub public_key: PublicKey,
    pub roles: Vec<Role>,
}

/// A key allowed to co-sign releases.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerEntry {
    pub label: String,
    pub operator: OperatorId,
    pub public_key: PublicKey,
}

/// A k-of-n signer set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySet {
    pub threshold: u8,
    pub keys: Vec<SignerEntry>,
}

/// A revoked key. Revocation is permanent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub key_id: KeyId,
    pub revoked_at: u64,
    pub reason: String,
}

/// The trust manifest payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustManifest {
    pub v: u16,
    pub network_id: String,
    /// Monotonic; nodes refuse manifests older than the last one they accepted.
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub operators: Vec<Operator>,
    pub members: Vec<Member>,
    pub release_signers: KeySet,
    pub revocations: Vec<Revocation>,
    /// Distinct verifier operators whose verified records must agree before an indicator is
    /// published (and, for `block`, must each classify it `block`). Omitted when 1, the
    /// single-verifier behaviour of v0.1.
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub min_verifiers: u8,
}

fn one() -> u8 {
    1
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_one(v: &u8) -> bool {
    *v == 1
}

/// Pinned governance keys (trust anchor), distributed out of band with node configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceRoot {
    pub network_id: String,
    pub threshold: u8,
    pub keys: Vec<PublicKey>,
    /// Lowest manifest sequence a node accepts, even on first start or after its state
    /// directory was lost. Governance raises it when distributing the root, so an old (but
    /// unexpired) manifest cannot be replayed to a fresh node. Omitted when 0.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub min_sequence: u64,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(v: &u64) -> bool {
    *v == 0
}

impl GovernanceRoot {
    /// Verifies a governance-signed envelope of the given payload type.
    pub fn verify_envelope(
        &self,
        env: &Envelope,
        payload_type: &str,
    ) -> Result<Vec<u8>, ProtocolError> {
        if self.threshold == 0 || usize::from(self.threshold) > self.keys.len() {
            return Err(ProtocolError::invalid("governance threshold out of range"));
        }
        let table: BTreeMap<KeyId, PublicKey> =
            self.keys.iter().map(|k| (k.key_id(), *k)).collect();
        let v = env.verify(payload_type, usize::from(self.threshold), |id| {
            table.get(id).copied()
        })?;
        Ok(v.payload)
    }
}

impl TrustManifest {
    /// Verifies a signed manifest against the pinned governance root.
    pub fn verify(
        env: &Envelope,
        root: &GovernanceRoot,
        now: u64,
        min_sequence: u64,
    ) -> Result<Self, ProtocolError> {
        let payload = root.verify_envelope(env, payload_type::MANIFEST)?;
        let m: TrustManifest = canonical::from_slice(&payload)?;
        if m.v != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(m.v));
        }
        if m.network_id != root.network_id {
            return Err(ProtocolError::WrongNetwork {
                expected: root.network_id.clone(),
                actual: m.network_id,
            });
        }
        if m.sequence < min_sequence {
            return Err(ProtocolError::Rollback {
                got: m.sequence,
                min: min_sequence,
            });
        }
        if now >= m.expires_at {
            return Err(ProtocolError::Expired);
        }
        if m.issued_at > now.saturating_add(MAX_MANIFEST_SKEW_SECS) {
            return Err(ProtocolError::NotYetValid);
        }
        if m.expires_at <= m.issued_at || m.expires_at - m.issued_at > MAX_MANIFEST_LIFETIME_SECS {
            return Err(ProtocolError::TtlTooLong);
        }
        m.validate()?;
        Ok(m)
    }

    /// Structural consistency checks.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let ops: BTreeSet<&OperatorId> = self.operators.iter().map(|o| &o.id).collect();
        if ops.len() != self.operators.len() {
            return Err(ProtocolError::invalid("duplicate operator id"));
        }
        let mut keys = BTreeSet::new();
        for m in &self.members {
            if !ops.contains(&m.operator) {
                return Err(ProtocolError::invalid(format!(
                    "member {} references unknown operator {}",
                    m.label, m.operator
                )));
            }
            if m.roles.is_empty() {
                return Err(ProtocolError::invalid(format!(
                    "member {} has no roles",
                    m.label
                )));
            }
            if !keys.insert(m.public_key) {
                return Err(ProtocolError::invalid("duplicate member key"));
            }
        }
        let rs = &self.release_signers;
        if rs.threshold == 0 || usize::from(rs.threshold) > rs.keys.len() {
            return Err(ProtocolError::invalid(
                "release signer threshold out of range",
            ));
        }
        let mut rkeys = BTreeSet::new();
        for k in &rs.keys {
            if !ops.contains(&k.operator) {
                return Err(ProtocolError::invalid(
                    "release signer references unknown operator",
                ));
            }
            if !rkeys.insert(k.public_key) {
                return Err(ProtocolError::invalid("duplicate release signer key"));
            }
        }
        // A quorum above 1 must be reachable by non-revoked verifiers of distinct operators.
        // (1 is the v0.1 behaviour and is always accepted.)
        if self.min_verifiers == 0
            || (self.min_verifiers > 1
                && usize::from(self.min_verifiers) > self.verifier_operators().len())
        {
            return Err(ProtocolError::invalid(
                "min_verifiers must be between 1 and the number of operators with non-revoked verifier keys",
            ));
        }
        Ok(())
    }

    /// Distinct operators holding a non-revoked verifier key.
    #[must_use]
    pub fn verifier_operators(&self) -> BTreeSet<&OperatorId> {
        self.members_with_role(Role::Verifier)
            .map(|m| &m.operator)
            .collect()
    }

    #[must_use]
    pub fn is_revoked(&self, kid: &KeyId) -> bool {
        self.revocations.iter().any(|r| &r.key_id == kid)
    }

    /// The enrolled, non-revoked member with this key id.
    #[must_use]
    pub fn member(&self, kid: &KeyId) -> Option<&Member> {
        if self.is_revoked(kid) {
            return None;
        }
        self.members.iter().find(|m| &m.public_key.key_id() == kid)
    }

    /// The public key of a non-revoked member holding `role`.
    #[must_use]
    pub fn key_with_role(&self, kid: &KeyId, role: Role) -> Option<PublicKey> {
        self.member(kid)
            .filter(|m| m.roles.contains(&role))
            .map(|m| m.public_key)
    }

    #[must_use]
    pub fn operator_of(&self, kid: &KeyId) -> Option<&OperatorId> {
        self.member(kid).map(|m| &m.operator)
    }

    /// Non-revoked members holding a role.
    pub fn members_with_role(&self, role: Role) -> impl Iterator<Item = &Member> {
        self.members
            .iter()
            .filter(move |m| m.roles.contains(&role) && !self.is_revoked(&m.public_key.key_id()))
    }

    /// Release signer keys that are not revoked.
    #[must_use]
    pub fn release_signer_table(&self) -> BTreeMap<KeyId, PublicKey> {
        self.release_signers
            .keys
            .iter()
            .map(|k| (k.public_key.key_id(), k.public_key))
            .filter(|(id, _)| !self.is_revoked(id))
            .collect()
    }
}
