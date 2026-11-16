use std::collections::BTreeSet;

use cybermesh_crypto::{CryptoError, Digest, Envelope, KeyId, canonical};
use cybermesh_protocol::domain::is_normalized_domain;
use cybermesh_protocol::{OperatorId, PROTOCOL_VERSION, SignerEntry, TrustManifest, payload_type};
use serde::{Deserialize, Serialize};

use crate::model::ThreatRelease;
use crate::{MAX_ENTRIES, MAX_RELEASE_BYTES, MAX_RELEASE_TTL_SECS, MAX_SEQUENCE_JUMP};

/// Limits on free-text and list fields (consumers render these to users).
const MAX_REASONS: usize = 16;
const MAX_EVIDENCE: usize = 16;
const MAX_DETAIL: usize = 200;
const MAX_NOTE: usize = 500;
const MAX_REFERENCE: usize = 128;

fn printable(s: &str, max: usize) -> bool {
    s.len() <= max && s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// Allowed clock skew for `issued_at`.
pub const MAX_RELEASE_SKEW_SECS: u64 = 300;

/// Pinned release-signing keys and the number of distinct operators that must sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRoot {
    pub network_id: String,
    pub threshold: u8,
    pub signers: Vec<SignerEntry>,
}

impl TrustRoot {
    /// Derives the consumer trust root from a verified manifest (revoked keys excluded).
    #[must_use]
    pub fn from_manifest(m: &TrustManifest) -> Self {
        Self {
            network_id: m.network_id.clone(),
            threshold: m.release_signers.threshold,
            signers: m
                .release_signers
                .keys
                .iter()
                .filter(|k| !m.is_revoked(&k.public_key.key_id()))
                .cloned()
                .collect(),
        }
    }
}

/// What a consumer remembers between updates (anti-rollback state).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerState {
    pub sequence: u64,
    pub digest: Digest,
}

/// A release that passed every check.
#[derive(Debug, Clone)]
pub struct VerifiedRelease {
    pub release: ThreatRelease,
    pub digest: Digest,
    pub signers: Vec<KeyId>,
    pub operators: Vec<OperatorId>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReleaseError {
    #[error("envelope: {0}")]
    Envelope(CryptoError),
    #[error("signatures from {valid_operators} distinct operators, {required} required")]
    Threshold {
        valid_operators: usize,
        required: usize,
    },
    #[error("release is for network {0}")]
    WrongNetwork(String),
    #[error("unsupported release version {0}")]
    Version(u16),
    #[error("release expired")]
    Expired,
    #[error("release issued in the future")]
    NotYetValid,
    #[error("rollback: release sequence {got} is older than accepted sequence {last}")]
    Rollback { got: u64, last: u64 },
    #[error("two different releases claim sequence {0}")]
    Equivocation(u64),
    #[error("invalid release: {0}")]
    Invalid(String),
}

/// Verifies a release envelope offline.
pub fn verify_release(
    bytes: &[u8],
    root: &TrustRoot,
    now: u64,
    state: Option<&ConsumerState>,
) -> Result<VerifiedRelease, ReleaseError> {
    let required = usize::from(root.threshold);
    if required == 0 {
        return Err(ReleaseError::Invalid(
            "trust root threshold must be >= 1".into(),
        ));
    }
    let env = Envelope::parse(bytes, MAX_RELEASE_BYTES).map_err(ReleaseError::Envelope)?;
    let lookup = |id: &KeyId| {
        root.signers
            .iter()
            .find(|s| &s.public_key.key_id() == id)
            .map(|s| s.public_key)
    };
    let v = match env.verify(payload_type::RELEASE, 1, lookup) {
        Ok(v) => v,
        Err(CryptoError::InsufficientSignatures { .. }) => {
            return Err(ReleaseError::Threshold {
                valid_operators: 0,
                required,
            });
        }
        Err(e) => return Err(ReleaseError::Envelope(e)),
    };
    let operators: BTreeSet<OperatorId> = v
        .signers
        .iter()
        .filter_map(|id| {
            root.signers
                .iter()
                .find(|s| &s.public_key.key_id() == id)
                .map(|s| s.operator.clone())
        })
        .collect();
    if operators.len() < required {
        return Err(ReleaseError::Threshold {
            valid_operators: operators.len(),
            required,
        });
    }
    let release: ThreatRelease =
        canonical::from_slice(&v.payload).map_err(ReleaseError::Envelope)?;
    if release.v != PROTOCOL_VERSION {
        return Err(ReleaseError::Version(release.v));
    }
    if release.network_id != root.network_id {
        return Err(ReleaseError::WrongNetwork(release.network_id));
    }
    if release.issued_at > now + MAX_RELEASE_SKEW_SECS {
        return Err(ReleaseError::NotYetValid);
    }
    if now >= release.expires_at {
        return Err(ReleaseError::Expired);
    }
    if release.expires_at <= release.issued_at
        || release.expires_at - release.issued_at > MAX_RELEASE_TTL_SECS
    {
        return Err(ReleaseError::Invalid(
            "release lifetime out of range".into(),
        ));
    }
    if release.entries.len() > MAX_ENTRIES {
        return Err(ReleaseError::Invalid("too many entries".into()));
    }
    let mut prev: Option<&str> = None;
    for e in &release.entries {
        if !is_normalized_domain(&e.indicator) {
            return Err(ReleaseError::Invalid(format!(
                "bad indicator {}",
                e.indicator
            )));
        }
        if prev.is_some_and(|p| p >= e.indicator.as_str()) {
            return Err(ReleaseError::Invalid("entries not sorted/unique".into()));
        }
        if e.risk_score_bp > 10_000 {
            return Err(ReleaseError::Invalid("score out of range".into()));
        }
        if e.reasons.len() > MAX_REASONS
            || e.evidence.len() > MAX_EVIDENCE
            || e.reasons.iter().any(|r| !printable(&r.detail, MAX_DETAIL))
            || e.evidence.iter().any(|r| !printable(&r.id, MAX_REFERENCE))
        {
            return Err(ReleaseError::Invalid(format!(
                "entry {} has oversized or non-printable fields",
                e.indicator
            )));
        }
        prev = Some(&e.indicator);
    }
    for w in release.corrections.windows(2) {
        if w[0] >= w[1] {
            return Err(ReleaseError::Invalid(
                "corrections not sorted/unique".into(),
            ));
        }
    }
    if release.corrections.iter().any(|c| {
        !printable(&c.indicator, 253)
            || !printable(&c.reference, MAX_REFERENCE)
            || !printable(&c.note, MAX_NOTE)
    }) {
        return Err(ReleaseError::Invalid(
            "correction has oversized or non-printable fields".into(),
        ));
    }
    let digest = Digest::of(&v.payload);
    if let Some(s) = state {
        if release.sequence < s.sequence {
            return Err(ReleaseError::Rollback {
                got: release.sequence,
                last: s.sequence,
            });
        }
        if release.sequence == s.sequence && digest != s.digest {
            return Err(ReleaseError::Equivocation(release.sequence));
        }
        if release.sequence - s.sequence > MAX_SEQUENCE_JUMP {
            return Err(ReleaseError::Invalid("sequence jump too large".into()));
        }
        // The immediate successor must chain to the release the consumer holds.
        if release.sequence == s.sequence + 1
            && let Some(p) = &release.previous
            && (p.sequence != s.sequence || p.digest != s.digest)
        {
            return Err(ReleaseError::Invalid(
                "previous-release link does not match the accepted release (fork)".into(),
            ));
        }
    }
    Ok(VerifiedRelease {
        release,
        digest,
        signers: v.signers,
        operators: operators.into_iter().collect(),
    })
}
