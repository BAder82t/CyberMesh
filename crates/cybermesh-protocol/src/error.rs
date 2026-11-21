use cybermesh_crypto::CryptoError;
use thiserror::Error;

/// Reasons a message is rejected. Variants are stable so they can be counted in metrics.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("message is for network {actual}, expected {expected}")]
    WrongNetwork { expected: String, actual: String },
    #[error("signer is not authorised for role {0}")]
    NotAuthorized(&'static str),
    #[error("signer does not match the identity claimed in the payload")]
    SignerMismatch,
    /// The payload disagrees with this node's manifest (an unenrolled assignee, another
    /// operator), which may simply be older than the sender's.
    #[error("not consistent with this node's manifest: {0}")]
    ManifestMismatch(&'static str),
    #[error("message expired")]
    Expired,
    #[error("message issued in the future beyond allowed clock skew")]
    NotYetValid,
    #[error("message lifetime exceeds the maximum allowed")]
    TtlTooLong,
    #[error("invalid message: {0}")]
    Invalid(String),
    #[error("replayed message")]
    Replay,
    #[error("replay cache full")]
    ReplayCacheFull,
    #[error("rate limited")]
    RateLimited,
    #[error("manifest rollback: sequence {got} is older than {min}")]
    Rollback { got: u64, min: u64 },
}

impl ProtocolError {
    pub(crate) fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }

    /// Whether the message proves misbehaviour by its signer, and so may count against it
    /// (network peer scoring). Only failures that no software version, manifest timing or
    /// clock can explain: a signature by an enrolled key that does not verify, a payload
    /// claiming an identity other than its signer, a message for another network.
    ///
    /// Everything else may come from an honest node: a payload this version cannot decode
    /// or a limit it does not allow (a newer release adds fields or raises limits), a signer,
    /// role, assignee or operator this node's manifest does not have yet, clocks, replays,
    /// quotas.
    #[must_use]
    pub fn proves_misbehaviour(&self) -> bool {
        matches!(
            self,
            Self::Crypto(CryptoError::BadSignature)
                | Self::SignerMismatch
                | Self::WrongNetwork { .. }
        )
    }

    /// Short, stable label for metrics and logs.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Crypto(
                CryptoError::BadSignature | CryptoError::InsufficientSignatures { .. },
            ) => "bad-signature",
            Self::Crypto(CryptoError::TooLarge { .. }) => "too-large",
            Self::Crypto(CryptoError::WrongPayloadType { .. }) => "wrong-type",
            Self::Crypto(CryptoError::NonCanonical) => "non-canonical",
            Self::Crypto(_) => "malformed",
            Self::UnsupportedVersion(_) => "version",
            Self::WrongNetwork { .. } => "wrong-network",
            Self::NotAuthorized(_) => "unauthorised",
            Self::SignerMismatch => "signer-mismatch",
            Self::ManifestMismatch(_) => "manifest-mismatch",
            Self::Expired => "expired",
            Self::NotYetValid => "future",
            Self::TtlTooLong => "ttl",
            Self::Invalid(_) => "invalid",
            Self::Replay => "replay",
            Self::ReplayCacheFull => "replay-cache-full",
            Self::RateLimited => "rate-limited",
            Self::Rollback { .. } => "rollback",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_what_an_honest_node_cannot_send_proves_misbehaviour() {
        // Clocks, manifest timing, another release (new fields, other limits), local state.
        for honest in [
            ProtocolError::Expired,
            ProtocolError::NotYetValid,
            ProtocolError::NotAuthorized("worker"),
            ProtocolError::ManifestMismatch("assignee is not an enrolled worker"),
            ProtocolError::UnsupportedVersion(2),
            ProtocolError::Crypto(CryptoError::NonCanonical),
            ProtocolError::Crypto(CryptoError::TooLarge { size: 2, limit: 1 }),
            ProtocolError::TtlTooLong,
            ProtocolError::Invalid("too many domains".into()),
            ProtocolError::Replay,
            ProtocolError::ReplayCacheFull,
            ProtocolError::RateLimited,
            ProtocolError::Rollback { got: 1, min: 2 },
        ] {
            assert!(!honest.proves_misbehaviour(), "{honest:?}");
        }
        for forged in [
            ProtocolError::Crypto(CryptoError::BadSignature),
            ProtocolError::SignerMismatch,
            ProtocolError::WrongNetwork {
                expected: "a".into(),
                actual: "b".into(),
            },
        ] {
            assert!(forged.proves_misbehaviour(), "{forged:?}");
        }
    }
}
