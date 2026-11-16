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
