use thiserror::Error;

/// Errors produced by the cryptographic layer. Messages never include secret material.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid hex encoding: {0}")]
    InvalidHex(String),
    #[error("invalid base64 encoding")]
    InvalidBase64,
    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("envelope too large: {size} bytes exceeds limit of {limit}")]
    TooLarge { size: usize, limit: usize },
    #[error("unexpected payload type: expected {expected}, got {actual}")]
    WrongPayloadType { expected: String, actual: String },
    #[error("insufficient valid signatures: {valid} valid, {required} required")]
    InsufficientSignatures { valid: usize, required: usize },
    #[error("malformed envelope: {0}")]
    MalformedEnvelope(String),
    #[error("non-canonical encoding")]
    NonCanonical,
    #[error("json error: {0}")]
    Json(String),
    #[error("randomness unavailable")]
    Randomness,
    #[error("key file error: {0}")]
    KeyFile(String),
}
