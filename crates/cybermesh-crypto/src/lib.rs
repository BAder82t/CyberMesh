//! Cryptographic building blocks for CyberMesh.
//!
//! * [`Digest`]: SHA-256 digests with domain-separated helpers.
//! * [`SecretKey`] / [`PublicKey`] / [`KeyId`]: Ed25519 identities. Verification uses
//!   `verify_strict`, which rejects small-order keys and non-canonical signatures.
//! * [`Envelope`]: a DSSE (Dead Simple Signing Envelope) container. Signatures cover the
//!   pre-authentication encoding (PAE) of the payload type and the exact payload bytes,
//!   so verifiers never have to re-serialise data before checking a signature.
//! * [`canonical`]: strict JSON encoding. Decoding re-encodes the value and rejects any
//!   input whose bytes differ, which removes encoding malleability (whitespace, key order,
//!   escapes, duplicate keys).

#![forbid(unsafe_code)]

pub mod canonical;
mod digest;
mod envelope;
mod error;
mod keys;

pub use digest::Digest;
pub use envelope::{EnvSignature, Envelope, VerifiedEnvelope, pae};
pub use error::CryptoError;
pub use keys::{KeyId, PublicKey, SecretKey, generate_nonce, random_bytes};
