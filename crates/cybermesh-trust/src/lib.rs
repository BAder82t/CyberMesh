//! Trust Fabric authentication (EXPERIMENTAL, unaudited).
//!
//! Modules: [`mac`], an information-theoretically secure message authentication code, and
//! [`shares`], which uses it to authenticate secret shares.
//!
//! The MAC is **pairwise and symmetric**: the receiver holds the same key as the sender, so a
//! tag convinces the receiver only. It is not a signature, is not publicly verifiable and gives no
//! non-repudiation. Nothing here uses Ed25519, SHA-2 or any computational assumption.

#![forbid(unsafe_code)]

pub mod mac;
pub mod shares;
