//! CyberMesh node runtimes.
//!
//! * [`worker`]: an opt-in, resource-governed analysis worker. It accepts only signed tasks
//!   from enrolled issuers, runs only the built-in deterministic engine on locally pinned
//!   evidence, never contacts analysed domains, and stops or pauses on administrator
//!   command.
//! * [`coordinator`]: the approved task issuer plus result verifier. It assigns each task to
//!   workers of distinct operators, verifies and settles results, reassigns on timeouts and
//!   writes signed verification records for release builders.
//! * [`governor`]: CPU, memory, load and working-hour policy for workers.

#![forbid(unsafe_code)]

pub mod config;
pub mod coordinator;
pub mod files;
pub mod governor;
pub mod worker;

#[cfg(feature = "adversary-sim")]
pub mod adversary;

/// Errors from node runtimes.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("configuration: {0}")]
    Config(String),
    #[error("io: {0}")]
    Io(String),
    #[error("crypto: {0}")]
    Crypto(#[from] cybermesh_crypto::CryptoError),
    #[error("protocol: {0}")]
    Protocol(#[from] cybermesh_protocol::ProtocolError),
    #[error("network: {0}")]
    Network(#[from] cybermesh_network::NetError),
    #[error("evidence: {0}")]
    Evidence(#[from] cybermesh_analysis::EvidenceError),
}
