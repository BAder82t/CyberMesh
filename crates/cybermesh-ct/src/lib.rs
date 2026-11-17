//! Certificate Transparency monitoring for CyberMesh (`ct-shard-scan` tasks).
//!
//! * [`tile`]: static CT API data tiles (C2SP `static-ct-api`): `TileLeaf` parsing, RFC 6962
//!   leaf hashes and per-tile Merkle roots (equal to the log's level-1 hash tile entries).
//! * [`names`]: DNS names (SAN `dNSName` and subject CN) from certificates and
//!   precertificate TBSCertificates, using the `x509-parser` crate.
//! * [`scan`]: deterministic brand-lookalike scanning of tiles with the CyberMesh engine.
//! * [`checkpoint`]: checkpoints (signed notes), verified against the log's pinned key
//!   (RFC 6962 ECDSA P-256 note signatures) and origin.
//! * [`proof`]: authenticates hash tiles against a verified checkpoint, so tile roots are
//!   trusted because the log signed them, not because they arrived over HTTPS.
//! * `http` feature: [`http::HttpTileSource`], an HTTPS client restricted to a pinned
//!   monitoring prefix (no redirects, size caps, timeouts).
//! * `mock` feature: a synthetic static CT log with real X.509 certificates, and a loopback
//!   server, for tests and demonstrations.
//!
//! Workers never contact the domains found in certificates; they only download public log
//! tiles from logs listed in the pinned `ct-logs` evidence.

#![forbid(unsafe_code)]

pub mod checkpoint;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "mock")]
pub mod mock;
pub mod names;
pub mod proof;
pub mod scan;
pub mod tile;

pub use checkpoint::{Checkpoint, LogKey, verify_checkpoint};
pub use proof::authenticated_tile_root;
pub use scan::{is_brand_signal, scan_tile, scan_tiles};
pub use tile::{Entry, EntryKind, parse_data_tile};

/// Maximum size of one downloaded data tile (a full tile is typically 0.5-2 MiB).
pub const MAX_TILE_BYTES: usize = 16 * 1024 * 1024;

/// Errors from CT processing.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CtError {
    #[error("malformed data: {0}")]
    Malformed(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("response too large")]
    TooLarge,
    #[error("http: {0}")]
    Http(String),
    #[error("analysis: {0}")]
    Analysis(String),
    /// The checkpoint is not validly signed by the pinned log key, or tiles do not match it.
    #[error("not authenticated by the log: {0}")]
    Unauthenticated(String),
}

/// Read access to a static CT log (tiles are immutable; the checkpoint is not).
pub trait TileSource: Send + Sync {
    /// The full data tile `n` (256 entries).
    fn data_tile(&self, n: u64) -> Result<Vec<u8>, CtError>;
    /// The hash tile `n` at `level` (C2SP `tlog-tiles`): full (`width = None`, 256 hashes)
    /// or partial. Level 0 holds leaf hashes; level `L` holds hashes of complete subtrees of
    /// `256^L` leaves.
    fn hash_tile(&self, level: u8, n: u64, width: Option<u8>) -> Result<Vec<u8>, CtError>;
    /// The current checkpoint text (unverified; see [`checkpoint::verify_checkpoint`]).
    fn checkpoint(&self) -> Result<String, CtError>;
}
