//! Certificate Transparency monitoring for CyberMesh (`ct-shard-scan` tasks).
//!
//! * [`tile`]: static CT API data tiles (C2SP `static-ct-api`): `TileLeaf` parsing, RFC 6962
//!   leaf hashes and per-tile Merkle roots (equal to the log's level-1 hash tile entries).
//! * [`names`]: DNS names (SAN `dNSName` and subject CN) from certificates and
//!   precertificate TBSCertificates, using the `x509-parser` crate.
//! * [`scan`]: deterministic brand-lookalike scanning of tiles with the CyberMesh engine.
//! * [`checkpoint`]: checkpoint (signed note) parsing. Signatures are **not** verified in
//!   this version.
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
pub mod scan;
pub mod tile;

pub use checkpoint::Checkpoint;
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
}

/// Read access to a static CT log (tiles are immutable; the checkpoint is not).
pub trait TileSource: Send + Sync {
    /// The full data tile `n` (256 entries).
    fn data_tile(&self, n: u64) -> Result<Vec<u8>, CtError>;
    /// The level-1 hash tile `n`, full (`width = None`) or partial.
    fn level1_tile(&self, n: u64, width: Option<u8>) -> Result<Vec<u8>, CtError>;
    /// The current checkpoint text.
    fn checkpoint(&self) -> Result<String, CtError>;

    /// The log's own Merkle root of full data tile `n` (from the level-1 hash tile), given
    /// the current tree size.
    fn tile_root(&self, n: u64, tree_size: u64) -> Result<[u8; 32], CtError> {
        let full_data_tiles = tree_size / 256;
        if n >= full_data_tiles {
            return Err(CtError::NotFound(format!("data tile {n} is not full yet")));
        }
        let level1 = n / 256;
        let offset = usize::try_from(n % 256).unwrap_or(0);
        let full_level1 = full_data_tiles / 256;
        let (bytes, expected) = if level1 < full_level1 {
            (self.level1_tile(level1, None)?, 256 * 32)
        } else {
            let width = u8::try_from(full_data_tiles % 256)
                .map_err(|_| CtError::Malformed("width".into()))?;
            (
                self.level1_tile(level1, Some(width))?,
                usize::from(width) * 32,
            )
        };
        // A hash tile has exactly one 32-byte hash per covered data tile.
        if bytes.len() != expected {
            return Err(CtError::Malformed(format!(
                "level-1 tile has {} bytes, expected {expected}",
                bytes.len()
            )));
        }
        let start = offset * 32;
        let slice = bytes
            .get(start..start + 32)
            .ok_or_else(|| CtError::Malformed("level-1 tile too short".into()))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(slice);
        Ok(out)
    }
}
