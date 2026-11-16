//! Signed threat-intelligence releases.
//!
//! * **Deterministic generation**: the same verification records, appeal decisions and
//!   parameters always produce byte-identical release payloads. Independent organisations
//!   can therefore rebuild a release themselves and co-sign it only if they get the same
//!   bytes.
//! * **k-of-n signatures from distinct operators**: consumers require a threshold of valid
//!   signatures from pinned release keys *held by different organisations*, so one
//!   compromised signing key cannot publish a release.
//! * **Offline verification**: consumers need only the pinned [`TrustRoot`] and a clock.
//! * **Anti-rollback**: consumers refuse sequences older than the last accepted one and
//!   detect two different releases with the same sequence. Operational rollback is done by
//!   publishing a *new* sequence that restores older content ([`rollback`]).
//! * **Corrections**: upheld false-positive appeals remove entries and are listed openly in
//!   every later release.

#![forbid(unsafe_code)]

mod build;
mod model;
mod verify;

pub use build::{BuildParams, build_release, rollback, sign_release};
pub use model::*;
pub use verify::{ConsumerState, ReleaseError, TrustRoot, VerifiedRelease, verify_release};

/// Generator string embedded in releases.
pub const GENERATOR: &str = concat!("cybermesh-intelligence/", env!("CARGO_PKG_VERSION"));
/// Maximum release envelope size accepted by consumers.
pub const MAX_RELEASE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of entries in one release.
pub const MAX_ENTRIES: usize = 200_000;
