//! Integrity anchoring for CyberMesh releases.
//!
//! Releases are appended to a Merkle transparency log ([`TransparencyLog`], RFC 9162 hashing,
//! inclusion and consistency proofs). The log's checkpoint (size + root) can then be
//! committed to an external timestamping system through the [`Anchor`] trait.
//!
//! What goes to an anchor is a single 32-byte commitment derived from the checkpoint. No
//! URLs, domains, organisation names or infrastructure identifiers ever leave the log.
//!
//! Anchoring is **off the protection path**: consumers verify releases with signatures
//! alone. Anchor failures are recorded and retried; they never block publication or
//! enforcement.

#![forbid(unsafe_code)]

mod anchor;
mod log;
pub mod merkle;
pub mod ots;

pub use anchor::{
    Anchor, AnchorError, AnchorReceipt, AnchorStatus, Checkpoint, FailingAnchor, FailureMode,
    LocalChain, LocalChainReceipt,
};
pub use log::{InclusionProof, LogEntry, TransparencyLog, verify_consistency};
