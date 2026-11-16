//! CyberMesh wire protocol, version 1.
//!
//! Every network message is a DSSE [`Envelope`](cybermesh_crypto::Envelope) whose payload is
//! the canonical JSON encoding of one of the message structs in [`messages`]. Each message
//! kind has its own payload type string ([`payload_type`]), so a signature over one kind
//! can never be replayed as another.
//!
//! Validation functions in [`validate`] are pure: they take the bytes, the governance-signed
//! [`TrustManifest`], the current time and [`Limits`], and either return a verified message or
//! a typed [`ProtocolError`]. Stateful checks (replay, rate limits) live in [`replay`] and
//! [`ratelimit`] and are applied by the caller.

#![forbid(unsafe_code)]

pub mod clock;
pub mod domain;
mod error;
pub mod manifest;
pub mod messages;
pub mod ratelimit;
pub mod replay;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod validate;

pub use clock::{Clock, ManualClock, SystemClock};
pub use error::ProtocolError;
pub use manifest::{
    GovernanceRoot, KeySet, Member, Operator, Revocation, Role, SignerEntry, TrustManifest,
};
pub use messages::*;
pub use validate::Limits;

/// Protocol version carried in every payload as `"v"`.
pub const PROTOCOL_VERSION: u16 = 1;

/// DSSE payload type strings, one per message kind.
pub mod payload_type {
    pub const TASK: &str = "application/vnd.cybermesh.task+json;v=1";
    pub const RESULT: &str = "application/vnd.cybermesh.result+json;v=1";
    pub const HEARTBEAT: &str = "application/vnd.cybermesh.heartbeat+json;v=1";
    pub const MANIFEST: &str = "application/vnd.cybermesh.manifest+json;v=1";
    pub const RELEASE: &str = "application/vnd.cybermesh.release+json;v=1";
    pub const APPEAL_DECISION: &str = "application/vnd.cybermesh.appeal-decision+json;v=1";
    pub const VERIFICATION: &str = "application/vnd.cybermesh.verification+json;v=1";
}
