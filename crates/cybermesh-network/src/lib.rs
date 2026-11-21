//! Permissioned gossip transport.
//!
//! * **Identity and transport**: libp2p over TCP with Noise (XX, mutually authenticated by
//!   Ed25519 peer keys) and Yamux. Peer ids are derived from keys enrolled in the trust
//!   manifest.
//! * **Admission**: an allowlist (`allow_block_list`) refuses connections from any peer not
//!   enrolled; connection limits bound per-peer and total connections.
//! * **Dissemination**: gossipsub with signed messages (`ValidationMode::Strict`),
//!   content-addressed message ids and **manual validation**: nothing is forwarded until the
//!   application has verified the CyberMesh signature, freshness and replay status.
//! * **Peer scoring**: only provable misbehaviour (messages the application `Reject`s) costs a
//!   peer, and only the message's author; about three invalid messages in ten minutes
//!   graylist it ([`peer_scoring`]).
//! * **Abuse resistance**: per-peer token buckets (cost grows with message size), bounded
//!   inbound and command queues (drop with a counter rather than buffer without limit), an
//!   outbound bandwidth budget, and author checks against the allowlist.
//! * **Partition tolerance**: bootstrap peers are redialled with backoff; publish failures
//!   are reported to the caller so it can keep the message in a bounded outbox.

#![forbid(unsafe_code)]

mod node;
mod stats;

pub use libp2p::{Multiaddr, PeerId};
pub use node::{
    Acceptance, GOSSIP_THRESHOLD, GRAYLIST_THRESHOLD, INVALID_MESSAGE_HALF_LIFE,
    INVALID_MESSAGE_WEIGHT, InboundMessage, NetConfig, NetError, NetEvent, NetworkHandle,
    PUBLISH_THRESHOLD, SCORE_GRAYLISTED, SCORE_WARNED, author_score, keypair_from_seed, peer_id_of,
    peer_scoring, spawn,
};
pub use stats::NetStats;

/// Topic names for a network.
#[derive(Debug, Clone)]
pub struct Topics {
    pub tasks: String,
    pub results: String,
    pub presence: String,
    /// Signed verification records, exchanged between verifiers (workers do not subscribe).
    pub records: String,
    /// Cosigned CT log checkpoints, exchanged between verifiers that witness logs.
    pub checkpoints: String,
    /// Fault proofs from independent verifiers, re-checked by the coordinator.
    pub faults: String,
}

impl Topics {
    #[must_use]
    pub fn for_network(network_id: &str) -> Self {
        Self {
            tasks: format!("/cybermesh/{network_id}/v1/tasks"),
            results: format!("/cybermesh/{network_id}/v1/results"),
            presence: format!("/cybermesh/{network_id}/v1/presence"),
            records: format!("/cybermesh/{network_id}/v1/records"),
            checkpoints: format!("/cybermesh/{network_id}/v1/checkpoints"),
            faults: format!("/cybermesh/{network_id}/v1/faults"),
        }
    }
}
