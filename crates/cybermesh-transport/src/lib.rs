//! Information-theoretic session transport (EXPERIMENTAL, unaudited).
//!
//! Inspired by the shape of TLS 1.3 (handshake, transcript binding, protected records) but **not
//! TLS and not wire-compatible with it**. Confidentiality is a one-time pad and authentication is
//! a Wegman-Carter MAC, both fed from pre-provisioned secret pools (`cybermesh-entropy`). Nothing
//! in this crate uses a cipher, a hash, a key-derivation function or a public-key primitive, so
//! the guarantees below do not rest on any computational assumption. They do rest on the model in
//! `docs/trust-fabric/transport-protocol.md`: shared secret pools, used once, in lockstep.
//!
//! # Profiles
//!
//! [`SecurityProfile`] names the three profiles of the Trust Fabric. Only
//! [`SecurityProfile::InformationTheoretic`] exists here; asking for another fails with
//! [`TransportError::ProfileUnsupported`], and a peer that announces a different profile is a
//! [`TransportError::Downgrade`]. There is no negotiation and no fallback: a session that cannot be
//! information-theoretic does not exist.
//!
//! # Guarantees, in the model
//!
//! * **Confidentiality**: ciphertext is the plaintext XOR fresh uniform pad bytes used once, so it
//!   is independent of the plaintext except for its length (the permitted leakage).
//! * **Integrity and authenticity**: forging a record or handshake message succeeds with
//!   probability at most `(blocks + 1) / 2^128` per attempt (`cybermesh_trust::mac::forgery_bound`),
//!   against unbounded computation. The first failed check ends the session, so the adversary gets
//!   one attempt per session.
//! * **Order, replay, reflection, cross-session replay**: records carry a session id, a direction
//!   and a strictly increasing sequence number inside the authenticated bytes. Anything out of
//!   order, repeated, reflected or from another session ends the session.
//! * **Truncation**: an authenticated close record ends a stream; a stream that stops without one
//!   is not a clean close.
//! * **No reuse across crashes**: pools advance durably before bytes are used, so a restart burns
//!   material instead of repeating it.
//! * **Past traffic after a later state compromise**: consumed pad bytes are erased, so an
//!   attacker who later takes the endpoint's state cannot decrypt recorded traffic (relies on the
//!   erasure holding; see the entropy model). There is **no post-compromise recovery**: whoever
//!   copies the unspent pools can read and forge all future traffic until the pools are replaced.
//!
//! # What it does not do
//!
//! Fail-closed means availability is not protected: an active network attacker can end any
//! session. Sessions are strictly in-order over a reliable byte transport; a lost record
//! desynchronises the pools; [`Endpoint::resync`] brings them back by burning forward. The
//! number of bytes sent is limited by the pool size: confidentiality costs as many secret bytes
//! as plaintext bytes, plus 16 bytes of authentication pad per record.

#![forbid(unsafe_code)]

mod profile;
mod resync;
mod session;

pub use profile::SecurityProfile;
pub use resync::{Cursors, ResyncReport, SYNC_LEN};
pub use session::{
    Endpoint, Initiator, MAX_RECORD_DATA, Opened, Responder, Role, Session, TransportError,
};
