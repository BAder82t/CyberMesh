//! Handshake and record protocol. See the crate docs for the guarantees and their limits.
//!
//! # Streams
//!
//! Each direction has two pools: encryption (pad) and authentication. Each party holds a copy
//! of all four; the sender consumes its direction's pools and the receiver consumes its copy of
//! the same pools, in the same order, so both stay in lockstep. The authentication stream of a
//! direction is, in order: one 16-byte hash key, one pad for the hello, (initiator only) one pad
//! for the finished message, then one pad per record. The encryption stream is one pad per record,
//! as long as the record's frame.
//!
//! # Messages
//!
//! ```text
//! Hello    'H' ver profile role  session_id[16]  auth_start[8]  enc_start[8]  tag[16]
//! Finished 'F' ver session_id[16]  tag[16]
//! Record   ver session_id[16] dir seq[8] ctlen[4]  ciphertext  tag[16]
//! Frame    type[1] len[4] data  zero-padding    (at least 8 bytes), encrypted as a whole
//! ```
//!
//! Handshake (initiator I, responder R): `I -> R: Hello`, `R -> I: Hello`, `I -> R: Finished`.
//! R's hello is tagged over R's header and I's complete hello, and I's finished is tagged over
//! both complete hellos, so each side proves it saw the other's hello unchanged (transcript
//! binding without a hash). `auth_start` and `enc_start` are the sender's pool cursors; the
//! receiver refuses unless its own cursors for the same pools equal them (`OutOfStep`).

use cybermesh_entropy::{EntropyError, Pool, Purpose};
use cybermesh_trust::mac::{MacError, MacKey, TAG_LEN, Tag, Verifier};
use zeroize::Zeroize;

use crate::SecurityProfile;

/// Largest data payload of one record.
pub const MAX_RECORD_DATA: usize = 1 << 16;
const MIN_FRAME: usize = 8;
const VERSION: u8 = 1;
const HELLO_BODY: usize = 1 + 1 + 1 + 1 + 16 + 8 + 8;
const HELLO_LEN: usize = HELLO_BODY + TAG_LEN;
const FINISHED_BODY: usize = 1 + 1 + 16;
const FINISHED_LEN: usize = FINISHED_BODY + TAG_LEN;
const REC_HEADER: usize = 1 + 16 + 1 + 8 + 4;
const DOM_HELLO: &[u8] = b"cybermesh-transport v1 hello";
const DOM_FINISHED: &[u8] = b"cybermesh-transport v1 finished";
const DOM_RECORD: &[u8] = b"cybermesh-transport v1 record";
const TYPE_DATA: u8 = 0;
const TYPE_CLOSE: u8 = 1;

/// Failures. None carries secret material.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("profile {0:?} is not supported: only the information-theoretic profile exists")]
    ProfileUnsupported(SecurityProfile),
    #[error("peer announced profile {0:?}: refusing to downgrade")]
    Downgrade(u8),
    #[error("pools are unsuitable: {0}")]
    BadEndpoint(&'static str),
    #[error("malformed message")]
    Malformed,
    #[error("authentication failed; session ended")]
    Authentication,
    #[error("pools are out of step ({what}: ours {ours}, theirs {theirs})")]
    OutOfStep {
        what: &'static str,
        ours: u64,
        theirs: u64,
    },
    #[error("record out of order or repeated (expected {expected}, got {got}); session ended")]
    Order { expected: u64, got: u64 },
    #[error("record belongs to another session or direction; session ended")]
    WrongSession,
    #[error("secret pool exhausted: replenish both parties' pools to continue")]
    KeyExhausted,
    #[error("payload larger than {MAX_RECORD_DATA} bytes")]
    TooLarge,
    #[error("session is closed")]
    Closed,
    #[error("session was terminated by an earlier failure")]
    Terminated,
    #[error("entropy: {0}")]
    Entropy(#[from] EntropyError),
    #[error("mac: {0}")]
    Mac(#[from] MacError),
    #[error("randomness source failed")]
    Randomness,
    #[error("malformed resync message")]
    BadSync,
    #[error("the sync response does not answer the request it was given; nothing was changed")]
    SyncNotRequested,
    #[error("the sync message does not authenticate; nothing was changed")]
    SyncAuthentication,
    #[error(
        "the sync message names material this side has already spent: a replay, or the peer is behind"
    )]
    SyncStale,
    #[error("peer's cursor for the {pool} pool is beyond what was provisioned")]
    ResyncExceedsPool { pool: &'static str },
    #[error("resync would burn {gap} bytes of the {pool} pool, over the allowed {max}")]
    ResyncExceedsPolicy {
        pool: &'static str,
        gap: u64,
        max: u64,
    },
    #[error(
        "cursors of the {pool} pool differ by {gap} bytes, which no sequence of records can cause"
    )]
    Misaligned { pool: &'static str, gap: u64 },
}

/// Which side of the handshake a party is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Initiator = 0,
    Responder = 1,
}

/// One party's four pools. Both parties hold identical copies of the same four pools; the
/// initiator sends on `ir` and the responder on `ri`.
pub struct Endpoint {
    role: Role,
    send_enc: Pool,
    send_auth: Pool,
    recv_enc: Pool,
    recv_auth: Pool,
}

impl core::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Endpoint")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl Endpoint {
    /// Check and take the four pools: encryption pools must have purpose `Encryption`,
    /// authentication pools `Authentication`, all must be shared-secret provenance (local
    /// randomness is refused) and all four must be distinct.
    ///
    /// # Errors
    /// [`TransportError::BadEndpoint`].
    pub fn new(
        profile: SecurityProfile,
        role: Role,
        send_enc: Pool,
        send_auth: Pool,
        recv_enc: Pool,
        recv_auth: Pool,
    ) -> Result<Self, TransportError> {
        if profile != SecurityProfile::InformationTheoretic {
            return Err(TransportError::ProfileUnsupported(profile));
        }
        for p in [&send_enc, &recv_enc] {
            if p.purpose() != Purpose::Encryption {
                return Err(TransportError::BadEndpoint(
                    "encryption pool has the wrong purpose",
                ));
            }
        }
        for p in [&send_auth, &recv_auth] {
            if p.purpose() != Purpose::Authentication {
                return Err(TransportError::BadEndpoint(
                    "authentication pool has the wrong purpose",
                ));
            }
        }
        let all = [&send_enc, &send_auth, &recv_enc, &recv_auth];
        if all.iter().any(|p| !p.provenance().is_shared_secret()) {
            return Err(TransportError::BadEndpoint(
                "pools must be shared-secret material, not local randomness",
            ));
        }
        for (i, a) in all.iter().enumerate() {
            if all[i + 1..].iter().any(|b| b.id() == a.id()) {
                return Err(TransportError::BadEndpoint(
                    "the four pools must be distinct",
                ));
            }
        }
        Ok(Self {
            role,
            send_enc,
            send_auth,
            recv_enc,
            recv_auth,
        })
    }

    fn dir(&self) -> u8 {
        self.role as u8
    }

    pub(crate) fn role(&self) -> Role {
        self.role
    }

    pub(crate) fn pools(&self) -> [(&'static str, &Pool); 4] {
        [
            ("send encryption", &self.send_enc),
            ("send authentication", &self.send_auth),
            ("receive encryption", &self.recv_enc),
            ("receive authentication", &self.recv_auth),
        ]
    }
}

fn consumed(p: &Pool) -> Result<u64, TransportError> {
    Ok(p.stats()?.consumed)
}

fn tagged(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut m = domain.to_vec();
    for p in parts {
        m.extend_from_slice(p);
    }
    m
}

fn hello_body(role: Role, sid: &[u8; 16], auth_start: u64, enc_start: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(HELLO_BODY);
    b.extend_from_slice(&[
        b'H',
        VERSION,
        SecurityProfile::InformationTheoretic as u8,
        role as u8,
    ]);
    b.extend_from_slice(sid);
    b.extend_from_slice(&auth_start.to_be_bytes());
    b.extend_from_slice(&enc_start.to_be_bytes());
    b
}

struct Hello {
    sid: [u8; 16],
    auth_start: u64,
    enc_start: u64,
    tag: Tag,
}

/// Strict parse. The profile is checked before anything else: a different one is a downgrade.
fn parse_hello(b: &[u8], want_role: Role) -> Result<Hello, TransportError> {
    if b.len() != HELLO_LEN || b[0] != b'H' || b[1] != VERSION {
        return Err(TransportError::Malformed);
    }
    if b[2] != SecurityProfile::InformationTheoretic as u8 {
        return Err(TransportError::Downgrade(b[2]));
    }
    if b[3] != want_role as u8 {
        return Err(TransportError::Malformed);
    }
    let mut sid = [0u8; 16];
    sid.copy_from_slice(&b[4..20]);
    let mut t = [0u8; TAG_LEN];
    t.copy_from_slice(&b[HELLO_BODY..]);
    Ok(Hello {
        sid,
        auth_start: u64::from_be_bytes(
            b[20..28]
                .try_into()
                .map_err(|_| TransportError::Malformed)?,
        ),
        enc_start: u64::from_be_bytes(
            b[28..36]
                .try_into()
                .map_err(|_| TransportError::Malformed)?,
        ),
        tag: Tag::from_bytes(t),
    })
}

fn key(p: &Pool) -> Result<MacKey, TransportError> {
    Ok(MacKey::from_reservation(p.reserve(TAG_LEN)?)?)
}

fn check_in_step(ep: &Endpoint, h: &Hello) -> Result<(), TransportError> {
    let (a, e) = (consumed(&ep.recv_auth)?, consumed(&ep.recv_enc)?);
    if a != h.auth_start {
        return Err(TransportError::OutOfStep {
            what: "authentication pool",
            ours: a,
            theirs: h.auth_start,
        });
    }
    if e != h.enc_start {
        return Err(TransportError::OutOfStep {
            what: "encryption pool",
            ours: e,
            theirs: h.enc_start,
        });
    }
    Ok(())
}

/// Initiator before the responder's hello.
pub struct Initiator {
    ep: Endpoint,
    sid: [u8; 16],
    send_key: MacKey,
    hello: Vec<u8>,
}

impl core::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Initiator(..)")
    }
}

impl Initiator {
    /// Start a session: take this direction's hash key and hello pad and produce the hello.
    ///
    /// # Errors
    /// [`TransportError::BadEndpoint`] if the endpoint is not an initiator, entropy errors if a
    /// pool is exhausted, [`TransportError::Randomness`].
    pub fn start(ep: Endpoint) -> Result<(Self, Vec<u8>), TransportError> {
        if ep.role != Role::Initiator {
            return Err(TransportError::BadEndpoint("not an initiator endpoint"));
        }
        let mut sid = [0u8; 16];
        getrandom::fill(&mut sid).map_err(|_| TransportError::Randomness)?; // public nonce
        let (auth_start, enc_start) = (consumed(&ep.send_auth)?, consumed(&ep.send_enc)?);
        let send_key = key(&ep.send_auth)?;
        let body = hello_body(Role::Initiator, &sid, auth_start, enc_start);
        let tag = send_key.tag(&tagged(DOM_HELLO, &[&body]), ep.send_auth.reserve(TAG_LEN)?)?;
        let mut hello = body;
        hello.extend_from_slice(&tag.to_bytes());
        Ok((
            Self {
                ep,
                sid,
                send_key,
                hello: hello.clone(),
            },
            hello,
        ))
    }

    /// Verify the responder's hello and produce the finished message and the session.
    ///
    /// # Errors
    /// Any authentication, downgrade, malformed or out-of-step condition ends the attempt.
    pub fn finish(self, responder_hello: &[u8]) -> Result<(Session, Vec<u8>), TransportError> {
        let Self {
            ep,
            sid,
            send_key,
            hello,
        } = self;
        let r = parse_hello(responder_hello, Role::Responder)?;
        if r.sid != sid {
            return Err(TransportError::WrongSession);
        }
        check_in_step(&ep, &r)?;
        let mut recv = Verifier::new(key(&ep.recv_auth)?, 1);
        let msg = tagged(DOM_HELLO, &[&responder_hello[..HELLO_BODY], &hello]);
        recv.verify(&msg, &r.tag, ep.recv_auth.reserve(TAG_LEN)?)
            .map_err(|_| TransportError::Authentication)?;
        let mut fin = vec![b'F', VERSION];
        fin.extend_from_slice(&sid);
        let t = send_key.tag(
            &tagged(DOM_FINISHED, &[&hello, responder_hello]),
            ep.send_auth.reserve(TAG_LEN)?,
        )?;
        fin.extend_from_slice(&t.to_bytes());
        Ok((Session::new(ep, sid, send_key, recv), fin))
    }
}

/// Responder after sending its hello, waiting for the finished message.
pub struct Responder {
    ep: Endpoint,
    sid: [u8; 16],
    send_key: MacKey,
    recv: Verifier,
    hello_i: Vec<u8>,
    hello_r: Vec<u8>,
}

impl core::fmt::Debug for Responder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Responder(..)")
    }
}

impl Responder {
    /// Verify the initiator's hello and produce the responder's hello.
    ///
    /// # Errors
    /// Any authentication, downgrade, malformed or out-of-step condition ends the attempt. Pool
    /// cursors are compared **before** any material is consumed.
    pub fn accept(ep: Endpoint, initiator_hello: &[u8]) -> Result<(Self, Vec<u8>), TransportError> {
        if ep.role != Role::Responder {
            return Err(TransportError::BadEndpoint("not a responder endpoint"));
        }
        let i = parse_hello(initiator_hello, Role::Initiator)?;
        check_in_step(&ep, &i)?;
        let mut recv = Verifier::new(key(&ep.recv_auth)?, 1);
        recv.verify(
            &tagged(DOM_HELLO, &[&initiator_hello[..HELLO_BODY]]),
            &i.tag,
            ep.recv_auth.reserve(TAG_LEN)?,
        )
        .map_err(|_| TransportError::Authentication)?;
        let (auth_start, enc_start) = (consumed(&ep.send_auth)?, consumed(&ep.send_enc)?);
        let send_key = key(&ep.send_auth)?;
        let body = hello_body(Role::Responder, &i.sid, auth_start, enc_start);
        let tag = send_key.tag(
            &tagged(DOM_HELLO, &[&body, initiator_hello]),
            ep.send_auth.reserve(TAG_LEN)?,
        )?;
        let mut hello_r = body;
        hello_r.extend_from_slice(&tag.to_bytes());
        Ok((
            Self {
                ep,
                sid: i.sid,
                send_key,
                recv,
                hello_i: initiator_hello.to_vec(),
                hello_r: hello_r.clone(),
            },
            hello_r,
        ))
    }

    /// Verify the initiator's finished message and open the session.
    ///
    /// # Errors
    /// [`TransportError::Authentication`] and friends.
    pub fn finish(self, finished: &[u8]) -> Result<Session, TransportError> {
        let Self {
            ep,
            sid,
            send_key,
            mut recv,
            hello_i,
            hello_r,
        } = self;
        if finished.len() != FINISHED_LEN || finished[0] != b'F' || finished[1] != VERSION {
            return Err(TransportError::Malformed);
        }
        if finished[2..FINISHED_BODY] != sid {
            return Err(TransportError::WrongSession);
        }
        let mut t = [0u8; TAG_LEN];
        t.copy_from_slice(&finished[FINISHED_BODY..]);
        recv.verify(
            &tagged(DOM_FINISHED, &[&hello_i, &hello_r]),
            &Tag::from_bytes(t),
            ep.recv_auth.reserve(TAG_LEN)?,
        )
        .map_err(|_| TransportError::Authentication)?;
        Ok(Session::new(ep, sid, send_key, recv))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Open,
    Dead,
}

/// What [`Session::open`] returned.
#[derive(Debug, PartialEq, Eq)]
pub enum Opened {
    /// Authenticated, decrypted application data.
    Data(Vec<u8>),
    /// The peer's authenticated close: the stream ended cleanly.
    Closed,
}

/// An established session. Any failure while sending or receiving ends it for good.
pub struct Session {
    ep: Endpoint,
    sid: [u8; 16],
    send_key: MacKey,
    recv: Verifier,
    send_seq: u64,
    recv_seq: u64,
    sent_close: bool,
    recv_closed: bool,
    state: State,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("role", &self.ep.role)
            .field("sent", &self.send_seq)
            .field("received", &self.recv_seq)
            .field("state", &self.state)
            .field("sent_close", &self.sent_close)
            .field("recv_closed", &self.recv_closed)
            .finish_non_exhaustive()
    }
}

impl Session {
    fn new(ep: Endpoint, sid: [u8; 16], send_key: MacKey, recv: Verifier) -> Self {
        Self {
            ep,
            sid,
            send_key,
            recv,
            send_seq: 0,
            recv_seq: 0,
            sent_close: false,
            recv_closed: false,
            state: State::Open,
        }
    }

    /// Give the pools back (for [`Endpoint::resync`] or a new session). The session's keys are
    /// dropped and zeroized. Works on terminated sessions too.
    #[must_use]
    pub fn into_endpoint(self) -> Endpoint {
        let Self { ep, .. } = self;
        ep
    }

    /// Public session identifier.
    #[must_use]
    pub fn id(&self) -> [u8; 16] {
        self.sid
    }

    /// Secret bytes left for sending: `(encryption, authentication)`.
    ///
    /// # Errors
    /// Entropy errors.
    pub fn remaining_to_send(&self) -> Result<(u64, u64), TransportError> {
        Ok((
            self.ep.send_enc.stats()?.remaining,
            self.ep.send_auth.stats()?.remaining,
        ))
    }

    fn kill<T>(&mut self, e: TransportError) -> Result<T, TransportError> {
        self.state = State::Dead;
        Err(e)
    }

    fn seal_frame(&mut self, kind: u8, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        if self.state == State::Dead {
            return Err(TransportError::Terminated);
        }
        if self.sent_close {
            return Err(TransportError::Closed);
        }
        if data.len() > MAX_RECORD_DATA {
            return Err(TransportError::TooLarge);
        }
        let frame_len = (1 + 4 + data.len()).max(MIN_FRAME);
        // Check both pools first: failing between the two reservations would burn one pool and
        // desynchronise the pair, so that case ends the session instead.
        if self.ep.send_enc.stats()?.remaining < frame_len as u64
            || self.ep.send_auth.stats()?.remaining < TAG_LEN as u64
        {
            return Err(TransportError::KeyExhausted);
        }
        let mut frame = vec![0u8; frame_len];
        frame[0] = kind;
        frame[1..5].copy_from_slice(&(data.len() as u32).to_be_bytes());
        frame[5..5 + data.len()].copy_from_slice(data);
        let pad = match self.ep.send_enc.reserve(frame_len) {
            Ok(p) => p.into_secret(),
            Err(e) => return self.kill(e.into()),
        };
        for (c, p) in frame.iter_mut().zip(pad.iter()) {
            *c ^= p;
        }
        let mut rec = Vec::with_capacity(REC_HEADER + frame_len + TAG_LEN);
        rec.push(VERSION);
        rec.extend_from_slice(&self.sid);
        rec.push(self.ep.dir());
        rec.extend_from_slice(&self.send_seq.to_be_bytes());
        rec.extend_from_slice(&(frame_len as u32).to_be_bytes());
        rec.extend_from_slice(&frame);
        let auth_pad = match self.ep.send_auth.reserve(TAG_LEN) {
            Ok(p) => p,
            Err(e) => return self.kill(e.into()),
        };
        let tag = match self.send_key.tag(&tagged(DOM_RECORD, &[&rec]), auth_pad) {
            Ok(t) => t,
            Err(e) => return self.kill(e.into()),
        };
        rec.extend_from_slice(&tag.to_bytes());
        self.send_seq += 1;
        Ok(rec)
    }

    /// Encrypt and authenticate `data` as the next record.
    ///
    /// # Errors
    /// [`TransportError::KeyExhausted`] and [`TransportError::TooLarge`] leave the session and
    /// the pools untouched; other errors end the session.
    pub fn seal(&mut self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.seal_frame(TYPE_DATA, data)
    }

    /// Produce the authenticated close record for this direction. Nothing more can be sent; the
    /// peer's direction is independent (half-close), so records can still be received until the
    /// peer closes too.
    ///
    /// # Errors
    /// As [`Session::seal`].
    pub fn close(&mut self) -> Result<Vec<u8>, TransportError> {
        let r = self.seal_frame(TYPE_CLOSE, &[])?;
        self.sent_close = true;
        Ok(r)
    }

    /// Verify, then decrypt, the next record from the peer. Records must arrive exactly once and
    /// in order; **any** failure ends the session.
    ///
    /// # Errors
    /// [`TransportError::Authentication`], [`TransportError::Order`],
    /// [`TransportError::WrongSession`], [`TransportError::Malformed`], entropy errors.
    pub fn open(&mut self, record: &[u8]) -> Result<Opened, TransportError> {
        if self.state == State::Dead {
            return Err(TransportError::Terminated);
        }
        if self.recv_closed {
            return Err(TransportError::Closed);
        }
        match self.open_inner(record) {
            Ok(o) => Ok(o),
            Err(e) => self.kill(e),
        }
    }

    fn open_inner(&mut self, rec: &[u8]) -> Result<Opened, TransportError> {
        if rec.len() < REC_HEADER + MIN_FRAME + TAG_LEN || rec[0] != VERSION {
            return Err(TransportError::Malformed);
        }
        if rec[1..17] != self.sid || rec[17] != (self.ep.dir() ^ 1) {
            return Err(TransportError::WrongSession);
        }
        let seq = u64::from_be_bytes(
            rec[18..26]
                .try_into()
                .map_err(|_| TransportError::Malformed)?,
        );
        if seq != self.recv_seq {
            return Err(TransportError::Order {
                expected: self.recv_seq,
                got: seq,
            });
        }
        let frame_len = u32::from_be_bytes(
            rec[26..30]
                .try_into()
                .map_err(|_| TransportError::Malformed)?,
        ) as usize;
        if !(MIN_FRAME..=MAX_RECORD_DATA + 5).contains(&frame_len)
            || rec.len() != REC_HEADER + frame_len + TAG_LEN
        {
            return Err(TransportError::Malformed);
        }
        let (signed, tag_bytes) = rec.split_at(REC_HEADER + frame_len);
        let mut t = [0u8; TAG_LEN];
        t.copy_from_slice(tag_bytes);
        // The authentication pad is spent even if the tag is wrong; so is the session.
        let auth_pad = self.ep.recv_auth.reserve(TAG_LEN)?;
        self.recv
            .verify(
                &tagged(DOM_RECORD, &[signed]),
                &Tag::from_bytes(t),
                auth_pad,
            )
            .map_err(|_| TransportError::Authentication)?;
        // Authentic: now (and only now) spend the encryption pad.
        let pad = self.ep.recv_enc.reserve(frame_len)?.into_secret();
        let mut frame = signed[REC_HEADER..].to_vec();
        for (c, p) in frame.iter_mut().zip(pad.iter()) {
            *c ^= p;
        }
        self.recv_seq += 1;
        let kind = frame[0];
        let len = u32::from_be_bytes(
            frame[1..5]
                .try_into()
                .map_err(|_| TransportError::Malformed)?,
        ) as usize;
        if len > frame_len - 5 || frame[5 + len..].iter().any(|&b| b != 0) {
            frame.zeroize();
            return Err(TransportError::Malformed);
        }
        match kind {
            TYPE_DATA => Ok(Opened::Data(frame[5..5 + len].to_vec())),
            TYPE_CLOSE if len == 0 => {
                self.recv_closed = true;
                Ok(Opened::Closed)
            }
            _ => Err(TransportError::Malformed),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
