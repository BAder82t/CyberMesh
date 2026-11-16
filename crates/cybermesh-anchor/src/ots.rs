//! Minimal OpenTimestamps support.
//!
//! * Codec for the standard detached-timestamp (`.ots`) format: parse, serialise, evaluate.
//! * Offline verification: recomputes every operation path from the commitment and reports
//!   each attestation it reaches (pending calendar, or Bitcoin block height plus the merkle
//!   root the block header must contain).
//! * With the `ots` feature: an HTTPS calendar client (`stamp`, `upgrade`) and an [`Anchor`]
//!   implementation.
//!
//! Supported operations: append, prepend, sha256, reverse, hexlify. Proof branches using
//! sha1, ripemd160 or keccak256 are reported as unverifiable rather than trusted.

use sha2::{Digest as _, Sha256};

use crate::anchor::{AnchorError, AnchorStatus};

const MAX_MSG: usize = 4096;
const MAX_DEPTH: usize = 256;
/// Total nodes in one proof (bounds breadth; depth is bounded by `MAX_DEPTH`).
const MAX_NODES: usize = 4096;
/// Total message bytes stored across all nodes of one proof (bounds amplification from
/// cheap ops such as `reverse` on a 4 KiB message).
const MAX_TOTAL_MSG_BYTES: usize = 2 * 1024 * 1024;
const MAJOR_VERSION: u64 = 1;
const TAG_PENDING: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const TAG_BITCOIN: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];

/// The 31-byte magic header of `.ots` files.
#[must_use]
pub fn header_magic() -> Vec<u8> {
    let mut v = vec![0u8];
    v.extend_from_slice(b"OpenTimestamps");
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(b"Proof");
    v.push(0);
    v.extend_from_slice(&[0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]);
    v
}

/// A commitment operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Append(Vec<u8>),
    Prepend(Vec<u8>),
    Sha256,
    Reverse,
    Hexlify,
    /// Unary op that is parsed but not evaluated (sha1 0x02, ripemd160 0x03, keccak 0x67).
    Unsupported(u8),
}

impl Op {
    fn tag(&self) -> u8 {
        match self {
            Op::Append(_) => 0xf0,
            Op::Prepend(_) => 0xf1,
            Op::Reverse => 0xf2,
            Op::Hexlify => 0xf3,
            Op::Sha256 => 0x08,
            Op::Unsupported(t) => *t,
        }
    }

    /// Applies the op; `None` when unsupported or the result is too long.
    #[must_use]
    pub fn apply(&self, msg: &[u8]) -> Option<Vec<u8>> {
        let out = match self {
            Op::Append(a) => [msg, a.as_slice()].concat(),
            Op::Prepend(p) => [p.as_slice(), msg].concat(),
            Op::Sha256 => Sha256::digest(msg).to_vec(),
            Op::Reverse => msg.iter().rev().copied().collect(),
            Op::Hexlify => hex::encode(msg).into_bytes(),
            Op::Unsupported(_) => return None,
        };
        (out.len() <= MAX_MSG).then_some(out)
    }
}

/// A time attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attestation {
    Pending { uri: String },
    Bitcoin { height: u64 },
    Unknown { tag: [u8; 8], payload: Vec<u8> },
}

/// A timestamp tree rooted at `msg`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Timestamp {
    pub msg: Vec<u8>,
    pub attestations: Vec<Attestation>,
    pub ops: Vec<(Op, Timestamp)>,
}

/// A detached timestamp over a SHA-256 file digest (the `.ots` file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedTimestamp {
    pub timestamp: Timestamp,
}

// ---------------------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------------------

fn write_varuint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

fn write_varbytes(out: &mut Vec<u8>, b: &[u8]) {
    write_varuint(out, b.len() as u64);
    out.extend_from_slice(b);
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    nodes: usize,
    msg_bytes: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], pos: usize) -> Self {
        Self {
            buf,
            pos,
            nodes: 0,
            msg_bytes: 0,
        }
    }

    fn charge(&mut self, msg_len: usize) -> Result<(), AnchorError> {
        self.nodes += 1;
        self.msg_bytes += msg_len;
        if self.nodes > MAX_NODES || self.msg_bytes > MAX_TOTAL_MSG_BYTES {
            return Err(AnchorError::InvalidReceipt("proof exceeds size budget".into()));
        }
        Ok(())
    }
}

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], AnchorError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.buf.len())
            .ok_or_else(|| AnchorError::InvalidReceipt("truncated ots data".into()))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8, AnchorError> {
        Ok(self.bytes(1)?[0])
    }

    fn varuint(&mut self) -> Result<u64, AnchorError> {
        let mut v: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            if shift == 63 && (b & 0x7f) > 1 {
                return Err(AnchorError::InvalidReceipt("varuint overflows u64".into()));
            }
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(AnchorError::InvalidReceipt("varuint too long".into()))
    }

    fn varbytes(&mut self, max: usize) -> Result<&'a [u8], AnchorError> {
        let n = usize::try_from(self.varuint()?)
            .map_err(|_| AnchorError::InvalidReceipt("length".into()))?;
        if n > max {
            return Err(AnchorError::InvalidReceipt("varbytes too long".into()));
        }
        self.bytes(n)
    }
}

impl Attestation {
    fn serialize(&self, out: &mut Vec<u8>) {
        let mut payload = Vec::new();
        let tag = match self {
            Attestation::Pending { uri } => {
                write_varbytes(&mut payload, uri.as_bytes());
                TAG_PENDING
            }
            Attestation::Bitcoin { height } => {
                write_varuint(&mut payload, *height);
                TAG_BITCOIN
            }
            Attestation::Unknown { tag, payload: p } => {
                payload.extend_from_slice(p);
                *tag
            }
        };
        out.extend_from_slice(&tag);
        write_varbytes(out, &payload);
    }

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, AnchorError> {
        let mut tag = [0u8; 8];
        tag.copy_from_slice(r.bytes(8)?);
        let payload = r.varbytes(8192)?;
        let mut pr = Reader::new(payload, 0);
        let att = match tag {
            TAG_PENDING => {
                let uri = pr.varbytes(1000)?;
                let uri = std::str::from_utf8(uri)
                    .map_err(|_| AnchorError::InvalidReceipt("calendar uri not utf-8".into()))?;
                if !uri.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(AnchorError::InvalidReceipt("calendar uri has invalid chars".into()));
                }
                Attestation::Pending {
                    uri: uri.to_owned(),
                }
            }
            TAG_BITCOIN => Attestation::Bitcoin {
                height: pr.varuint()?,
            },
            _ => {
                return Ok(Attestation::Unknown {
                    tag,
                    payload: payload.to_vec(),
                });
            }
        };
        if pr.pos != payload.len() {
            return Err(AnchorError::InvalidReceipt("trailing bytes in attestation".into()));
        }
        Ok(att)
    }
}

impl Op {
    fn serialize(&self, out: &mut Vec<u8>) {
        out.push(self.tag());
        if let Op::Append(a) | Op::Prepend(a) = self {
            write_varbytes(out, a);
        }
    }

    fn deserialize(tag: u8, r: &mut Reader<'_>) -> Result<Self, AnchorError> {
        Ok(match tag {
            0xf0 => Op::Append(r.varbytes(MAX_MSG)?.to_vec()),
            0xf1 => Op::Prepend(r.varbytes(MAX_MSG)?.to_vec()),
            0xf2 => Op::Reverse,
            0xf3 => Op::Hexlify,
            0x08 => Op::Sha256,
            0x02 | 0x03 | 0x67 => Op::Unsupported(tag),
            other => {
                return Err(AnchorError::InvalidReceipt(format!("unknown op tag {other:#04x}")));
            }
        })
    }
}

impl Timestamp {
    /// Serialises the tree (python-opentimestamps compatible layout: `0xff` fork markers,
    /// `0x00` attestation marker, last child without a fork marker).
    pub fn serialize(&self, out: &mut Vec<u8>) {
        let n_items = self.attestations.len() + self.ops.len();
        let mut i = 0usize;
        for a in &self.attestations {
            i += 1;
            if i < n_items {
                out.push(0xff);
            }
            out.push(0x00);
            a.serialize(out);
        }
        for (op, child) in &self.ops {
            i += 1;
            if i < n_items {
                out.push(0xff);
            }
            op.serialize(out);
            child.serialize(out);
        }
    }

    /// Parses a timestamp whose root message is `msg`.
    pub fn deserialize(buf: &[u8], msg: Vec<u8>) -> Result<Self, AnchorError> {
        let mut r = Reader::new(buf, 0);
        let t = Self::read(&mut r, msg, 0)?;
        if r.pos != buf.len() {
            return Err(AnchorError::InvalidReceipt("trailing bytes after timestamp".into()));
        }
        Ok(t)
    }

    fn read(r: &mut Reader<'_>, msg: Vec<u8>, depth: usize) -> Result<Self, AnchorError> {
        if depth > MAX_DEPTH {
            return Err(AnchorError::InvalidReceipt("timestamp too deep".into()));
        }
        r.charge(msg.len())?;
        let mut t = Timestamp {
            msg,
            ..Timestamp::default()
        };
        let mut tag = r.byte()?;
        while tag == 0xff {
            let inner = r.byte()?;
            t.read_item(r, inner, depth)?;
            tag = r.byte()?;
        }
        t.read_item(r, tag, depth)?;
        Ok(t)
    }

    fn read_item(&mut self, r: &mut Reader<'_>, tag: u8, depth: usize) -> Result<(), AnchorError> {
        if tag == 0x00 {
            self.attestations.push(Attestation::deserialize(r)?);
            return Ok(());
        }
        let op = Op::deserialize(tag, r)?;
        // Unsupported ops still need a child message to keep parsing; use an empty marker
        // message that can never match a real attestation.
        let child_msg = op.apply(&self.msg).unwrap_or_default();
        let child = Self::read(r, child_msg, depth + 1)?;
        self.ops.push((op, child));
        Ok(())
    }

    /// Walks the tree and reports every attestation with the message it attests.
    pub fn attestations_with_msgs(&self) -> Vec<(Vec<u8>, Result<Attestation, String>)> {
        let mut out = Vec::new();
        self.walk(&mut out, true);
        out
    }

    fn walk(&self, out: &mut Vec<(Vec<u8>, Result<Attestation, String>)>, valid: bool) {
        for a in &self.attestations {
            if valid {
                out.push((self.msg.clone(), Ok(a.clone())));
            } else {
                out.push((Vec::new(), Err("branch uses an unsupported operation".into())));
            }
        }
        for (op, child) in &self.ops {
            let ok = valid && matches!(op.apply(&self.msg), Some(ref m) if *m == child.msg);
            child.walk(out, ok && !matches!(op, Op::Unsupported(_)));
        }
    }
}

impl DetachedTimestamp {
    /// Serialises as a standard `.ots` file (SHA-256 file hash op).
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = header_magic();
        write_varuint(&mut out, MAJOR_VERSION);
        out.push(0x08);
        out.extend_from_slice(&self.timestamp.msg);
        self.timestamp.serialize(&mut out);
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, AnchorError> {
        let magic = header_magic();
        if bytes.len() < magic.len() || bytes[..magic.len()] != magic[..] {
            return Err(AnchorError::InvalidReceipt("not an OpenTimestamps proof".into()));
        }
        let mut r = Reader::new(bytes, magic.len());
        if r.varuint()? != MAJOR_VERSION {
            return Err(AnchorError::InvalidReceipt("unsupported ots version".into()));
        }
        if r.byte()? != 0x08 {
            return Err(AnchorError::Unsupported("only sha256 file digests are supported".into()));
        }
        let digest = r.bytes(32)?.to_vec();
        let timestamp = Timestamp::deserialize(&bytes[r.pos..], digest)?;
        Ok(Self { timestamp })
    }

    /// Offline verification against the expected 32-byte commitment.
    pub fn verify(&self, commitment: &[u8; 32]) -> Result<Vec<AnchorStatus>, AnchorError> {
        if self.timestamp.msg != commitment {
            return Err(AnchorError::InvalidReceipt(
                "proof is for a different commitment".into(),
            ));
        }
        let mut statuses = Vec::new();
        for (msg, att) in self.timestamp.attestations_with_msgs() {
            statuses.push(match att {
                Ok(Attestation::Pending { uri }) => AnchorStatus::Pending { calendar: uri },
                Ok(Attestation::Bitcoin { height }) => {
                    if msg.len() != 32 {
                        AnchorStatus::Unverifiable {
                            reason: "bitcoin attestation over non-32-byte message".into(),
                        }
                    } else {
                        let display: Vec<u8> = msg.iter().rev().copied().collect();
                        AnchorStatus::BitcoinAttested {
                            height,
                            merkle_root_display: hex::encode(display),
                        }
                    }
                }
                Ok(Attestation::Unknown { tag, .. }) => AnchorStatus::Unverifiable {
                    reason: format!("unknown attestation type {}", hex::encode(tag)),
                },
                Err(reason) => AnchorStatus::Unverifiable { reason },
            });
        }
        if statuses.is_empty() {
            return Err(AnchorError::InvalidReceipt("proof has no attestations".into()));
        }
        Ok(statuses)
    }
}

/// Builds the client-side part of a stamp: `commitment -> append(nonce) -> sha256 -> tip`.
/// Returns the detached timestamp skeleton and the tip that is submitted to calendars. The
/// random nonce keeps the commitment itself private from calendar operators.
#[must_use]
pub fn prepare(commitment: [u8; 32], nonce: [u8; 16]) -> (DetachedTimestamp, Vec<u8>) {
    let appended = [commitment.as_slice(), nonce.as_slice()].concat();
    let tip = Sha256::digest(&appended).to_vec();
    let ts = Timestamp {
        msg: commitment.to_vec(),
        attestations: vec![],
        ops: vec![(
            Op::Append(nonce.to_vec()),
            Timestamp {
                msg: appended,
                attestations: vec![],
                ops: vec![(
                    Op::Sha256,
                    Timestamp {
                        msg: tip.clone(),
                        ..Timestamp::default()
                    },
                )],
            },
        )],
    };
    (DetachedTimestamp { timestamp: ts }, tip)
}

/// Attaches calendar responses (timestamps rooted at the tip) to a prepared stamp.
pub fn attach(dt: &mut DetachedTimestamp, responses: Vec<Timestamp>) -> Result<(), AnchorError> {
    let tip = dt
        .timestamp
        .ops
        .get_mut(0)
        .and_then(|(_, t)| t.ops.get_mut(0))
        .map(|(_, t)| t)
        .ok_or_else(|| AnchorError::InvalidReceipt("not a prepared stamp".into()))?;
    for r in responses {
        if r.msg != tip.msg {
            return Err(AnchorError::InvalidReceipt("calendar answered a different digest".into()));
        }
        tip.attestations.extend(r.attestations);
        tip.ops.extend(r.ops);
    }
    Ok(())
}

#[cfg(feature = "ots")]
mod client {
    use std::io::Read as _;
    use std::time::Duration;

    use base64::Engine as _;
    use cybermesh_crypto::{Digest, random_bytes};

    use super::{DetachedTimestamp, Timestamp, attach, prepare};
    use crate::anchor::{Anchor, AnchorError, AnchorReceipt};

    /// Public calendars run by the OpenTimestamps project and community.
    pub const DEFAULT_CALENDARS: &[&str] = &[
        "https://a.pool.opentimestamps.org",
        "https://b.pool.opentimestamps.org",
        "https://a.pool.eternitywall.com",
    ];

    fn agent(timeout: Duration) -> ureq::Agent {
        ureq::AgentBuilder::new()
            .timeout(timeout)
            .redirects(0)
            .user_agent("cybermesh-anchor")
            .build()
    }

    fn read_limited(resp: ureq::Response) -> Result<Vec<u8>, AnchorError> {
        let mut body = Vec::new();
        resp.into_reader()
            .take(10_000)
            .read_to_end(&mut body)
            .map_err(|e| AnchorError::Unavailable(e.to_string()))?;
        Ok(body)
    }

    /// Submits a commitment to calendars. Succeeds if at least one calendar answers.
    pub fn stamp(
        commitment: [u8; 32],
        calendars: &[String],
        timeout: Duration,
    ) -> Result<DetachedTimestamp, AnchorError> {
        let nonce = random_bytes::<16>().map_err(|e| AnchorError::Unavailable(e.to_string()))?;
        let (mut dt, tip) = prepare(commitment, nonce);
        let agent = agent(timeout);
        let mut responses = Vec::new();
        let mut errors = Vec::new();
        for cal in calendars {
            let url = format!("{}/digest", cal.trim_end_matches('/'));
            match agent
                .post(&url)
                .set("Accept", "application/vnd.opentimestamps.v1")
                .send_bytes(&tip)
            {
                Ok(resp) => match read_limited(resp)
                    .and_then(|body| Timestamp::deserialize(&body, tip.clone()))
                {
                    Ok(t) => responses.push(t),
                    Err(e) => errors.push(format!("{cal}: {e}")),
                },
                Err(e) => errors.push(format!("{cal}: {e}")),
            }
        }
        if responses.is_empty() {
            return Err(AnchorError::Unavailable(errors.join("; ")));
        }
        attach(&mut dt, responses)?;
        Ok(dt)
    }

    /// Maximum calendar requests made by one `upgrade` call.
    const MAX_UPGRADE_REQUESTS: usize = 16;

    /// Asks calendars for completed (Bitcoin) attestations of pending branches.
    ///
    /// Only calendars in `allowed` are contacted (a proof's own URIs are untrusted input),
    /// at most [`MAX_UPGRADE_REQUESTS`] requests are made, fetched data is never traversed
    /// again in the same call, and an upgraded pending attestation is replaced by the
    /// calendar's answer.
    pub fn upgrade(
        dt: &mut DetachedTimestamp,
        allowed: &[String],
        timeout: Duration,
    ) -> Result<usize, AnchorError> {
        fn norm(u: &str) -> &str {
            u.trim_end_matches('/')
        }
        fn visit(
            t: &mut Timestamp,
            agent: &ureq::Agent,
            allowed: &[String],
            budget: &mut usize,
            upgraded: &mut usize,
        ) {
            let existing_children = t.ops.len();
            let mut i = 0;
            while i < t.attestations.len() {
                let uri = match &t.attestations[i] {
                    super::Attestation::Pending { uri } => uri.clone(),
                    _ => {
                        i += 1;
                        continue;
                    }
                };
                if *budget == 0 || !allowed.iter().any(|a| norm(a) == norm(&uri)) {
                    i += 1;
                    continue;
                }
                *budget -= 1;
                let url = format!("{}/timestamp/{}", norm(&uri), hex::encode(&t.msg));
                let fetched = agent
                    .get(&url)
                    .set("Accept", "application/vnd.opentimestamps.v1")
                    .call()
                    .ok()
                    .and_then(|resp| read_limited(resp).ok())
                    .and_then(|body| Timestamp::deserialize(&body, t.msg.clone()).ok());
                match fetched {
                    Some(up) => {
                        t.attestations.remove(i);
                        t.attestations.extend(up.attestations);
                        t.ops.extend(up.ops);
                        *upgraded += 1;
                    }
                    None => i += 1,
                }
            }
            for (_, child) in t.ops.iter_mut().take(existing_children) {
                visit(child, agent, allowed, budget, upgraded);
            }
        }
        let agent = agent(timeout);
        let mut n = 0;
        let mut budget = MAX_UPGRADE_REQUESTS;
        visit(&mut dt.timestamp, &agent, allowed, &mut budget, &mut n);
        Ok(n)
    }

    /// OpenTimestamps anchor. Network access happens only when `submit` is called.
    #[derive(Debug, Clone)]
    pub struct OtsAnchor {
        pub calendars: Vec<String>,
        pub timeout: Duration,
    }

    impl Default for OtsAnchor {
        fn default() -> Self {
            Self {
                calendars: DEFAULT_CALENDARS.iter().map(|s| (*s).to_owned()).collect(),
                timeout: Duration::from_secs(15),
            }
        }
    }

    impl Anchor for OtsAnchor {
        fn name(&self) -> &'static str {
            "opentimestamps"
        }

        fn submit(&mut self, commitment: Digest, _now: u64) -> Result<AnchorReceipt, AnchorError> {
            let dt = stamp(commitment.0, &self.calendars, self.timeout)?;
            Ok(AnchorReceipt::OpenTimestamps {
                ots: base64::engine::general_purpose::STANDARD.encode(dt.serialize()),
                calendars: self.calendars.clone(),
            })
        }
    }
}

#[cfg(feature = "ots")]
pub use client::{DEFAULT_CALENDARS, OtsAnchor, stamp, upgrade};

#[cfg(test)]
mod tests {
    use super::*;

    fn bitcoin_proof(commitment: [u8; 32]) -> DetachedTimestamp {
        // commitment -> append(nonce) -> sha256 -> prepend(x) -> sha256 => "block merkle root"
        let (mut dt, tip) = prepare(commitment, [7u8; 16]);
        let pre = [b"left-sibling".as_slice(), tip.as_slice()].concat();
        let root = Sha256::digest(&pre).to_vec();
        let calendar = Timestamp {
            msg: tip,
            attestations: vec![Attestation::Pending {
                uri: "https://calendar.example".into(),
            }],
            ops: vec![(
                Op::Prepend(b"left-sibling".to_vec()),
                Timestamp {
                    msg: pre,
                    attestations: vec![],
                    ops: vec![(
                        Op::Sha256,
                        Timestamp {
                            msg: root,
                            attestations: vec![Attestation::Bitcoin { height: 840_000 }],
                            ops: vec![],
                        },
                    )],
                },
            )],
        };
        attach(&mut dt, vec![calendar]).unwrap();
        dt
    }

    #[test]
    fn roundtrip_and_offline_verification() {
        let c = [42u8; 32];
        let dt = bitcoin_proof(c);
        let bytes = dt.serialize();
        assert!(bytes.starts_with(&header_magic()));
        let parsed = DetachedTimestamp::parse(&bytes).unwrap();
        assert_eq!(parsed, dt);
        let statuses = parsed.verify(&c).unwrap();
        assert!(statuses.contains(&AnchorStatus::Pending {
            calendar: "https://calendar.example".into()
        }));
        assert!(statuses.iter().any(|s| matches!(
            s,
            AnchorStatus::BitcoinAttested { height: 840_000, .. }
        )));
        assert!(parsed.verify(&[0u8; 32]).is_err());
    }

    #[test]
    fn rejects_malformed_proofs() {
        let mut bytes = bitcoin_proof([1u8; 32]).serialize();
        assert!(DetachedTimestamp::parse(&bytes[..bytes.len() - 3]).is_err());
        bytes.push(0);
        assert!(DetachedTimestamp::parse(&bytes).is_err(), "trailing bytes");
        assert!(DetachedTimestamp::parse(b"not a proof").is_err());
        // Deeply nested sha256 ops beyond the recursion limit.
        let mut deep = header_magic();
        deep.push(1);
        deep.push(0x08);
        deep.extend_from_slice(&[0u8; 32]);
        deep.extend(std::iter::repeat_n(0x08u8, 300));
        assert!(DetachedTimestamp::parse(&deep).is_err());
    }

    #[test]
    fn breadth_amplification_is_bounded() {
        // Append(4064 zero bytes) then thousands of cheap Reverse forks, each storing 4 KiB.
        let mut b = header_magic();
        b.push(1);
        b.push(0x08);
        b.extend_from_slice(&[0u8; 32]);
        b.push(0xf0);
        write_varuint(&mut b, 4064);
        b.extend(std::iter::repeat_n(0u8, 4064));
        for _ in 0..5000 {
            b.extend_from_slice(&[0xff, 0xf2, 0x00]);
            b.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
            b.push(0);
        }
        b.extend_from_slice(&[0xf2, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 0]);
        assert!(DetachedTimestamp::parse(&b).is_err());
    }

    #[test]
    fn varuint_overflow_and_trailing_attestation_bytes_are_rejected() {
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f], 0);
        assert!(r.varuint().is_err());
        let mut out = Vec::new();
        out.extend_from_slice(&TAG_BITCOIN);
        write_varbytes(&mut out, &[0x05, 0x99]); // height 5 plus a trailing byte
        let mut r = Reader::new(&out, 0);
        assert!(Attestation::deserialize(&mut r).is_err());
    }

    #[test]
    fn varuint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, 840_000, u64::from(u32::MAX), u64::MAX] {
            let mut out = Vec::new();
            write_varuint(&mut out, v);
            let mut r = Reader::new(&out, 0);
            assert_eq!(r.varuint().unwrap(), v);
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        use proptest::prelude::*;
        proptest!(|(tail in proptest::collection::vec(any::<u8>(), 0..300))| {
            let mut b = header_magic();
            b.push(1);
            b.push(0x08);
            b.extend_from_slice(&[0u8; 32]);
            b.extend_from_slice(&tail);
            let _ = DetachedTimestamp::parse(&b);
        });
    }
}
