//! Classic RFC 6962 CT logs (`get-sth`, `get-entries`, `get-proof-by-hash`,
//! `get-sth-consistency`), presented to CyberMesh like static CT logs.
//!
//! Most CT logs are still classic RFC 6962 logs, including those of DigiCert, Cloudflare and
//! Sectigo. They have no tiles and no checkpoints, but the rest of CyberMesh needs only:
//!
//! * a **checkpoint**: a signed tree head carries exactly the `TreeHeadSignature` that static
//!   CT checkpoints carry as a note signature, so [`sth_note`] rebuilds the note and
//!   [`verify_checkpoint`](crate::verify_checkpoint) checks it unchanged. As for static logs
//!   the signature does not cover the origin, so the origin is pinned in the evidence.
//! * **entries per tile**: 256 consecutive entries, in the same [`Entry`] form as a parsed
//!   data tile ([`Rfc6962Source`] fetches them with `get-entries`).
//! * **authentication**: static logs prove a tile root with their hash tiles. Classic logs
//!   serve audit paths instead: one `get-proof-by-hash` call for the tile's first entry gives
//!   the path from it to the signed root. Its first eight hashes must rebuild the tile root
//!   from the 256 entries received, and the rest must lead to the signed root, so every entry
//!   and its position are bound ([`Rfc6962Authenticator`]).
//! * **consistency** between checkpoints, from `get-sth-consistency`.
//!
//! Only ECDSA P-256 logs are supported, as for static logs.

use std::collections::VecDeque;
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use cybermesh_analysis::CtLogInfo;
use cybermesh_anchor::merkle;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::checkpoint::{Checkpoint, LogKey};
use crate::proof::{Consistency, LogAuthenticator};
use crate::tile::{Entry, EntryKind, MAX_CERT_BYTES, WIDTH};
use crate::{CtError, TileSource};

type Hash = [u8; 32];

/// Largest JSON response accepted from a classic log (a 256-entry `get-entries` answer with
/// large certificates and chains is a few MiB).
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
/// `get-entries` requests made for one tile at most. Logs cap the entries they return per
/// request (often far below 256), so a tile may need several.
const MAX_GET_ENTRIES_CALLS: usize = 300;
/// Tiles whose entries are kept, since a tile is read to scan it and to authenticate it.
const CACHED_TILES: usize = 4;
/// Longest audit or consistency path accepted (a tree of 2^63 leaves needs 63 hashes).
const MAX_PATH: usize = 64;

/// A signed tree head as served by `get-sth`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sth {
    pub tree_size: u64,
    /// Milliseconds since the epoch.
    pub timestamp: u64,
    pub root: Hash,
    /// The TLS `DigitallySigned` structure: hash algorithm, signature algorithm, length, DER.
    pub signature: Vec<u8>,
}

#[derive(Deserialize)]
struct SthJson {
    tree_size: u64,
    timestamp: u64,
    sha256_root_hash: String,
    tree_head_signature: String,
}

#[derive(Deserialize)]
struct EntriesJson {
    entries: Vec<EntryJson>,
}

#[derive(Deserialize)]
struct EntryJson {
    leaf_input: String,
}

#[derive(Deserialize)]
struct ProofJson {
    leaf_index: u64,
    audit_path: Vec<String>,
}

#[derive(Deserialize)]
struct ConsistencyJson {
    consistency: Vec<String>,
}

fn hash_from_b64(s: &str) -> Result<Hash, CtError> {
    B64.decode(s)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| CtError::Malformed("hash is not 32 bytes of base64".into()))
}

fn path_from_b64(v: &[String]) -> Result<Vec<Hash>, CtError> {
    if v.len() > MAX_PATH {
        return Err(CtError::Malformed("proof path is too long".into()));
    }
    v.iter().map(|s| hash_from_b64(s)).collect()
}

/// Parses a `get-sth` response body.
pub fn parse_sth(body: &[u8]) -> Result<Sth, CtError> {
    let j: SthJson = serde_json::from_slice(body)
        .map_err(|e| CtError::Malformed(format!("get-sth response: {e}")))?;
    Ok(Sth {
        tree_size: j.tree_size,
        timestamp: j.timestamp,
        root: hash_from_b64(&j.sha256_root_hash)?,
        signature: B64
            .decode(&j.tree_head_signature)
            .map_err(|_| CtError::Malformed("tree_head_signature is not base64".into()))?,
    })
}

/// Parses a `get-entries` response body into `leaf_input`s.
pub fn parse_entries(body: &[u8]) -> Result<Vec<Vec<u8>>, CtError> {
    let j: EntriesJson = serde_json::from_slice(body)
        .map_err(|e| CtError::Malformed(format!("get-entries response: {e}")))?;
    j.entries
        .iter()
        .map(|e| {
            B64.decode(&e.leaf_input)
                .map_err(|_| CtError::Malformed("leaf_input is not base64".into()))
        })
        .collect()
}

/// Parses a `get-proof-by-hash` response body into the leaf index and audit path.
pub fn parse_proof(body: &[u8]) -> Result<(u64, Vec<Hash>), CtError> {
    let j: ProofJson = serde_json::from_slice(body)
        .map_err(|e| CtError::Malformed(format!("get-proof-by-hash response: {e}")))?;
    Ok((j.leaf_index, path_from_b64(&j.audit_path)?))
}

/// Parses a `get-sth-consistency` response body.
pub fn parse_consistency(body: &[u8]) -> Result<Vec<Hash>, CtError> {
    let j: ConsistencyJson = serde_json::from_slice(body)
        .map_err(|e| CtError::Malformed(format!("get-sth-consistency response: {e}")))?;
    path_from_b64(&j.consistency)
}

/// The note text of a signed tree head, as a static CT log would serve it as a checkpoint:
/// origin, size and root, then one signature line by the pinned key whose blob is the key ID,
/// the timestamp and the log's `DigitallySigned`.
#[must_use]
pub fn sth_note(sth: &Sth, key: &LogKey) -> String {
    let mut blob = key.key_id().to_vec();
    blob.extend_from_slice(&sth.timestamp.to_be_bytes());
    blob.extend_from_slice(&sth.signature);
    let origin = key.origin();
    format!(
        "{origin}\n{}\n{}\n\n\u{2014} {origin} {}\n",
        sth.tree_size,
        B64.encode(sth.root),
        B64.encode(blob)
    )
}

/// Read access to one classic log. Implemented over HTTPS by
/// [`HttpLogApi`](crate::http::HttpLogApi) and in memory by the mock log.
pub trait LogApi: Send + Sync {
    /// `get-sth`.
    fn get_sth(&self) -> Result<Sth, CtError>;
    /// `get-entries` for `start..=end`: the `leaf_input` of each entry returned. A log may
    /// return fewer entries than asked, never more.
    fn get_entries(&self, start: u64, end: u64) -> Result<Vec<Vec<u8>>, CtError>;
    /// `get-proof-by-hash`: the index of the leaf with this hash in the tree of `tree_size`,
    /// and its audit path.
    fn get_proof_by_hash(
        &self,
        leaf_hash: &Hash,
        tree_size: u64,
    ) -> Result<(u64, Vec<Hash>), CtError>;
    /// `get-sth-consistency` from `first` to `second`.
    fn get_sth_consistency(&self, first: u64, second: u64) -> Result<Vec<Hash>, CtError>;
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], CtError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.buf.len())
            .ok_or_else(|| CtError::Malformed("leaf_input is truncated".into()))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn uint(&mut self, n: usize) -> Result<u64, CtError> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0, |a, b| (a << 8) | u64::from(*b)))
    }

    fn vec(&mut self, len_bytes: usize, min: usize, max: usize) -> Result<&[u8], CtError> {
        let n = usize::try_from(self.uint(len_bytes)?)
            .map_err(|_| CtError::Malformed("length".into()))?;
        if n < min || n > max {
            return Err(CtError::Malformed("length out of range".into()));
        }
        self.take(n)
    }
}

/// Parses an RFC 6962 `MerkleTreeLeaf` (`leaf_input`) at position `index`: its certificate
/// or precertificate TBSCertificate, and its leaf hash `SHA-256(0x00 || leaf_input)`.
pub fn parse_leaf_input(index: u64, leaf_input: &[u8]) -> Result<Entry, CtError> {
    let mut r = Reader {
        buf: leaf_input,
        pos: 0,
    };
    let (version, leaf_type) = (r.uint(1)?, r.uint(1)?);
    if version != 0 || leaf_type != 0 {
        return Err(CtError::Malformed(
            "unsupported MerkleTreeLeaf version or leaf type".into(),
        ));
    }
    let timestamp = r.uint(8)?;
    let (kind, der) = match r.uint(2)? {
        0 => (EntryKind::X509, r.vec(3, 1, MAX_CERT_BYTES)?),
        1 => {
            r.take(32)?; // issuer_key_hash
            (EntryKind::Precert, r.vec(3, 1, MAX_CERT_BYTES)?)
        }
        other => return Err(CtError::Malformed(format!("unknown entry type {other}"))),
    };
    let der = der.to_vec();
    r.vec(2, 0, 0xffff)?; // extensions
    if r.pos != leaf_input.len() {
        return Err(CtError::Malformed("trailing bytes in leaf_input".into()));
    }
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(leaf_input);
    Ok(Entry {
        index,
        timestamp,
        kind,
        der,
        leaf_hash: h.finalize().into(),
    })
}

/// A classic log as a [`TileSource`]: its checkpoint is the signed tree head as a note, and
/// tile `n` is entries `256n..256n+256`.
pub struct Rfc6962Source {
    api: Box<dyn LogApi>,
    key: LogKey,
    cache: Mutex<VecDeque<(u64, Vec<Entry>, usize)>>,
}

impl std::fmt::Debug for Rfc6962Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rfc6962Source")
            .field("origin", &self.key.origin())
            .finish_non_exhaustive()
    }
}

impl Rfc6962Source {
    /// Access to the log pinned as `log`, through `api`.
    pub fn new(api: Box<dyn LogApi>, log: &CtLogInfo) -> Result<Self, CtError> {
        Ok(Self {
            api,
            key: LogKey::from_info(log)?,
            cache: Mutex::new(VecDeque::new()),
        })
    }
}

impl TileSource for Rfc6962Source {
    fn data_tile(&self, _n: u64) -> Result<Vec<u8>, CtError> {
        Err(CtError::NotFound(
            "an RFC 6962 log has no data tiles".into(),
        ))
    }

    fn hash_tile(&self, _level: u8, _n: u64, _width: Option<u8>) -> Result<Vec<u8>, CtError> {
        Err(CtError::NotFound(
            "an RFC 6962 log has no hash tiles".into(),
        ))
    }

    fn checkpoint(&self) -> Result<String, CtError> {
        Ok(sth_note(&self.api.get_sth()?, &self.key))
    }

    fn entries(&self, n: u64) -> Result<(Vec<Entry>, usize), CtError> {
        if let Ok(c) = self.cache.lock()
            && let Some((_, e, size)) = c.iter().find(|(t, _, _)| *t == n)
        {
            return Ok((e.clone(), *size));
        }
        let first = n
            .checked_mul(WIDTH as u64)
            .filter(|f| f.checked_add(WIDTH as u64).is_some())
            .ok_or_else(|| CtError::Malformed("tile index overflow".into()))?;
        let mut out: Vec<Entry> = Vec::with_capacity(WIDTH);
        let mut bytes = 0usize;
        for _ in 0..MAX_GET_ENTRIES_CALLS {
            if out.len() == WIDTH {
                break;
            }
            let start = first + out.len() as u64;
            let wanted = WIDTH - out.len();
            let got = self.api.get_entries(start, first + WIDTH as u64 - 1)?;
            if got.is_empty() {
                return Err(CtError::Malformed("the log returned no entries".into()));
            }
            if got.len() > wanted {
                return Err(CtError::Malformed(
                    "the log returned more entries than asked".into(),
                ));
            }
            for leaf in got {
                bytes += leaf.len();
                out.push(parse_leaf_input(first + out.len() as u64, &leaf)?);
            }
        }
        if out.len() != WIDTH {
            return Err(CtError::Malformed(
                "the log served too few entries per request".into(),
            ));
        }
        if let Ok(mut c) = self.cache.lock() {
            if c.len() >= CACHED_TILES {
                c.pop_front();
            }
            c.push_back((n, out.clone(), bytes));
        }
        Ok((out, bytes))
    }

    fn api(&self) -> Option<&dyn LogApi> {
        Some(&*self.api)
    }
}

/// Proves tile roots and checkpoint consistency against one verified checkpoint of a classic
/// log.
pub struct Rfc6962Authenticator<'a> {
    src: &'a dyn TileSource,
    api: &'a dyn LogApi,
    checkpoint: Checkpoint,
}

impl std::fmt::Debug for Rfc6962Authenticator<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rfc6962Authenticator")
            .field("size", &self.checkpoint.size)
            .finish_non_exhaustive()
    }
}

impl<'a> Rfc6962Authenticator<'a> {
    /// `checkpoint` must have been verified ([`crate::verify_checkpoint`]). `None` if `src`
    /// is not a classic log.
    #[must_use]
    pub fn new(src: &'a dyn TileSource, checkpoint: Checkpoint) -> Option<Self> {
        Some(Self {
            src,
            api: src.api()?,
            checkpoint,
        })
    }

    /// The root of this tree's first `m` entries (`0 < m < size`), proven against the signed
    /// root, together with the consistency proof from it.
    fn prefix_root(&self, m: u64) -> Result<(Hash, Vec<Hash>), CtError> {
        let n = self.checkpoint.size;
        let proof = self.api.get_sth_consistency(m, n)?;
        let unauth = |what: &str| CtError::Unauthenticated(what.to_owned());
        let prefix = if m.is_power_of_two() {
            // The proof leaves out the root of a perfect first tree. It is the fold of the
            // first log2(m) hashes of the audit path of entry 0.
            let first = self.src.entries(0).and_then(|(e, _)| {
                e.first()
                    .map(|e| e.leaf_hash)
                    .ok_or_else(|| CtError::Malformed("empty tile".into()))
            })?;
            let (index, path) = self.api.get_proof_by_hash(&first, n)?;
            let k = m.trailing_zeros() as usize;
            if index != 0
                || path.len() < k
                || !merkle::verify_inclusion(0, n, &first, &path, &self.checkpoint.root)
            {
                return Err(unauth("the audit path of the first entry does not verify"));
            }
            path[..k]
                .iter()
                .fold(first, |h, p| merkle::node_hash(&h, p))
        } else {
            first_root_of(m, n, &proof, &self.checkpoint.root)
                .ok_or_else(|| unauth("the consistency proof does not verify"))?
        };
        if !merkle::verify_consistency(m, n, &prefix, &self.checkpoint.root, &proof) {
            return Err(unauth("the consistency proof does not verify"));
        }
        Ok((prefix, proof))
    }
}

/// The root of the first `m` leaves implied by an RFC 6962 consistency `proof` to a tree of
/// `n` leaves with root `second`, if the proof leads to `second`. For `m` a power of two the
/// proof does not contain it, so this is for other `m` (RFC 9162 section 2.1.4.2).
fn first_root_of(m: u64, n: u64, proof: &[Hash], second: &Hash) -> Option<Hash> {
    if m == 0 || m >= n || m.is_power_of_two() || proof.is_empty() {
        return None;
    }
    let (mut fn_, mut sn) = (m - 1, n - 1);
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let (mut fr, mut sr) = (proof[0], proof[0]);
    for c in &proof[1..] {
        if sn == 0 {
            return None;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = merkle::node_hash(c, &fr);
            sr = merkle::node_hash(c, &sr);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = merkle::node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    (sr == *second && sn == 0).then_some(fr)
}

impl LogAuthenticator for Rfc6962Authenticator<'_> {
    fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    fn source(&self) -> &dyn TileSource {
        self.src
    }

    fn tile_root(&self, tile: u64) -> Result<Hash, CtError> {
        let cp = &self.checkpoint;
        if tile >= cp.full_tiles() {
            return Err(CtError::NotFound(format!(
                "data tile {tile} is not full yet"
            )));
        }
        let unauth = |what: &str| CtError::Unauthenticated(format!("tile {tile}: {what}"));
        let (entries, _) = self.src.entries(tile)?;
        let leaves: Vec<Hash> = entries.iter().map(|e| e.leaf_hash).collect();
        let claimed = merkle::root(&leaves);
        let first = leaves
            .first()
            .ok_or_else(|| CtError::Malformed("empty tile".into()))?;
        let (index, path) = self.api.get_proof_by_hash(first, cp.size)?;
        if index != tile * WIDTH as u64 || path.len() < 8 {
            return Err(unauth("the audit path is for another entry"));
        }
        // The first entry of an aligned tile is always a left child: eight steps rebuild the
        // tile root from the entries received.
        let rebuilt = path[..8]
            .iter()
            .fold(*first, |h, p| merkle::node_hash(&h, p));
        if rebuilt != claimed {
            return Err(unauth("the entries do not match the log's audit path"));
        }
        let tiles = ((cp.size - 1) >> 8) + 1;
        if !merkle::verify_inclusion(tile, tiles, &claimed, &path[8..], &cp.root) {
            return Err(unauth("the audit path does not lead to the signed root"));
        }
        Ok(claimed)
    }

    fn prove_extends(&self, older: &Checkpoint) -> Result<(), CtError> {
        let (m, n) = (older.size, self.checkpoint.size);
        if m > n {
            return Err(CtError::Unauthenticated(format!(
                "checkpoint size {n} is smaller than an earlier verified size {m}"
            )));
        }
        let proof = if m > 0 && m < n {
            self.api.get_sth_consistency(m, n)?
        } else {
            Vec::new()
        };
        if merkle::verify_consistency(m, n, &older.root, &self.checkpoint.root, &proof) {
            Ok(())
        } else {
            Err(CtError::Unauthenticated(format!(
                "checkpoint of size {n} is not consistent with the earlier checkpoint of size {m}"
            )))
        }
    }

    fn consistency_with(&self, other: &Checkpoint) -> Result<Consistency, CtError> {
        let (m, n) = (other.size, self.checkpoint.size);
        if m > n {
            return Err(CtError::Unauthenticated(format!(
                "compare against the larger checkpoint ({m} > {n})"
            )));
        }
        if m == n {
            return Ok(if other.root == self.checkpoint.root {
                Consistency::Consistent
            } else {
                Consistency::Inconsistent {
                    prefix_root: self.checkpoint.root,
                    proof: Vec::new(),
                }
            });
        }
        let (prefix_root, proof) = if m == 0 {
            (merkle::empty_root(), Vec::new())
        } else {
            self.prefix_root(m)?
        };
        Ok(if prefix_root == other.root {
            Consistency::Consistent
        } else {
            Consistency::Inconsistent { prefix_root, proof }
        })
    }
}
