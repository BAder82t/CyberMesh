//! A synthetic static CT log for tests and demonstrations.
//!
//! Entries are real X.509 certificates (and precertificate TBSCertificates) generated with
//! `rcgen`, serialised exactly as the static CT API specifies: data tiles, hash tiles at
//! every level, and a checkpoint signed as a real static CT log signs it (RFC 6962 ECDSA
//! P-256 note signature). Only full data tiles are produced.
//!
//! The signing key is a fixed **public demonstration key** (below), so the demo evidence can
//! pin it. It protects nothing: anyone can sign as the mock log.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;

use base64::Engine as _;
use cybermesh_analysis::CtLogInfo;
use cybermesh_anchor::merkle;
use rcgen::{CertificateParams, DnType, KeyPair};
use x509_parser::prelude::*;

use crate::checkpoint::{LogKey, tree_head_input};
use crate::tile::{EntryKind, data_tile_path, encode_tile_leaf, hash_tile_path};
use crate::{CtError, TileSource};

/// PKCS#8 (DER) of the mock log's ECDSA P-256 signing key. A **public demonstration key**
/// for tests and demos only; it is not a secret and must never sign anything else.
const MOCK_LOG_PKCS8: &[u8] = &[
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
    0x01, 0x01, 0x04, 0x20, 0xd0, 0xf0, 0x92, 0x07, 0xf9, 0xbc, 0x2e, 0xdd, 0xe5, 0xcf, 0x36, 0x42,
    0xd6, 0xb2, 0xd9, 0x66, 0x57, 0xec, 0x2f, 0x1a, 0xc8, 0x95, 0x6c, 0x01, 0x33, 0xb2, 0x0d, 0xfd,
    0x44, 0x3d, 0x12, 0xbb, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xd3, 0x2f, 0x18, 0x2b, 0x49, 0xf2,
    0xae, 0x30, 0x81, 0xa9, 0x18, 0xe5, 0xd0, 0x26, 0x64, 0x70, 0xc3, 0x88, 0x24, 0xbb, 0x51, 0xaf,
    0x3a, 0x12, 0x19, 0xee, 0x6b, 0xf9, 0xb2, 0xf1, 0xcd, 0x3e, 0x93, 0xd0, 0xa2, 0x24, 0x69, 0x7a,
    0xfc, 0x7e, 0x4f, 0xd0, 0x29, 0x4a, 0x0c, 0xf6, 0xee, 0x84, 0xb9, 0x04, 0x38, 0x9b, 0x5d, 0xcf,
    0x53, 0x24, 0x7a, 0x90, 0x11, 0x05, 0x3c, 0xa4, 0x58, 0x1b,
];
/// The matching public key (base64 DER `SubjectPublicKeyInfo`), as pinned in demo evidence.
pub const MOCK_LOG_PUBLIC_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0y8YK0nyrjCBqRjl0CZkcMOIJLtRrzoSGe5r+bLxzT6T0KIkaXr8fk/QKUoM9u6EuQQ4m13PUyR6kBEFPKRYGw==";
/// Checkpoint timestamp: the time the mock log is built (verifiers refuse stale checkpoints).
fn mock_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// One synthetic log entry.
#[derive(Debug, Clone)]
pub struct MockEntry {
    pub names: Vec<String>,
    pub precert: bool,
}

/// An in-memory static CT log.
#[derive(Debug, Clone, Default)]
pub struct MockLog {
    /// Path (relative to the monitoring prefix) -> body.
    pub files: BTreeMap<String, Vec<u8>>,
    pub size: u64,
    /// Checkpoint origin (and signature key name).
    pub origin: String,
    /// All leaf hashes, in order (kept so the log can grow).
    leaves: Vec<[u8; 32]>,
}

/// Signs an RFC 6962 `TreeHeadSignature` with the mock key and returns the TLS
/// `DigitallySigned` structure (hash algorithm, signature algorithm, length, DER signature).
fn sign_tree_head(ts: u64, size: u64, root: &[u8; 32]) -> Result<Vec<u8>, CtError> {
    let rng = ring::rand::SystemRandom::new();
    let kp = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        MOCK_LOG_PKCS8,
        &rng,
    )
    .map_err(|e| CtError::Malformed(format!("mock key: {e}")))?;
    let der = kp
        .sign(&rng, &tree_head_input(ts, size, root))
        .map_err(|e| CtError::Malformed(format!("mock signature: {e}")))?;
    let mut signed = vec![4, 3];
    signed.extend_from_slice(&u16::try_from(der.as_ref().len()).unwrap_or(0).to_be_bytes());
    signed.extend_from_slice(der.as_ref());
    Ok(signed)
}

/// Signs a checkpoint body as a static CT log: an RFC 6962 `TreeHeadSignature` as a C2SP
/// note signature by `log`'s key (the mock key).
fn sign_checkpoint(origin: &str, size: u64, root: &[u8; 32]) -> Result<String, CtError> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let ts = mock_timestamp_ms();
    let signed = sign_tree_head(ts, size, root)?;
    let key = LogKey::from_info(&mock_info("mock", "http://127.0.0.1/", origin))?;
    let mut blob = key.key_id().to_vec();
    blob.extend_from_slice(&ts.to_be_bytes());
    blob.extend_from_slice(&signed);
    Ok(format!(
        "{origin}\n{size}\n{}\n\n\u{2014} {origin} {}\n",
        b64.encode(root),
        b64.encode(blob)
    ))
}

fn mock_info(log_id: &str, monitoring_url: &str, origin: &str) -> CtLogInfo {
    CtLogInfo {
        log_id: log_id.to_owned(),
        description: "Synthetic static CT log (demonstration key)".to_owned(),
        monitoring_url: monitoring_url.to_owned(),
        origin: origin.to_owned(),
        public_key: MOCK_LOG_PUBLIC_KEY.to_owned(),
    }
}

fn cert_der(key: &KeyPair, names: &[String]) -> Result<Vec<u8>, CtError> {
    let mut params = CertificateParams::new(names.to_vec())
        .map_err(|e| CtError::Malformed(format!("rcgen: {e}")))?;
    if let Some(first) = names.first() {
        params
            .distinguished_name
            .push(DnType::CommonName, first.clone());
    }
    let cert = params
        .self_signed(key)
        .map_err(|e| CtError::Malformed(format!("rcgen: {e}")))?;
    Ok(cert.der().to_vec())
}

fn tbs_of(der: &[u8]) -> Result<Vec<u8>, CtError> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| CtError::Malformed(e.to_string()))?;
    Ok(cert.tbs_certificate.as_ref().to_vec())
}

impl MockLog {
    /// Builds a log; `entries.len()` must be a multiple of 256 (full tiles only).
    pub fn build(origin: &str, entries: &[MockEntry]) -> Result<Self, CtError> {
        let mut log = Self {
            files: BTreeMap::new(),
            size: 0,
            origin: origin.to_owned(),
            leaves: Vec::new(),
        };
        log.extend(entries)?;
        Ok(log)
    }

    /// Appends entries (a multiple of 256) as a real log grows: existing data tiles and full
    /// hash tiles are unchanged, earlier partial hash tiles stay available, and a new
    /// checkpoint is signed.
    pub fn extend(&mut self, entries: &[MockEntry]) -> Result<(), CtError> {
        if entries.is_empty() || !entries.len().is_multiple_of(256) {
            return Err(CtError::Malformed(
                "mock log needs a multiple of 256 entries".into(),
            ));
        }
        let key = KeyPair::generate().map_err(|e| CtError::Malformed(e.to_string()))?;
        let first_tile = self.leaves.len() / 256;
        for (j, chunk) in entries.chunks(256).enumerate() {
            let t = first_tile + j;
            let mut data = Vec::new();
            for (i, e) in chunk.iter().enumerate() {
                let index = (t * 256 + i) as u64;
                let der = cert_der(&key, &e.names)?;
                let (leaf, hash) = if e.precert {
                    let tbs = tbs_of(&der)?;
                    encode_tile_leaf(
                        1_800_000_000_000 + index,
                        EntryKind::Precert,
                        &tbs,
                        index,
                        Some(&der),
                    )
                } else {
                    encode_tile_leaf(
                        1_800_000_000_000 + index,
                        EntryKind::X509,
                        &der,
                        index,
                        None,
                    )
                };
                data.extend_from_slice(&leaf);
                self.leaves.push(hash);
            }
            self.files.insert(data_tile_path(t as u64), data);
        }
        // Hash tiles at every level: level L holds hashes of complete subtrees of 256^L
        // leaves; the last tile of a level may be partial.
        let mut nodes: Vec<[u8; 32]> = self.leaves.clone();
        let mut level: u8 = 0;
        while !nodes.is_empty() {
            let mut next = Vec::new();
            for (n, chunk) in nodes.chunks(256).enumerate() {
                let width = (chunk.len() < 256).then(|| u8::try_from(chunk.len()).unwrap_or(255));
                self.files
                    .insert(hash_tile_path(level, n as u64, width), chunk.concat());
                if chunk.len() == 256 {
                    next.push(merkle::root(chunk));
                }
            }
            nodes = next;
            level += 1;
        }
        self.size = self.leaves.len() as u64;
        let root = merkle::root(&self.leaves);
        self.files.insert(
            "checkpoint".into(),
            sign_checkpoint(&self.origin, self.size, &root)?.into_bytes(),
        );
        Ok(())
    }

    /// The `ct-logs` evidence entry for this log served at `monitoring_url`.
    #[must_use]
    pub fn log_info(&self, log_id: &str, monitoring_url: &str) -> CtLogInfo {
        mock_info(log_id, monitoring_url, &self.origin)
    }

    /// Replaces a data tile's bytes (to simulate a log serving tampered data in tests).
    pub fn replace_file(&mut self, path: &str, bytes: Vec<u8>) {
        self.files.insert(path.to_owned(), bytes);
    }
}

impl TileSource for MockLog {
    fn data_tile(&self, n: u64) -> Result<Vec<u8>, CtError> {
        self.files
            .get(&data_tile_path(n))
            .cloned()
            .ok_or_else(|| CtError::NotFound(data_tile_path(n)))
    }

    fn hash_tile(&self, level: u8, n: u64, width: Option<u8>) -> Result<Vec<u8>, CtError> {
        let p = hash_tile_path(level, n, width);
        self.files.get(&p).cloned().ok_or(CtError::NotFound(p))
    }

    fn checkpoint(&self) -> Result<String, CtError> {
        self.files
            .get("checkpoint")
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .ok_or_else(|| CtError::NotFound("checkpoint".into()))
    }
}

/// Serves a mock log on a loopback address. Returns the monitoring prefix URL.
pub fn serve(log: Arc<MockLog>, addr: &str) -> Result<(String, JoinHandle<()>), CtError> {
    serve_shared(Arc::new(RwLock::new((*log).clone())), addr)
}

/// Serves a mock log that may grow while it is served ([`MockLog::extend`] under the lock).
pub fn serve_shared(
    log: Arc<RwLock<MockLog>>,
    addr: &str,
) -> Result<(String, JoinHandle<()>), CtError> {
    let server = tiny_http::Server::http(addr).map_err(|e| CtError::Http(e.to_string()))?;
    let local = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| CtError::Http("no ip address".into()))?;
    let url = format!("http://{local}/");
    let handle = std::thread::spawn(move || {
        for req in server.incoming_requests() {
            let path = req.url().trim_start_matches('/').to_owned();
            let body = log.read().ok().and_then(|l| l.files.get(&path).cloned());
            let resp = match body {
                Some(b) => tiny_http::Response::from_data(b),
                None => tiny_http::Response::from_data(Vec::new()).with_status_code(404),
            };
            let _ = req.respond(resp);
        }
    });
    Ok((url, handle))
}

/// A deterministic demo population: mostly ordinary names plus a few brand lookalikes.
#[must_use]
pub fn demo_entries(tiles: usize) -> Vec<MockEntry> {
    let lookalikes = [
        "examplebank-secure-login.example.net",
        "paypa1-account-verify.com",
        "xn--pypal-4ve.com",
        "login-microsoftonline-support.top",
        "examplebank-online.example.org",
        "secure-icloud-verify.info",
        "examp1ebank-secure-login.example.net",
    ];
    let mut out = Vec::with_capacity(tiles * 256);
    for i in 0..tiles * 256 {
        let names = if i % 97 == 13 {
            vec![lookalikes[(i / 97) % lookalikes.len()].to_owned()]
        } else if i % 211 == 5 {
            vec!["www.paypal.com".to_owned(), "paypal.com".to_owned()]
        } else {
            vec![
                format!("shop{i}.example-{}.org", i % 17),
                format!("www.shop{i}.example-{}.org", i % 17),
            ]
        };
        out.push(MockEntry {
            names,
            precert: i % 2 == 0,
        });
    }
    out
}

/// An in-memory classic RFC 6962 log, signing with the same public demonstration key.
///
/// Entries are real X.509 certificates, as in [`MockLog`]. Any number of entries is allowed.
/// `max_entries_per_call` caps what one `get-entries` call returns, as real logs do.
#[derive(Debug, Clone)]
pub struct MockRfc6962Log {
    pub origin: String,
    /// Most entries one `get-entries` call returns.
    pub max_entries_per_call: usize,
    leaf_inputs: Vec<Vec<u8>>,
    leaves: Vec<[u8; 32]>,
}

impl MockRfc6962Log {
    /// Builds a log with these entries.
    pub fn build(origin: &str, entries: &[MockEntry]) -> Result<Self, CtError> {
        let mut log = Self {
            origin: origin.to_owned(),
            max_entries_per_call: 64,
            leaf_inputs: Vec::new(),
            leaves: Vec::new(),
        };
        log.extend(entries)?;
        Ok(log)
    }

    /// Appends entries: the tree grows, and earlier tree heads stay consistent with it.
    pub fn extend(&mut self, entries: &[MockEntry]) -> Result<(), CtError> {
        let key = KeyPair::generate().map_err(|e| CtError::Malformed(e.to_string()))?;
        for e in entries {
            let index = self.leaf_inputs.len() as u64;
            let der = cert_der(&key, &e.names)?;
            let mut leaf = vec![0u8, 0u8];
            leaf.extend_from_slice(&(1_800_000_000_000 + index).to_be_bytes());
            let body = if e.precert {
                leaf.extend_from_slice(&1u16.to_be_bytes());
                leaf.extend_from_slice(&[0x11u8; 32]);
                tbs_of(&der)?
            } else {
                leaf.extend_from_slice(&0u16.to_be_bytes());
                der
            };
            leaf.extend_from_slice(&u32::try_from(body.len()).unwrap_or(0).to_be_bytes()[1..]);
            leaf.extend_from_slice(&body);
            leaf.extend_from_slice(&0u16.to_be_bytes());
            self.leaves.push(merkle::leaf_hash(&leaf));
            self.leaf_inputs.push(leaf);
        }
        Ok(())
    }

    /// Number of entries.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// The root of the first `n` entries.
    #[must_use]
    pub fn root_at(&self, n: u64) -> [u8; 32] {
        merkle::root(&self.leaves[..usize::try_from(n).unwrap_or(0).min(self.leaves.len())])
    }

    /// A signed tree head for the first `n` entries (`n` at most the size), dated now.
    pub fn sth_at(&self, n: u64) -> Result<crate::rfc6962::Sth, CtError> {
        if n > self.size() {
            return Err(CtError::NotFound("tree size".into()));
        }
        let (ts, root) = (mock_timestamp_ms(), self.root_at(n));
        Ok(crate::rfc6962::Sth {
            tree_size: n,
            timestamp: ts,
            root,
            signature: sign_tree_head(ts, n, &root)?,
        })
    }

    /// The `ct-logs` evidence entry for this log; `monitoring_url` is its API prefix.
    #[must_use]
    pub fn log_info(&self, log_id: &str, monitoring_url: &str) -> CtLogInfo {
        mock_info(log_id, monitoring_url, &self.origin)
    }

    /// Serves `leaf_input` as entry `index` while the tree keeps the hash of the original
    /// (a log serving tampered data).
    pub fn replace_leaf_input(&mut self, index: usize, leaf_input: Vec<u8>) {
        self.leaf_inputs[index] = leaf_input;
    }

    /// The `leaf_input` of entry `index`.
    #[must_use]
    pub fn leaf_input(&self, index: usize) -> &[u8] {
        &self.leaf_inputs[index]
    }
}

impl crate::rfc6962::LogApi for MockRfc6962Log {
    fn get_sth(&self) -> Result<crate::rfc6962::Sth, CtError> {
        self.sth_at(self.size())
    }

    fn get_entries(&self, start: u64, end: u64) -> Result<Vec<Vec<u8>>, CtError> {
        if start > end || start >= self.size() {
            return Err(CtError::NotFound("entries".into()));
        }
        let end = end.min(self.size() - 1);
        let n = usize::try_from(end - start + 1)
            .unwrap_or(usize::MAX)
            .min(self.max_entries_per_call);
        let s = usize::try_from(start).unwrap_or(usize::MAX);
        Ok(self.leaf_inputs[s..s + n].to_vec())
    }

    fn get_proof_by_hash(
        &self,
        leaf_hash: &[u8; 32],
        tree_size: u64,
    ) -> Result<(u64, Vec<[u8; 32]>), CtError> {
        let n = usize::try_from(tree_size).unwrap_or(usize::MAX);
        let leaves = self
            .leaves
            .get(..n)
            .ok_or_else(|| CtError::NotFound("tree size".into()))?;
        let i = leaves
            .iter()
            .position(|h| h == leaf_hash)
            .ok_or_else(|| CtError::NotFound("leaf hash".into()))?;
        Ok((i as u64, merkle::inclusion_proof(i, leaves)))
    }

    fn get_sth_consistency(&self, first: u64, second: u64) -> Result<Vec<[u8; 32]>, CtError> {
        let (m, n) = (
            usize::try_from(first).unwrap_or(usize::MAX),
            usize::try_from(second).unwrap_or(usize::MAX),
        );
        if m == 0 || m > n || n > self.leaves.len() {
            return Err(CtError::NotFound("tree sizes".into()));
        }
        Ok(merkle::consistency_proof(m, &self.leaves[..n]))
    }
}
