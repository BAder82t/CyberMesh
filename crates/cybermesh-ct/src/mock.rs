//! A synthetic static CT log for tests and demonstrations.
//!
//! Entries are real X.509 certificates (and precertificate TBSCertificates) generated with
//! `rcgen`, serialised exactly as the static CT API specifies: data tiles, level-0 and
//! level-1 hash tiles, and a checkpoint (unsigned). Only full tiles are produced.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread::JoinHandle;

use base64::Engine as _;
use cybermesh_anchor::merkle;
use rcgen::{CertificateParams, DnType, KeyPair};
use x509_parser::prelude::*;

use crate::tile::{EntryKind, data_tile_path, encode_tile_leaf, hash_tile_path};
use crate::{CtError, TileSource};

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
        if entries.is_empty() || !entries.len().is_multiple_of(256) {
            return Err(CtError::Malformed(
                "mock log needs a multiple of 256 entries".into(),
            ));
        }
        let key = KeyPair::generate().map_err(|e| CtError::Malformed(e.to_string()))?;
        let mut files = BTreeMap::new();
        let mut all_leaves = Vec::with_capacity(entries.len());
        let mut tile_roots = Vec::new();
        for (t, chunk) in entries.chunks(256).enumerate() {
            let mut data = Vec::new();
            let mut leaves = Vec::with_capacity(256);
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
                leaves.push(hash);
            }
            files.insert(data_tile_path(t as u64), data);
            files.insert(hash_tile_path(0, t as u64, None), leaves.concat());
            tile_roots.push(merkle::root(&leaves));
            all_leaves.extend(leaves);
        }
        // Level-1 tiles: 256 tile roots each; the last may be partial.
        for (n, chunk) in tile_roots.chunks(256).enumerate() {
            let width = if chunk.len() == 256 {
                None
            } else {
                Some(u8::try_from(chunk.len()).unwrap_or(255))
            };
            files.insert(hash_tile_path(1, n as u64, width), chunk.concat());
        }
        let size = entries.len() as u64;
        let root = merkle::root(&all_leaves);
        let checkpoint = format!(
            "{origin}\n{size}\n{}\n\n",
            base64::engine::general_purpose::STANDARD.encode(root)
        );
        files.insert("checkpoint".into(), checkpoint.into_bytes());
        Ok(Self { files, size })
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

    fn level1_tile(&self, n: u64, width: Option<u8>) -> Result<Vec<u8>, CtError> {
        let p = hash_tile_path(1, n, width);
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
    let server = tiny_http::Server::http(addr).map_err(|e| CtError::Http(e.to_string()))?;
    let local = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| CtError::Http("no ip address".into()))?;
    let url = format!("http://{local}/");
    let handle = std::thread::spawn(move || {
        for req in server.incoming_requests() {
            let path = req.url().trim_start_matches('/').to_owned();
            let resp = match log.files.get(&path) {
                Some(b) => tiny_http::Response::from_data(b.clone()),
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
