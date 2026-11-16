//! Pinned evidence snapshots.
//!
//! An evidence bundle is a directory with `bundle.json` listing source files and their
//! SHA-256 digests. Loading verifies every digest, so a worker can only run a task against
//! byte-identical evidence to what the task pins. Evidence is data only: domain lists and a
//! brand table. Nothing in a bundle is executed.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::Path;

use cybermesh_crypto::Digest;
use cybermesh_protocol::EvidencePins;
use serde::{Deserialize, Serialize};

use crate::normalize::normalize_domain;

/// Upper bound on any single evidence file (bounds memory on load).
pub const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
/// Upper bound on all evidence files of one bundle together.
pub const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;
/// Upper bound on the number of sources in one bundle.
pub const MAX_SOURCES: usize = 16;

/// The pin for one source binds its id, kind and file digest, so re-labelling a blocklist as
/// a popularity list (or vice versa) changes the pin.
#[must_use]
pub fn source_pin(id: &str, kind: SourceKind, file_digest: &Digest) -> Digest {
    let kind = match kind {
        SourceKind::Blocklist => "blocklist",
        SourceKind::Popularity => "popularity",
        SourceKind::Brands => "brands",
        SourceKind::HostingPlatforms => "hosting-platforms",
    };
    Digest::tagged(
        "cybermesh/evidence-source/v1",
        &[id.as_bytes(), kind.as_bytes(), file_digest.as_bytes()],
    )
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid bundle manifest: {0}")]
    Manifest(String),
    #[error("digest mismatch for {id}: manifest {expected}, file {actual}")]
    DigestMismatch {
        id: String,
        expected: String,
        actual: String,
    },
    #[error("source {0} exceeds the size limit")]
    TooLarge(String),
    #[error("invalid brands file: {0}")]
    Brands(String),
}

/// Kind of evidence source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    /// Reference list of malicious hosts or domains (one per line, `#` comments).
    Blocklist,
    /// Ranked list of popular registrable domains (one per line).
    Popularity,
    /// JSON table of protected brands.
    Brands,
    /// Registrable domains whose subdomains are independently controlled customer sites
    /// (user-content hosting not covered by the Public Suffix List's private section).
    HostingPlatforms,
}

/// Metadata for one source in `bundle.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMeta {
    pub id: String,
    pub kind: SourceKind,
    pub file: String,
    pub sha256: Digest,
    pub version: String,
    pub license: String,
    pub origin: String,
}

/// `bundle.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub v: u16,
    pub sources: Vec<SourceMeta>,
}

/// A protected brand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Brand {
    pub name: String,
    /// Lowercase ASCII tokens that identify the brand in a hostname.
    pub tokens: Vec<String>,
    /// Registrable domains legitimately operated by the brand.
    pub legitimate: Vec<String>,
}

/// Loaded, verified evidence.
#[derive(Debug, Clone, Default)]
pub struct EvidenceBundle {
    /// `(source id, normalised hosts)`, sorted by source id.
    pub blocklists: Vec<(String, HashSet<String>)>,
    pub popular: HashSet<String>,
    pub hosting_platforms: HashSet<String>,
    pub brands: Vec<Brand>,
    pub pins: EvidencePins,
    pub sources: Vec<SourceMeta>,
    /// Lines skipped while parsing lists (IP literals, malformed entries).
    pub skipped_lines: usize,
}

/// Reads a regular, non-symlink file with a hard size cap. The cap is enforced on the bytes
/// actually read (not on metadata), so special files and races cannot bypass it.
fn read_limited(path: &Path, id: &str) -> Result<Vec<u8>, EvidenceError> {
    use std::io::Read as _;
    let io = |e: std::io::Error| EvidenceError::Io {
        path: path.display().to_string(),
        source: e,
    };
    let meta = fs::symlink_metadata(path).map_err(io)?;
    if !meta.file_type().is_file() {
        return Err(EvidenceError::Manifest(format!(
            "{} is not a regular file (symlinks and special files are refused)",
            path.display()
        )));
    }
    let f = fs::File::open(path).map_err(io)?;
    let mut buf = Vec::new();
    f.take(MAX_SOURCE_BYTES + 1).read_to_end(&mut buf).map_err(io)?;
    if buf.len() as u64 > MAX_SOURCE_BYTES {
        return Err(EvidenceError::TooLarge(id.to_owned()));
    }
    Ok(buf)
}

/// Parses a newline-separated domain list. Accepts bare domains or URLs, ignores `#`
/// comments and anything after the first whitespace or comma on a line.
#[must_use]
pub fn parse_domain_list(bytes: &[u8]) -> (HashSet<String>, usize) {
    let text = String::from_utf8_lossy(bytes);
    let mut out = HashSet::new();
    let mut skipped = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let token = line.split([' ', '\t', ',']).next().unwrap_or("");
        match normalize_domain(token) {
            Ok(d) => {
                out.insert(d);
            }
            Err(_) => skipped += 1,
        }
    }
    (out, skipped)
}

impl EvidenceBundle {
    /// Loads `dir/bundle.json` and every referenced file, verifying digests.
    pub fn load(dir: &Path) -> Result<Self, EvidenceError> {
        let mpath = dir.join("bundle.json");
        let mbytes = read_limited(&mpath, "bundle.json")?;
        let manifest: BundleManifest = serde_json::from_slice(&mbytes)
            .map_err(|e| EvidenceError::Manifest(e.to_string()))?;
        if manifest.sources.len() > MAX_SOURCES {
            return Err(EvidenceError::Manifest("too many sources".into()));
        }
        let mut files = BTreeMap::new();
        let mut total: u64 = 0;
        for s in &manifest.sources {
            let plain = !s.file.is_empty()
                && !s.file.starts_with('.')
                && s.file
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
            if !plain {
                return Err(EvidenceError::Manifest(format!(
                    "source file name {} must be a plain file name in the bundle directory",
                    s.file
                )));
            }
            let bytes = read_limited(&dir.join(&s.file), &s.id)?;
            total += bytes.len() as u64;
            if total > MAX_BUNDLE_BYTES {
                return Err(EvidenceError::TooLarge("bundle".into()));
            }
            files.insert(s.id.clone(), bytes);
        }
        Self::from_manifest_and_files(manifest, &files)
    }

    /// Builds a bundle from in-memory files (used by `load` and by tests).
    pub fn from_manifest_and_files(
        manifest: BundleManifest,
        files: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, EvidenceError> {
        if manifest.v != 1 {
            return Err(EvidenceError::Manifest("unsupported bundle version".into()));
        }
        let mut ids = BTreeSet::new();
        let mut bundle = EvidenceBundle::default();
        let mut sources = manifest.sources.clone();
        sources.sort_by(|a, b| a.id.cmp(&b.id));
        for s in &sources {
            if !ids.insert(s.id.clone()) {
                return Err(EvidenceError::Manifest(format!("duplicate source id {}", s.id)));
            }
            let bytes = files
                .get(&s.id)
                .ok_or_else(|| EvidenceError::Manifest(format!("missing file for {}", s.id)))?;
            let actual = Digest::of(bytes);
            if actual != s.sha256 {
                return Err(EvidenceError::DigestMismatch {
                    id: s.id.clone(),
                    expected: s.sha256.to_string(),
                    actual: actual.to_string(),
                });
            }
            match s.kind {
                SourceKind::Blocklist => {
                    let (set, skipped) = parse_domain_list(bytes);
                    bundle.skipped_lines += skipped;
                    bundle.blocklists.push((s.id.clone(), set));
                }
                SourceKind::Popularity => {
                    let (set, skipped) = parse_domain_list(bytes);
                    bundle.skipped_lines += skipped;
                    bundle.popular.extend(set);
                }
                SourceKind::HostingPlatforms => {
                    let (set, skipped) = parse_domain_list(bytes);
                    bundle.skipped_lines += skipped;
                    bundle.hosting_platforms.extend(set);
                }
                SourceKind::Brands => {
                    let mut brands: Vec<Brand> = serde_json::from_slice(bytes)
                        .map_err(|e| EvidenceError::Brands(e.to_string()))?;
                    for b in &mut brands {
                        if b.tokens.iter().any(|t| {
                            t.len() < 3
                                || !t.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                        }) {
                            return Err(EvidenceError::Brands(format!(
                                "brand {} has an invalid token (need >=3 chars of [a-z0-9])",
                                b.name
                            )));
                        }
                        b.tokens.sort();
                        b.legitimate.sort();
                    }
                    brands.sort_by(|a, b| a.name.cmp(&b.name));
                    bundle.brands.extend(brands);
                }
            }
            bundle.pins.insert(s.id.clone(), source_pin(&s.id, s.kind, &s.sha256));
        }
        bundle.sources = sources;
        Ok(bundle)
    }

    /// Ids of blocklists listing `host` or any parent domain down to the registrable domain.
    #[must_use]
    pub fn blocklist_hits(&self, host: &str, registrable: &str) -> Vec<String> {
        let mut hits = Vec::new();
        for (id, set) in &self.blocklists {
            let mut candidate = host;
            loop {
                if set.contains(candidate) {
                    hits.push(id.clone());
                    break;
                }
                if candidate == registrable {
                    break;
                }
                match candidate.find('.') {
                    Some(i) => candidate = &candidate[i + 1..],
                    None => break,
                }
                if candidate.len() < registrable.len() {
                    break;
                }
            }
        }
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: &str, kind: SourceKind, bytes: &[u8]) -> SourceMeta {
        SourceMeta {
            id: id.into(),
            kind,
            file: format!("{id}.txt"),
            sha256: Digest::of(bytes),
            version: "test".into(),
            license: "CC0-1.0".into(),
            origin: "test".into(),
        }
    }

    #[test]
    fn verifies_digests_and_parses_lists() {
        let feed = b"# comment\nevil.example.com\nhttp://bad.test/path\n10.0.0.1\n".to_vec();
        let pop = b"google.com\nexample.org\n".to_vec();
        let manifest = BundleManifest {
            v: 1,
            sources: vec![
                meta("feed", SourceKind::Blocklist, &feed),
                meta("popularity", SourceKind::Popularity, &pop),
            ],
        };
        let files = BTreeMap::from([("feed".to_owned(), feed.clone()), ("popularity".to_owned(), pop)]);
        let b = EvidenceBundle::from_manifest_and_files(manifest.clone(), &files).unwrap();
        assert_eq!(b.skipped_lines, 1);
        assert!(b.blocklists[0].1.contains("bad.test"));
        assert_eq!(b.blocklist_hits("a.evil.example.com", "example.com"), vec!["feed"]);
        assert!(b.blocklist_hits("example.com", "example.com").is_empty());
        assert_eq!(b.pins.len(), 2);

        // Poisoned snapshot: digest no longer matches.
        let mut tampered = files;
        tampered.insert("feed".into(), b"google.com\n".to_vec());
        assert!(matches!(
            EvidenceBundle::from_manifest_and_files(manifest, &tampered),
            Err(EvidenceError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn relabelling_a_source_changes_its_pin() {
        let d = Digest::of(b"same bytes");
        assert_ne!(
            source_pin("x", SourceKind::Blocklist, &d),
            source_pin("x", SourceKind::Popularity, &d)
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_sources() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/dev/zero", dir.path().join("feed.txt")).unwrap();
        let m = r#"{"v":1,"sources":[{"id":"x","kind":"blocklist","file":"feed.txt","sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","version":"1","license":"x","origin":"x"}]}"#;
        fs::write(dir.path().join("bundle.json"), m).unwrap();
        assert!(matches!(EvidenceBundle::load(dir.path()), Err(EvidenceError::Manifest(_))));
    }

    #[test]
    fn rejects_path_traversal_in_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let m = r#"{"v":1,"sources":[{"id":"x","kind":"blocklist","file":"../etc/passwd","sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","version":"1","license":"x","origin":"x"}]}"#;
        fs::write(dir.path().join("bundle.json"), m).unwrap();
        assert!(matches!(
            EvidenceBundle::load(dir.path()),
            Err(EvidenceError::Manifest(_))
        ));
    }
}
