use std::fs;
use std::io::Write as _;
use std::path::Path;

use cybermesh_crypto::{Digest, canonical};
use serde::{Deserialize, Serialize};

use crate::anchor::{AnchorError, Checkpoint};
use crate::merkle::{self, Hash};

/// One log entry: a release sequence number and the digest of its signed payload. Nothing
/// else (no indicators, no organisation data) is logged or anchored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogEntry {
    pub sequence: u64,
    pub release_digest: Digest,
}

impl LogEntry {
    fn leaf(&self) -> Result<Hash, AnchorError> {
        let bytes = canonical::to_vec(self).map_err(|e| AnchorError::Log(e.to_string()))?;
        Ok(merkle::leaf_hash(&bytes))
    }
}

/// Inclusion proof for one release in a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionProof {
    pub log_id: String,
    pub index: u64,
    pub entry: LogEntry,
    pub checkpoint: Checkpoint,
    pub path: Vec<Digest>,
}

impl InclusionProof {
    /// Verifies offline that `entry` is leaf `index` of the tree committed by `checkpoint`.
    #[must_use]
    pub fn verify(&self) -> bool {
        let Ok(leaf) = self.entry.leaf() else {
            return false;
        };
        let path: Vec<Hash> = self.path.iter().map(|d| d.0).collect();
        self.log_id == self.checkpoint.log_id
            && merkle::verify_inclusion(
                self.index,
                self.checkpoint.size,
                &leaf,
                &path,
                &self.checkpoint.root.0,
            )
    }
}

/// Append-only Merkle log of releases, persisted as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransparencyLog {
    pub log_id: String,
    pub entries: Vec<LogEntry>,
}

impl TransparencyLog {
    #[must_use]
    pub fn new(log_id: &str) -> Self {
        Self {
            log_id: log_id.to_owned(),
            entries: Vec::new(),
        }
    }

    pub fn load_or_create(path: &Path, log_id: &str) -> Result<Self, AnchorError> {
        if !path.exists() {
            return Ok(Self::new(log_id));
        }
        let bytes = fs::read(path).map_err(|e| AnchorError::Log(e.to_string()))?;
        let log: Self =
            serde_json::from_slice(&bytes).map_err(|e| AnchorError::Log(e.to_string()))?;
        if log.log_id != log_id {
            return Err(AnchorError::Log(format!(
                "log at {} has id {}, expected {log_id}",
                path.display(),
                log.log_id
            )));
        }
        log.validate()?;
        Ok(log)
    }

    /// Writes atomically (exclusive temp file + fsync + rename).
    pub fn save(&self, path: &Path) -> Result<(), AnchorError> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| AnchorError::Log(e.to_string()))?;
        write_atomic(path, &bytes).map_err(|e| AnchorError::Log(e.to_string()))
    }

    fn validate(&self) -> Result<(), AnchorError> {
        for w in self.entries.windows(2) {
            if w[1].sequence <= w[0].sequence {
                return Err(AnchorError::Log(
                    "log sequences must strictly increase".into(),
                ));
            }
        }
        let digests: std::collections::BTreeSet<_> =
            self.entries.iter().map(|e| e.release_digest).collect();
        if digests.len() != self.entries.len() {
            return Err(AnchorError::Log("duplicate release digest in log".into()));
        }
        Ok(())
    }

    /// Appends a release. Sequences must strictly increase; the same release cannot be
    /// logged twice.
    pub fn append(&mut self, entry: LogEntry) -> Result<u64, AnchorError> {
        if let Some(last) = self.entries.last()
            && entry.sequence <= last.sequence
        {
            return Err(AnchorError::Log(format!(
                "sequence {} is not greater than last logged sequence {}",
                entry.sequence, last.sequence
            )));
        }
        if self
            .entries
            .iter()
            .any(|e| e.release_digest == entry.release_digest)
        {
            return Err(AnchorError::Log("release already logged".into()));
        }
        self.entries.push(entry);
        Ok(self.entries.len() as u64 - 1)
    }

    fn leaves(&self, size: usize) -> Result<Vec<Hash>, AnchorError> {
        self.entries[..size].iter().map(LogEntry::leaf).collect()
    }

    /// Checkpoint of the first `size` entries.
    pub fn checkpoint_at(&self, size: u64) -> Result<Checkpoint, AnchorError> {
        let n = usize::try_from(size).map_err(|_| AnchorError::Log("size".into()))?;
        if n > self.entries.len() {
            return Err(AnchorError::Log("checkpoint beyond log size".into()));
        }
        Ok(Checkpoint {
            log_id: self.log_id.clone(),
            size,
            root: Digest(merkle::root(&self.leaves(n)?)),
        })
    }

    pub fn checkpoint(&self) -> Result<Checkpoint, AnchorError> {
        self.checkpoint_at(self.entries.len() as u64)
    }

    #[must_use]
    pub fn find(&self, release_digest: &Digest) -> Option<u64> {
        self.entries
            .iter()
            .position(|e| &e.release_digest == release_digest)
            .map(|i| i as u64)
    }

    /// Inclusion proof for entry `index` against the checkpoint of size `size`.
    pub fn prove_inclusion(&self, index: u64, size: u64) -> Result<InclusionProof, AnchorError> {
        let n = usize::try_from(size).map_err(|_| AnchorError::Log("size".into()))?;
        let i = usize::try_from(index).map_err(|_| AnchorError::Log("index".into()))?;
        if i >= n || n > self.entries.len() {
            return Err(AnchorError::Log("index outside checkpoint".into()));
        }
        let leaves = self.leaves(n)?;
        Ok(InclusionProof {
            log_id: self.log_id.clone(),
            index,
            entry: self.entries[i].clone(),
            checkpoint: self.checkpoint_at(size)?,
            path: merkle::inclusion_proof(i, &leaves)
                .into_iter()
                .map(Digest)
                .collect(),
        })
    }

    /// Consistency proof that the log of size `old` is a prefix of the log of size `new`.
    pub fn prove_consistency(&self, old: u64, new: u64) -> Result<Vec<Digest>, AnchorError> {
        let n = usize::try_from(new).map_err(|_| AnchorError::Log("size".into()))?;
        let m = usize::try_from(old).map_err(|_| AnchorError::Log("size".into()))?;
        if m > n || n > self.entries.len() {
            return Err(AnchorError::Log("invalid sizes".into()));
        }
        Ok(merkle::consistency_proof(m, &self.leaves(n)?)
            .into_iter()
            .map(Digest)
            .collect())
    }
}

/// Atomic file replacement: write to a fresh, exclusively created temp file in the same
/// directory (never following an existing path), fsync, then rename over the target.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let nonce =
        cybermesh_crypto::random_bytes::<8>().map_err(|e| std::io::Error::other(e.to_string()))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", hex::encode(nonce)));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    let res = f.write_all(bytes).and_then(|()| f.sync_all());
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::rename(&tmp, path)
}

/// Verifies that checkpoint `old` is a prefix of checkpoint `new` (append-only history).
#[must_use]
pub fn verify_consistency(old: &Checkpoint, new: &Checkpoint, proof: &[Digest]) -> bool {
    let p: Vec<Hash> = proof.iter().map(|d| d.0).collect();
    old.log_id == new.log_id
        && merkle::verify_consistency(old.size, new.size, &old.root.0, &new.root.0, &p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(i: u64) -> LogEntry {
        LogEntry {
            sequence: i,
            release_digest: Digest::of(&i.to_be_bytes()),
        }
    }

    #[test]
    fn append_prove_and_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.json");
        let mut log = TransparencyLog::load_or_create(&path, "net").unwrap();
        for i in 1..=7 {
            log.append(entry(i)).unwrap();
        }
        assert!(log.append(entry(7)).is_err(), "non-increasing sequence");
        log.save(&path).unwrap();
        let log = TransparencyLog::load_or_create(&path, "net").unwrap();
        assert!(TransparencyLog::load_or_create(&path, "other").is_err());
        for i in 0..7 {
            let p = log.prove_inclusion(i, 7).unwrap();
            assert!(p.verify());
            let mut bad = p.clone();
            bad.entry.sequence += 100;
            assert!(!bad.verify());
        }
        let old = log.checkpoint_at(3).unwrap();
        let new = log.checkpoint().unwrap();
        let proof = log.prove_consistency(3, 7).unwrap();
        assert!(verify_consistency(&old, &new, &proof));
        assert!(!verify_consistency(&new, &old, &proof));
    }
}
