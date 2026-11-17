//! File helpers shared by runtimes and the CLI.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use cybermesh_crypto::Envelope;
use cybermesh_protocol::{GovernanceRoot, TrustManifest};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::NodeError;

/// Maximum size of configuration-like files read by nodes.
pub const MAX_FILE: u64 = 32 * 1024 * 1024;

pub fn read_bytes(path: &Path) -> Result<Vec<u8>, NodeError> {
    let meta = fs::metadata(path).map_err(|e| NodeError::Io(format!("{}: {e}", path.display())))?;
    if meta.len() > MAX_FILE {
        return Err(NodeError::Io(format!("{} is too large", path.display())));
    }
    fs::read(path).map_err(|e| NodeError::Io(format!("{}: {e}", path.display())))
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, NodeError> {
    serde_json::from_slice(&read_bytes(path)?)
        .map_err(|e| NodeError::Config(format!("{}: {e}", path.display())))
}

/// Writes JSON atomically (temp file + rename).
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), NodeError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| NodeError::Io(e.to_string()))?;
    write_atomic(path, &bytes)
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), NodeError> {
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        fs::create_dir_all(dir).map_err(|e| NodeError::Io(e.to_string()))?;
    }
    // Exclusive, unpredictable temp name in the same directory: never follows or reuses an
    // existing path; removed on failure.
    let nonce = cybermesh_crypto::random_bytes::<8>()?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = path.with_file_name(format!(".{name}.{suffix}.tmp"));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| NodeError::Io(format!("{}: {e}", tmp.display())))?;
    if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
        let _ = fs::remove_file(&tmp);
        return Err(NodeError::Io(e.to_string()));
    }
    fs::rename(&tmp, path).map_err(|e| NodeError::Io(e.to_string()))
}

/// Loads and verifies a signed trust manifest against a pinned governance root.
pub fn load_manifest(
    manifest_path: &Path,
    root_path: &Path,
    now: u64,
) -> Result<(TrustManifest, GovernanceRoot), NodeError> {
    let root: GovernanceRoot = read_json(root_path)?;
    let env = Envelope::parse(&read_bytes(manifest_path)?, MAX_FILE as usize)?;
    let m = TrustManifest::verify(&env, &root, now, 0)?;
    Ok((m, root))
}

/// The highest manifest a node has accepted, persisted so that a restart cannot roll the
/// node back to an older manifest (for example one from before a key was revoked).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestState {
    pub sequence: u64,
    pub digest: cybermesh_crypto::Digest,
}

fn manifest_digest(m: &TrustManifest) -> Result<cybermesh_crypto::Digest, NodeError> {
    Ok(cybermesh_crypto::Digest::of(
        &cybermesh_crypto::canonical::to_vec(m)?,
    ))
}

/// Records `m` as the highest accepted manifest.
pub fn persist_manifest_state(state_path: &Path, m: &TrustManifest) -> Result<(), NodeError> {
    write_json(
        state_path,
        &ManifestState {
            sequence: m.sequence,
            digest: manifest_digest(m)?,
        },
    )
}

/// Loads and verifies the manifest, refusing anything older than the persisted state and a
/// different manifest with the same sequence (governance equivocation). Persists the state
/// when the manifest is newer.
pub fn load_manifest_checked(
    manifest_path: &Path,
    root_path: &Path,
    state_path: &Path,
    now: u64,
) -> Result<(TrustManifest, GovernanceRoot), NodeError> {
    let state: Option<ManifestState> = if state_path.exists() {
        Some(read_json(state_path)?)
    } else {
        None
    };
    let root: GovernanceRoot = read_json(root_path)?;
    let env = Envelope::parse(&read_bytes(manifest_path)?, MAX_FILE as usize)?;
    let min = state
        .as_ref()
        .map_or(0, |s| s.sequence)
        .max(root.min_sequence);
    let m = TrustManifest::verify(&env, &root, now, min)?;
    let d = manifest_digest(&m)?;
    match &state {
        Some(s) if s.sequence == m.sequence && s.digest != d => {
            return Err(NodeError::Config(format!(
                "manifest sequence {} differs from the one previously accepted (equivocation); refusing",
                m.sequence
            )));
        }
        Some(s) if s.sequence == m.sequence => {}
        _ => persist_manifest_state(state_path, &m)?,
    }
    Ok((m, root))
}

/// Where a node reloads its trust manifest from.
#[derive(Debug, Clone)]
pub struct ManifestSource {
    pub manifest: std::path::PathBuf,
    pub governance_root: std::path::PathBuf,
}

/// Outcome of a manifest reload attempt.
#[derive(Debug)]
pub enum Reload {
    /// No newer manifest (unchanged or unreadable; the current one stays in force).
    Unchanged,
    /// A newer, valid manifest.
    Updated(TrustManifest),
    /// Same sequence, different content: governance equivocation. Keep the current one.
    Equivocation,
}

/// Re-reads and verifies the manifest; only a strictly newer sequence replaces `current`.
#[must_use]
pub fn reload_manifest(src: &ManifestSource, current: &TrustManifest, now: u64) -> Reload {
    let Ok((m, _)) = load_manifest(&src.manifest, &src.governance_root, now) else {
        return Reload::Unchanged;
    };
    if m.sequence > current.sequence {
        Reload::Updated(m)
    } else if m.sequence == current.sequence && &m != current {
        Reload::Equivocation
    } else {
        Reload::Unchanged
    }
}

#[cfg(test)]
mod tests {
    use cybermesh_protocol::testkit::TestNetwork;

    use super::*;

    #[test]
    fn restart_cannot_roll_back_to_an_older_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_800_000_000;
        let mut net = TestNetwork::new(&[("org-a", 1), ("org-b", 1), ("org-c", 1)], now);
        let (mp, rp, sp) = (
            dir.path().join("manifest.json"),
            dir.path().join("root.json"),
            dir.path().join("manifest-state.json"),
        );
        write_json(&rp, &net.root).unwrap();
        let v1 = net.manifest_envelope.to_vec().unwrap();
        // Node accepts sequence 2 (which revokes a worker) ...
        net.manifest.sequence = 2;
        net.manifest
            .revocations
            .push(cybermesh_protocol::Revocation {
                key_id: net.worker_id(0),
                revoked_at: now,
                reason: "compromised".into(),
            });
        net.resign_manifest();
        write_atomic(&mp, &net.manifest_envelope.to_vec().unwrap()).unwrap();
        let (m, _) = load_manifest_checked(&mp, &rp, &sp, now).unwrap();
        assert_eq!(m.sequence, 2);
        // ... then, after a restart, someone puts the older pre-revocation manifest back.
        write_atomic(&mp, &v1).unwrap();
        assert!(
            load_manifest_checked(&mp, &rp, &sp, now).is_err(),
            "rollback refused"
        );
        // A different manifest with the same sequence is refused too.
        net.manifest.operators[0].name = "changed".into();
        net.resign_manifest();
        write_atomic(&mp, &net.manifest_envelope.to_vec().unwrap()).unwrap();
        assert!(
            load_manifest_checked(&mp, &rp, &sp, now).is_err(),
            "equivocation refused"
        );
    }

    #[test]
    fn governance_root_floor_protects_a_fresh_node() {
        // No state file (first start, or the state directory was lost): the root's
        // `min_sequence` still refuses an old manifest.
        let dir = tempfile::tempdir().unwrap();
        let now = 1_800_000_000;
        let mut net = TestNetwork::new(&[("org-a", 1), ("org-b", 1), ("org-c", 1)], now);
        let (mp, rp, sp) = (
            dir.path().join("manifest.json"),
            dir.path().join("root.json"),
            dir.path().join("manifest-state.json"),
        );
        write_atomic(&mp, &net.manifest_envelope.to_vec().unwrap()).unwrap();
        net.root.min_sequence = net.manifest.sequence + 1;
        write_json(&rp, &net.root).unwrap();
        assert!(load_manifest_checked(&mp, &rp, &sp, now).is_err());
        assert!(!sp.exists());
        net.root.min_sequence = net.manifest.sequence;
        write_json(&rp, &net.root).unwrap();
        load_manifest_checked(&mp, &rp, &sp, now).unwrap();
        // A root without the field (older files) parses with floor 0.
        net.root.min_sequence = 0;
        let text =
            String::from_utf8(cybermesh_crypto::canonical::to_vec(&net.root).unwrap()).unwrap();
        assert!(!text.contains("min_sequence"));
    }

    #[test]
    fn reload_accepts_only_newer_manifests_and_flags_equivocation() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_800_000_000;
        let mut net = TestNetwork::new(&[("org-a", 1), ("org-b", 1), ("org-c", 1)], now);
        let src = ManifestSource {
            manifest: dir.path().join("manifest.json"),
            governance_root: dir.path().join("root.json"),
        };
        write_json(&src.governance_root, &net.root).unwrap();
        write_atomic(&src.manifest, &net.manifest_envelope.to_vec().unwrap()).unwrap();
        let current = net.manifest.clone();
        assert!(matches!(
            reload_manifest(&src, &current, now),
            Reload::Unchanged
        ));

        // Same sequence, different content: equivocation.
        net.manifest.operators[0].name = "renamed".into();
        net.resign_manifest();
        write_atomic(&src.manifest, &net.manifest_envelope.to_vec().unwrap()).unwrap();
        assert!(matches!(
            reload_manifest(&src, &current, now),
            Reload::Equivocation
        ));

        // Newer sequence revoking a worker.
        net.manifest.sequence = 2;
        let revoked = net.worker_id(0);
        net.manifest
            .revocations
            .push(cybermesh_protocol::Revocation {
                key_id: revoked.clone(),
                revoked_at: now,
                reason: "compromised".into(),
            });
        net.resign_manifest();
        write_atomic(&src.manifest, &net.manifest_envelope.to_vec().unwrap()).unwrap();
        match reload_manifest(&src, &current, now) {
            Reload::Updated(m) => assert!(m.member(&revoked).is_none()),
            other => panic!("expected update, got {other:?}"),
        }
        // Unreadable or unverifiable files never replace the current manifest.
        write_atomic(&src.manifest, b"garbage").unwrap();
        assert!(matches!(
            reload_manifest(&src, &current, now),
            Reload::Unchanged
        ));
    }
}
