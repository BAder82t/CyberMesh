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
