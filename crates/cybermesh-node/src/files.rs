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
