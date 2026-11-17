use std::path::Path;

use anyhow::{Context as _, Result, bail};
use cybermesh_crypto::Envelope;
use cybermesh_protocol::{Clock as _, GovernanceRoot, SystemClock, TrustManifest};

pub fn now() -> u64 {
    SystemClock.now()
}

pub fn read(path: &Path) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if meta.len() > 64 * 1024 * 1024 {
        bail!("{} is larger than 64 MiB", path.display());
    }
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read(path)?).with_context(|| format!("parsing {}", path.display()))
}

pub fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    cybermesh_node::files::write_atomic(path, bytes).map_err(|e| anyhow::anyhow!("{e}"))
}

pub fn write_json<T: serde::Serialize>(path: &Path, v: &T) -> Result<()> {
    let mut b = serde_json::to_vec_pretty(v)?;
    b.push(b'\n');
    write(path, &b)
}

/// Verifies a manifest against the governance root, honouring the root's `min_sequence`
/// floor (so an old manifest with a weaker `min_verifiers` cannot be substituted).
pub fn load_manifest(manifest: &Path, root: &Path, now: u64) -> Result<TrustManifest> {
    let root: GovernanceRoot = read_json(root)?;
    let env = Envelope::parse(&read(manifest)?, 32 * 1024 * 1024)?;
    Ok(TrustManifest::verify(&env, &root, now, root.min_sequence)?)
}
