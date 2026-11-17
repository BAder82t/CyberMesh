//! TOML configuration for workers and coordinators.

use std::path::{Path, PathBuf};

use cybermesh_verifier::Policy;
use serde::{Deserialize, Serialize};

use crate::NodeError;
use crate::governor::ResourcePolicy;

fn default_heartbeat() -> u64 {
    10
}

/// Worker configuration (`worker.toml`). Relative paths resolve against the config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerConfig {
    pub network_id: String,
    pub key: PathBuf,
    pub manifest: PathBuf,
    pub governance_root: PathBuf,
    pub evidence_dir: PathBuf,
    pub state_dir: PathBuf,
    /// Administrator control directory: create `PAUSE` to pause, `STOP` to stop.
    pub control_dir: PathBuf,
    pub listen: Vec<String>,
    pub bootstrap: Vec<String>,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_secs: u64,
    #[serde(default)]
    pub resources: ResourcePolicy,
    /// Adversarial behaviour for demonstrations (requires the `adversary-sim` feature).
    #[serde(default)]
    pub adversary: Option<String>,
}

/// Coordinator configuration (`coordinator.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorConfig {
    pub network_id: String,
    pub issuer_key: PathBuf,
    pub verifier_key: PathBuf,
    pub manifest: PathBuf,
    pub governance_root: PathBuf,
    pub evidence_dir: PathBuf,
    pub state_dir: PathBuf,
    pub listen: Vec<String>,
    #[serde(default)]
    pub bootstrap: Vec<String>,
    /// Newline-separated domains (or URLs) to assess.
    pub domains_file: PathBuf,
    #[serde(default = "d_batch")]
    pub batch_size: usize,
    /// Workers (of distinct operators) per task.
    #[serde(default = "d_three")]
    pub replication: usize,
    #[serde(default = "d_ttl")]
    pub task_ttl_secs: u64,
    #[serde(default = "d_result_timeout")]
    pub result_timeout_secs: u64,
    #[serde(default = "d_three")]
    pub max_attempts: usize,
    #[serde(default = "d_liveness")]
    pub liveness_secs: u64,
    #[serde(default = "d_inflight")]
    pub max_inflight: usize,
    /// Exit after every batch has been settled.
    #[serde(default)]
    pub exit_when_done: bool,
    #[serde(default)]
    pub policy: Policy,
    /// Certificate Transparency monitoring (optional).
    #[serde(default)]
    pub ct: Option<CtScanConfig>,
}

/// `[ct]` section of `coordinator.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CtScanConfig {
    /// A log id from the pinned `ct-logs` evidence.
    pub log_id: String,
    /// First full data tile; omit to scan the most recent `tile_count` full tiles.
    #[serde(default)]
    pub first_tile: Option<u64>,
    pub tile_count: u64,
    #[serde(default = "d_ct_tiles")]
    pub tiles_per_task: u32,
    /// Workers of distinct operators per shard (CT findings are advisory: 2 is the default).
    #[serde(default = "d_two")]
    pub replication: usize,
    #[serde(default)]
    pub policy: cybermesh_verifier::ct::CtPolicy,
}

fn d_ct_tiles() -> u32 {
    8
}
fn d_two() -> usize {
    2
}

fn d_batch() -> usize {
    16
}
fn d_three() -> usize {
    3
}
fn d_ttl() -> u64 {
    300
}
fn d_result_timeout() -> u64 {
    20
}
fn d_liveness() -> u64 {
    45
}
fn d_inflight() -> usize {
    4
}

fn resolve(base: &Path, p: &mut PathBuf) {
    if p.is_relative() {
        *p = base.join(&*p);
    }
}

impl WorkerConfig {
    pub fn load(path: &Path) -> Result<Self, NodeError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| NodeError::Config(format!("{}: {e}", path.display())))?;
        let mut c: Self = toml::from_str(&text)
            .map_err(|e| NodeError::Config(format!("{}: {e}", path.display())))?;
        let base = path.parent().unwrap_or(Path::new("."));
        for p in [
            &mut c.key,
            &mut c.manifest,
            &mut c.governance_root,
            &mut c.evidence_dir,
            &mut c.state_dir,
            &mut c.control_dir,
        ] {
            resolve(base, p);
        }
        c.resources.validate()?;
        Ok(c)
    }
}

impl CoordinatorConfig {
    pub fn load(path: &Path) -> Result<Self, NodeError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| NodeError::Config(format!("{}: {e}", path.display())))?;
        let mut c: Self = toml::from_str(&text)
            .map_err(|e| NodeError::Config(format!("{}: {e}", path.display())))?;
        let base = path.parent().unwrap_or(Path::new("."));
        for p in [
            &mut c.issuer_key,
            &mut c.verifier_key,
            &mut c.manifest,
            &mut c.governance_root,
            &mut c.evidence_dir,
            &mut c.state_dir,
            &mut c.domains_file,
        ] {
            resolve(base, p);
        }
        if c.replication == 0 || c.batch_size == 0 || c.batch_size > 64 {
            return Err(NodeError::Config(
                "replication must be >= 1 and batch_size 1..=64".into(),
            ));
        }
        Ok(c)
    }
}
