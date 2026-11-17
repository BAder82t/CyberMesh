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
    /// Wait for this many live workers before issuing the first task (0: do not wait).
    #[serde(default)]
    pub start_after_workers: usize,
    #[serde(default)]
    pub policy: Policy,
    /// Certificate Transparency monitoring (optional).
    #[serde(default)]
    pub ct: Option<CtScanConfig>,
}

/// Independent verifier configuration (`verifier.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierConfig {
    pub network_id: String,
    /// This organisation's verifier key (role `verifier` in the trust manifest).
    pub key: PathBuf,
    pub manifest: PathBuf,
    pub governance_root: PathBuf,
    pub evidence_dir: PathBuf,
    pub state_dir: PathBuf,
    pub listen: Vec<String>,
    /// Peers to dial: the coordinator and, ideally, workers directly, so no single relay can
    /// withhold results from this verifier.
    #[serde(default)]
    pub bootstrap: Vec<String>,
    #[serde(default = "d_result_timeout")]
    pub result_timeout_secs: u64,
    /// Exit after this many idle seconds once work was done (demos); omit to run until stopped.
    #[serde(default)]
    pub idle_exit_secs: Option<u64>,
    #[serde(default)]
    pub policy: Policy,
    /// CT verification policy (spot checks with this verifier's own secret seed).
    #[serde(default)]
    pub ct_policy: cybermesh_verifier::ct::CtPolicy,
}

impl VerifierConfig {
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
        ] {
            resolve(base, p);
        }
        if c.result_timeout_secs == 0 {
            return Err(NodeError::Config("result_timeout_secs must be >= 1".into()));
        }
        Ok(c)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_ct_policy_table_uses_defaults() {
        let c: CtScanConfig =
            toml::from_str("log_id = \"x\"\ntile_count = 8\n[policy]\npublish_warnings = true\n")
                .unwrap();
        assert!(c.policy.publish_warnings);
        assert_eq!(c.policy.min_operators, 2);
        assert_eq!(c.tiles_per_task, 8);
        assert!(
            toml::from_str::<CtScanConfig>("log_id = \"x\"\ntile_count = 8\n[policy]\nbogus = 1\n")
                .is_err()
        );
    }
}
