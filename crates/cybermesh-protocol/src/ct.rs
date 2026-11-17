//! Certificate Transparency shard-scan messages (`ct-shard-scan`).
//!
//! A task names a pinned CT log and a range of *full* data tiles (256 entries each). Workers
//! fetch those tiles from the log's static monitoring endpoint (never from a URL supplied by
//! the task), extract the DNS names of every certificate and precertificate, run the
//! deterministic domain engine on them and report, per tile, the Merkle root of the leaf
//! hashes and the names that look like impersonation of a protected brand.
//!
//! The per-tile root is the same value the log publishes in its level-1 hash tile, so a
//! verifier can check that a worker processed exactly the log's entries for 32 bytes per
//! tile. Matches are checked by cross-operator agreement and by verifier re-scans of
//! sampled tiles.

use std::collections::BTreeSet;

use cybermesh_crypto::{Digest, KeyId, canonical};
use serde::{Deserialize, Serialize};

use crate::domain::is_normalized_domain;
use crate::manifest::Role;
use crate::messages::{EngineSpec, EvidencePins, FindingCode, OperatorId, ResourceUsage, Verdict};
use crate::validate::{Limits, Verified};
use crate::{PROTOCOL_VERSION, ProtocolError, TrustManifest};

/// Payload type of CT shard-scan tasks.
pub const CT_TASK: &str = "application/vnd.cybermesh.ct-task+json;v=1";
/// Payload type of CT shard-scan results.
pub const CT_RESULT: &str = "application/vnd.cybermesh.ct-result+json;v=1";
/// Entries per full data tile (static CT API).
pub const TILE_WIDTH: u64 = 256;
/// Upper bound on tiles per task.
pub const MAX_TILES_PER_TASK: u32 = 64;
/// Upper bound on matches reported per tile (deterministic truncation beyond this).
pub const MAX_MATCHES_PER_TILE: usize = 256;

/// A signed CT shard-scan task.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CtScanTask {
    pub v: u16,
    pub network_id: String,
    pub task_id: String,
    pub attempt: u32,
    pub issuer: KeyId,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub engine: EngineSpec,
    pub evidence: EvidencePins,
    /// Identifier of a CT log listed in the pinned `ct-logs` evidence.
    pub log_id: String,
    /// First full data tile to scan.
    pub first_tile: u64,
    /// Number of consecutive full data tiles.
    pub tile_count: u32,
    pub assignees: Vec<KeyId>,
    pub min_operators: u8,
}

#[derive(Serialize)]
struct CtInput<'a> {
    engine: &'a EngineSpec,
    evidence: &'a EvidencePins,
    log_id: &'a str,
    first_tile: u64,
    tile_count: u32,
}

impl CtScanTask {
    /// Digest of everything that determines the output.
    pub fn input_digest(&self) -> Result<Digest, ProtocolError> {
        let c = CtInput {
            engine: &self.engine,
            evidence: &self.evidence,
            log_id: &self.log_id,
            first_tile: self.first_tile,
            tile_count: self.tile_count,
        };
        Ok(Digest::tagged(
            "cybermesh/ct-task-input/v1",
            &[&canonical::to_vec(&c)?],
        ))
    }

    /// The data tiles covered, in order.
    pub fn tiles(&self) -> impl Iterator<Item = u64> + '_ {
        (0..u64::from(self.tile_count)).map(move |i| self.first_tile + i)
    }
}

/// A certificate name that looks like impersonation of a protected brand.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CtMatch {
    /// Global index of the log entry.
    pub index: u64,
    /// Normalised name from the certificate (wildcard prefix removed).
    pub name: String,
    pub risk_score_bp: u16,
    pub verdict: Verdict,
    /// Finding codes from the deterministic engine, sorted.
    pub codes: Vec<FindingCode>,
}

/// Result for one full data tile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TileScanResult {
    pub tile_index: u64,
    /// Always 256 for full tiles.
    pub leaf_count: u16,
    /// RFC 6962 Merkle tree hash of the tile's leaf hashes (equals the log's level-1 hash).
    pub root: Digest,
    /// Entries whose certificate could not be parsed (counted, still committed in `root`).
    pub unparsed: u16,
    /// Sorted by (index, name); at most [`MAX_MATCHES_PER_TILE`].
    pub matches: Vec<CtMatch>,
    /// True when more than [`MAX_MATCHES_PER_TILE`] names matched.
    pub truncated: bool,
}

/// A worker's signed CT scan result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CtScanResult {
    pub v: u16,
    pub network_id: String,
    pub task_id: String,
    pub attempt: u32,
    pub task_digest: Digest,
    pub input_digest: Digest,
    pub worker: KeyId,
    pub operator: OperatorId,
    pub engine: EngineSpec,
    pub evidence: EvidencePins,
    pub log_id: String,
    /// One per task tile, in tile order.
    pub tiles: Vec<TileScanResult>,
    pub completed_at: u64,
    pub nonce: String,
    pub usage: ResourceUsage,
    /// Bytes downloaded from the log for this task (informational).
    pub fetched_bytes: u64,
}

impl CtScanResult {
    /// Digest of the deterministic part (the tiles).
    pub fn tiles_digest(&self) -> Result<Digest, ProtocolError> {
        Ok(Digest::tagged(
            "cybermesh/ct-tiles/v1",
            &[&canonical::to_vec(&self.tiles)?],
        ))
    }
}

/// Digest of a single tile result (used to compare tiles across workers).
pub fn tile_digest(t: &TileScanResult) -> Result<Digest, ProtocolError> {
    Ok(Digest::tagged(
        "cybermesh/ct-tile/v1",
        &[&canonical::to_vec(t)?],
    ))
}

fn is_hex_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Log ids: 1-64 chars of `[a-z0-9.-]`.
#[must_use]
pub fn is_valid_log_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

fn check_header(v: u16, network: &str, manifest: &TrustManifest) -> Result<(), ProtocolError> {
    if v != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(v));
    }
    if network != manifest.network_id {
        return Err(ProtocolError::WrongNetwork {
            expected: manifest.network_id.clone(),
            actual: network.to_owned(),
        });
    }
    Ok(())
}

/// Verifies a CT shard-scan task.
pub fn verify_ct_task(
    bytes: &[u8],
    manifest: &TrustManifest,
    now: u64,
    limits: &Limits,
) -> Result<Verified<CtScanTask>, ProtocolError> {
    let v: Verified<CtScanTask> =
        crate::validate::verify_signed(bytes, CT_TASK, Role::Issuer, manifest, limits)?;
    let t = &v.message;
    check_header(t.v, &t.network_id, manifest)?;
    if v.signer != t.issuer {
        return Err(ProtocolError::SignerMismatch);
    }
    if !is_hex_id(&t.task_id) || !is_hex_id(&t.nonce) {
        return Err(ProtocolError::Invalid(
            "task_id and nonce must be 32 hex chars".into(),
        ));
    }
    if t.issued_at > now.saturating_add(limits.max_clock_skew_secs) {
        return Err(ProtocolError::NotYetValid);
    }
    if t.expires_at <= now {
        return Err(ProtocolError::Expired);
    }
    if t.expires_at <= t.issued_at || t.expires_at - t.issued_at > limits.max_task_ttl_secs {
        return Err(ProtocolError::TtlTooLong);
    }
    if !is_valid_log_id(&t.log_id) {
        return Err(ProtocolError::Invalid("invalid log id".into()));
    }
    if t.tile_count == 0 || t.tile_count > MAX_TILES_PER_TASK {
        return Err(ProtocolError::Invalid("tile count out of range".into()));
    }
    if t.first_tile.checked_add(u64::from(t.tile_count)).is_none() {
        return Err(ProtocolError::Invalid("tile range overflows".into()));
    }
    crate::validate::check_engine_and_evidence(&t.engine, &t.evidence, limits)?;
    if t.assignees.is_empty() || t.assignees.len() > limits.max_assignees {
        return Err(ProtocolError::Invalid("assignee count out of range".into()));
    }
    let mut seen = BTreeSet::new();
    let mut operators = BTreeSet::new();
    for a in &t.assignees {
        if !seen.insert(a) {
            return Err(ProtocolError::Invalid("duplicate assignee".into()));
        }
        if manifest.key_with_role(a, Role::Worker).is_none() {
            return Err(ProtocolError::Invalid(
                "assignee is not an enrolled worker".into(),
            ));
        }
        if let Some(op) = manifest.operator_of(a) {
            operators.insert(op.clone());
        }
    }
    if t.min_operators == 0 || usize::from(t.min_operators) > operators.len() {
        return Err(ProtocolError::Invalid(
            "min_operators must be between 1 and the number of distinct assigned operators".into(),
        ));
    }
    Ok(v)
}

/// Verifies a CT shard-scan result (binding to the task is done by the verifier).
pub fn verify_ct_result(
    bytes: &[u8],
    manifest: &TrustManifest,
    now: u64,
    limits: &Limits,
) -> Result<Verified<CtScanResult>, ProtocolError> {
    let v: Verified<CtScanResult> =
        crate::validate::verify_signed(bytes, CT_RESULT, Role::Worker, manifest, limits)?;
    let r = &v.message;
    check_header(r.v, &r.network_id, manifest)?;
    if v.signer != r.worker || manifest.operator_of(&r.worker) != Some(&r.operator) {
        return Err(ProtocolError::SignerMismatch);
    }
    if !is_hex_id(&r.task_id) || !is_hex_id(&r.nonce) {
        return Err(ProtocolError::Invalid(
            "task_id and nonce must be 32 hex chars".into(),
        ));
    }
    if r.completed_at > now.saturating_add(limits.max_clock_skew_secs) {
        return Err(ProtocolError::NotYetValid);
    }
    if !is_valid_log_id(&r.log_id) {
        return Err(ProtocolError::Invalid("invalid log id".into()));
    }
    crate::validate::check_engine_and_evidence(&r.engine, &r.evidence, limits)?;
    if r.tiles.is_empty() || r.tiles.len() > MAX_TILES_PER_TASK as usize {
        return Err(ProtocolError::Invalid("tile count out of range".into()));
    }
    let mut prev_tile: Option<u64> = None;
    for t in &r.tiles {
        if prev_tile.is_some_and(|p| t.tile_index != p + 1) {
            return Err(ProtocolError::Invalid("tiles must be consecutive".into()));
        }
        prev_tile = Some(t.tile_index);
        if u64::from(t.leaf_count) != TILE_WIDTH || u64::from(t.unparsed) > TILE_WIDTH {
            return Err(ProtocolError::Invalid("only full tiles are scanned".into()));
        }
        if t.matches.len() > MAX_MATCHES_PER_TILE {
            return Err(ProtocolError::Invalid("too many matches".into()));
        }
        let lo = t.tile_index.saturating_mul(TILE_WIDTH);
        let hi = lo.saturating_add(TILE_WIDTH);
        let mut prev: Option<(&u64, &str)> = None;
        for m in &t.matches {
            if m.index < lo || m.index >= hi || !is_normalized_domain(&m.name) {
                return Err(ProtocolError::Invalid(
                    "match outside tile or invalid name".into(),
                ));
            }
            if m.risk_score_bp > 10_000 || m.codes.len() > limits.max_findings {
                return Err(ProtocolError::Invalid("match fields out of range".into()));
            }
            let key = (&m.index, m.name.as_str());
            if prev.is_some_and(|p| p >= key) {
                return Err(ProtocolError::Invalid(
                    "matches must be sorted and unique".into(),
                ));
            }
            prev = Some(key);
        }
    }
    Ok(v)
}
