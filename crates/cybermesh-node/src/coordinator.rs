//! The coordinator: approved task issuer and independent result verifier.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cybermesh_analysis::CtLogInfo;
use cybermesh_analysis::{Engine, EvidenceBundle, engine_spec, normalize_domain};
use cybermesh_crypto::{
    Digest, Envelope, KeyId, SecretKey, canonical, generate_nonce, random_bytes,
};
use cybermesh_ct::checkpoint::{fetch_verified_checkpoint, max_checkpoint_age_secs};
use cybermesh_ct::http::open_log;
use cybermesh_ct::scan_entries;
use cybermesh_network::{
    Acceptance, NetConfig, NetEvent, NetworkHandle, Topics, keypair_from_seed,
};
use cybermesh_protocol::ct::{CtScanTask, verify_ct_result};
use cybermesh_protocol::replay::ReplayCache;
use cybermesh_protocol::validate::{peek_payload_type, verify_heartbeat, verify_result};
use cybermesh_protocol::{
    Clock, Limits, OperatorId, PROTOCOL_VERSION, Role, TaskAnnouncement, TaskKind, TrustManifest,
    WorkerState, payload_type,
};
use cybermesh_verifier::ct::{CtOracle, CtPolicy, CtTaskVerifier};
use cybermesh_verifier::fault_proof::{Check, FaultProof, check_fault_proof, verify_fault_proof};
use cybermesh_verifier::{
    Policy, ReputationBook, SubmitOutcome, TaskStatus, TaskVerifier, VerificationRecord, VerifierId,
};
use serde::Serialize;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::NodeError;
use crate::config::CoordinatorConfig;
use crate::files;
use crate::worker::{allowed_peers, parse_addrs};

/// Everything a coordinator needs, already loaded and verified.
#[derive(Debug)]
pub struct CoordinatorSetup {
    pub issuer: SecretKey,
    pub verifier: SecretKey,
    pub manifest: TrustManifest,
    pub engine: Engine,
    pub listen: Vec<cybermesh_network::Multiaddr>,
    pub bootstrap: Vec<cybermesh_network::Multiaddr>,
    pub state_dir: PathBuf,
    pub domains: Vec<String>,
    pub batch_size: usize,
    pub replication: usize,
    pub task_ttl_secs: u64,
    pub result_timeout: Duration,
    pub max_attempts: usize,
    pub liveness_secs: u64,
    pub max_inflight: usize,
    pub exit_when_done: bool,
    /// A batch that cannot be assigned to enough distinct operators for this long is
    /// abandoned (counted in the report) so it never blocks the queue indefinitely.
    pub abandon_after: Duration,
    /// Issue nothing until this many distinct workers are live (heartbeats received), or
    /// until `abandon_after` has passed since start. 0 starts as soon as enough operators
    /// are live for a task. Gives late-starting workers a fair share of the first batches.
    pub start_after_workers: usize,
    /// With `exit_when_done`: how long to keep running for the other verifiers' records of
    /// the tasks this coordinator settled (so its organisation can build releases from its
    /// own node), when the manifest requires more than one verifier.
    pub records_wait: Duration,
    pub policy: Policy,
    pub clock: Arc<dyn Clock>,
    pub gossip_heartbeat: Duration,
    /// Reload the manifest from here every minute (None in tests).
    pub manifest_source: Option<files::ManifestSource>,
    /// Certificate Transparency monitoring (None = domain tasks only).
    pub ct: Option<CtSetup>,
    /// CT logs this coordinator witnesses with its verifier key (by default the followed log).
    pub witness: Option<crate::ct_witness::WitnessSetup>,
}

/// CT monitoring setup for the coordinator.
#[derive(Debug, Clone)]
pub struct CtSetup {
    pub log: CtLogInfo,
    /// First full data tile; `None` = the most recent `tile_count` full tiles.
    pub first_tile: Option<u64>,
    pub tile_count: u64,
    pub tiles_per_task: u32,
    /// Workers (distinct operators) per shard.
    pub replication: usize,
    pub policy: CtPolicy,
    /// Secret seed for unpredictable spot checks.
    pub seed: [u8; 32],
    /// Follow the log as it grows instead of scanning a fixed range once.
    pub follow: Option<CtFollowSetup>,
}

/// Continuous tailing of a CT log (`[ct] follow = true`).
#[derive(Debug, Clone)]
pub struct CtFollowSetup {
    /// How often the checkpoint is polled.
    pub poll: Duration,
    /// New tiles scheduled per poll at most (the rest wait for later polls).
    pub max_tiles_per_poll: u64,
    /// Stop following once every tile below this one is settled (bounded runs, demos).
    pub until_tile: Option<u64>,
}

/// A fault proof checked off the event loop.
struct FaultChecked {
    reporter: KeyId,
    key: crate::fault_proofs::ProofKey,
    bytes: Vec<u8>,
    check: Check,
}

/// A fault proof waiting for its check.
struct QueuedProof {
    proof: FaultProof,
    bytes: Vec<u8>,
}

/// The pinned log a CT task names, read from its (not yet verified) payload to choose log
/// access; the check verifies the task itself.
fn ct_log_of(task: &str, engine: &Engine, limits: &Limits) -> Option<CtLogInfo> {
    if peek_payload_type(task.as_bytes(), limits).as_deref() != Some(payload_type::CT_TASK) {
        return None;
    }
    let env = Envelope::parse(task.as_bytes(), limits.max_envelope_bytes).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&env.payload_bytes().ok()?).ok()?;
    let id = v.get("log_id")?.as_str()?;
    engine
        .evidence()
        .ct_logs
        .iter()
        .find(|l| l.log_id == id)
        .cloned()
}

/// Checks a fault proof with this coordinator's own engine and, for CT, its own log access,
/// authenticated as for settling tasks (blocking, within
/// [`crate::fault_proofs::CHECK_BUDGET`]). A log proven to show a split view (`split_logs`)
/// cannot be relied on to say what the worker saw, so such a proof stays unconfirmed.
fn check_fault_proof_here(
    p: &FaultProof,
    manifest: &TrustManifest,
    engine: &Engine,
    split_logs: &BTreeSet<String>,
    now: u64,
) -> Check {
    let limits = Limits::default();
    let log = ct_log_of(&p.task, engine, &limits);
    if let Some(l) = log.as_ref().filter(|l| split_logs.contains(&l.log_id)) {
        return Check::Unconfirmed(format!("log {} was proven to show a split view", l.log_id));
    }
    let deadline = Instant::now() + crate::fault_proofs::CHECK_BUDGET;
    let src = log
        .as_ref()
        .and_then(|l| open_log(l, Duration::from_secs(30)).ok());
    let auth = match (&src, &log) {
        (Some(s), Some(l)) => fetch_verified_checkpoint(&**s, l)
            .and_then(|cp| {
                cybermesh_ct::checkpoint::check_fresh(&cp, now, max_checkpoint_age_secs(l))?;
                Ok(cp)
            })
            .ok()
            .map(|cp| cybermesh_ct::authenticator(&**s, cp)),
        _ => None,
    };
    let oracle = auth.as_ref().map(|a| LogOracle {
        auth: &**a,
        engine,
        contradicted: std::sync::Mutex::new(BTreeSet::new()),
        deadline: Some(deadline),
    });
    check_fault_proof(
        p,
        manifest,
        Some(engine),
        oracle.as_ref().map(|o| o as &dyn CtOracle),
        &limits,
        now,
    )
}

/// The followed log, if a split view of it has been proven.
fn followed_log_split(
    ct: Option<&CtSetup>,
    witness: Option<&crate::ct_witness::Witness>,
) -> Option<String> {
    let ct = ct.filter(|c| c.follow.is_some())?;
    witness
        .filter(|w| w.is_split(&ct.log.log_id))
        .map(|_| ct.log.log_id.clone())
}

/// Consecutive inconsistent checkpoints after which following stops.
const MAX_INCONSISTENT_POLLS: u32 = 3;

/// Result of polling a followed log's checkpoint.
enum PollOutcome {
    /// Verified with the pinned key, fresh, and proven to extend the previous head.
    Head(cybermesh_ct::Checkpoint),
    /// Validly signed but not an extension of the previous head: the log rewrote history.
    Inconsistent(String),
    /// Unavailable, unverifiable or stale.
    Failed(String),
}

/// Summary returned when the coordinator exits.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CoordinatorReport {
    pub tasks_issued: u64,
    pub reassignments: u64,
    pub results_accepted: u64,
    pub results_rejected: u64,
    /// Byte-identical re-deliveries of results already seen (replays), dropped.
    pub results_replayed: u64,
    pub faults: u64,
    /// Provable faults detected after a task was settled (e.g. late equivocation).
    pub late_faults: Vec<cybermesh_verifier::FaultRecord>,
    pub verified: u64,
    pub disputed: u64,
    pub insufficient: u64,
    pub domains_total: usize,
    pub domains_skipped: usize,
    /// Domains in batches abandoned because too few distinct operators were available.
    pub domains_abandoned: usize,
    /// Issue-to-settle latency per task, milliseconds.
    pub settle_latency_ms: Vec<u64>,
    #[serde(skip)]
    pub records: Vec<(Digest, VerificationRecord)>,
    pub net_bytes_in: u64,
    pub net_bytes_out: u64,
    pub net_dropped_rate_limited: u64,
    pub net_dropped_queue_full: u64,
    /// Connected peers with a negative score at exit: they sent this node provably invalid
    /// messages (network peer scoring).
    pub net_penalised_peers: u64,
    /// CPU time of this process (ms), and what it received from CT logs (bytes after
    /// decompression, requests), for cost comparisons.
    pub cpu_ms: u64,
    pub ct_http_bytes: u64,
    pub ct_http_requests: u64,
    pub ct_tiles_verified: u64,
    pub ct_entries_verified: u64,
    pub ct_matches: u64,
    pub ct_tiles_rescanned: u64,
    /// Own records published on the `records` topic (including re-publications).
    pub records_published: u64,
    /// Own records too large for one network message (kept only as files).
    pub records_too_large: u64,
    /// Valid records of other verifiers received and stored in `received-records/`.
    pub records_received: u64,
    /// Records refused from the network (invalid, too old, from the future, store full).
    pub records_refused: u64,
    /// Follow mode: checkpoints accepted (verified, fresh, consistent with the previous one).
    pub ct_checkpoints_verified: u64,
    /// Follow mode: polls that failed (unavailable, unverifiable or stale checkpoints).
    pub ct_poll_failures: u64,
    /// Follow mode: validly signed checkpoints that did not extend the previous one.
    pub ct_log_inconsistencies: u64,
    /// Follow mode: next tile to schedule, and full tiles not yet scheduled.
    pub ct_next_tile: u64,
    pub ct_lag_tiles: u64,
    /// Follow mode: tiles given up for good in this run (left below the resume point).
    pub ct_tiles_unverified: u64,
    /// Follow mode: following stopped after repeated inconsistent checkpoints, or because the
    /// log was proven to show a split view.
    pub ct_follow_halted: bool,
    /// Fault proofs from independent verifiers: checked, confirmed here (the worker is then
    /// quarantined), refuted, undecidable here, and dropped (too many checks at once).
    pub peer_fault_proofs_received: u64,
    pub peer_faults_confirmed: u64,
    pub peer_faults_refuted: u64,
    pub peer_faults_unconfirmed: u64,
    pub peer_fault_proofs_dropped: u64,
    /// CT log witnessing, including proven split views.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ct_witness: Option<crate::ct_witness::WitnessStats>,
    /// The other verifiers' records received (also in `received-records/`).
    #[serde(skip)]
    pub received: Vec<(Digest, VerificationRecord)>,
}

/// Fields shared by both result kinds, extracted for routing.
pub(crate) struct ResultMeta {
    pub(crate) payload_digest: Digest,
    /// Digest of what the result asserts (assessments, or tile results), without its nonce
    /// and timing: the same answer signed twice has the same claims.
    pub(crate) claims: Option<Digest>,
    pub(crate) task_id: String,
    pub(crate) attempt: u32,
    pub(crate) task_digest: Digest,
    pub(crate) worker: KeyId,
    pub(crate) operator: OperatorId,
}

/// Authenticates a result of either kind (signature, enrolment, shape) and extracts the
/// routing fields. Binding to a task is the task verifier's job.
pub(crate) fn parse_result(
    data: &[u8],
    manifest: &TrustManifest,
    now: u64,
    limits: &Limits,
) -> Result<ResultMeta, cybermesh_protocol::ProtocolError> {
    if peek_payload_type(data, limits).as_deref() == Some(payload_type::CT_RESULT) {
        verify_ct_result(data, manifest, now, limits).map(|v| ResultMeta {
            payload_digest: v.payload_digest,
            claims: v.message.tiles_digest().ok(),
            task_id: v.message.task_id,
            attempt: v.message.attempt,
            task_digest: v.message.task_digest,
            worker: v.message.worker,
            operator: v.message.operator,
        })
    } else {
        verify_result(data, manifest, now, limits).map(|v| ResultMeta {
            payload_digest: v.payload_digest,
            claims: v.message.assessments_digest().ok(),
            task_id: v.message.task_id,
            attempt: v.message.attempt,
            task_digest: v.message.task_digest,
            worker: v.message.worker,
            operator: v.message.operator,
        })
    }
}

/// Normalises, de-duplicates and sorts input domains. Returns (domains, skipped).
#[must_use]
pub fn prepare_domains(lines: &str) -> (Vec<String>, usize) {
    let mut set = BTreeSet::new();
    let mut skipped = 0;
    for l in lines.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        match normalize_domain(l.split_whitespace().next().unwrap_or("")) {
            Ok(d) => {
                set.insert(d);
            }
            Err(_) => skipped += 1,
        }
    }
    (set.into_iter().collect(), skipped)
}

/// Loads a coordinator from its configuration file.
pub fn setup_from_config(
    cfg: &CoordinatorConfig,
    clock: Arc<dyn Clock>,
) -> Result<(CoordinatorSetup, usize), NodeError> {
    let issuer = SecretKey::read_from_file(&cfg.issuer_key)?;
    let verifier = SecretKey::read_from_file(&cfg.verifier_key)?;
    let (manifest, _) = files::load_manifest_checked(
        &cfg.manifest,
        &cfg.governance_root,
        &cfg.state_dir.join("manifest-state.json"),
        clock.now(),
    )?;
    if manifest
        .key_with_role(&issuer.key_id(), Role::Issuer)
        .is_none()
    {
        return Err(NodeError::Config("issuer key lacks the issuer role".into()));
    }
    if manifest
        .key_with_role(&verifier.key_id(), Role::Verifier)
        .is_none()
    {
        return Err(NodeError::Config(
            "verifier key lacks the verifier role".into(),
        ));
    }
    cfg.policy.validate().map_err(NodeError::Config)?;
    let engine = Engine::new(EvidenceBundle::load(&cfg.evidence_dir)?);
    let ct = match &cfg.ct {
        None => None,
        Some(c) => {
            let log = engine
                .evidence()
                .ct_logs
                .iter()
                .find(|l| l.log_id == c.log_id)
                .cloned()
                .ok_or_else(|| {
                    NodeError::Config(format!(
                        "CT log {} is not in the ct-logs evidence",
                        c.log_id
                    ))
                })?;
            if c.tiles_per_task == 0
                || c.tiles_per_task > cybermesh_protocol::ct::MAX_TILES_PER_TASK
                || c.replication == 0
                || (c.follow && c.poll_secs == 0)
            {
                return Err(NodeError::Config(format!(
                    "ct.tiles_per_task must be 1..={}, ct.replication >= 1 and ct.poll_secs >= 1",
                    cybermesh_protocol::ct::MAX_TILES_PER_TASK
                )));
            }
            Some(CtSetup {
                log,
                first_tile: c.first_tile,
                tile_count: c.tile_count,
                tiles_per_task: c.tiles_per_task,
                replication: c.replication,
                policy: c.policy.clone(),
                seed: random_bytes::<32>()?,
                follow: c.follow.then(|| CtFollowSetup {
                    poll: Duration::from_secs(c.poll_secs),
                    max_tiles_per_poll: c.max_tiles_per_poll,
                    until_tile: c.until_tile,
                }),
            })
        }
    };
    let followed = cfg
        .ct
        .as_ref()
        .filter(|c| c.follow && c.witness)
        .map(|c| c.log_id.as_str());
    let witness =
        crate::ct_witness::setup_from_config(cfg.ct_witness.as_ref(), followed, engine.evidence())?;
    let text = String::from_utf8_lossy(&files::read_bytes(&cfg.domains_file)?).into_owned();
    let (domains, skipped) = prepare_domains(&text);
    Ok((
        CoordinatorSetup {
            issuer,
            verifier,
            manifest,
            engine,
            listen: parse_addrs(&cfg.listen)?,
            bootstrap: parse_addrs(&cfg.bootstrap)?,
            state_dir: cfg.state_dir.clone(),
            domains,
            batch_size: cfg.batch_size,
            replication: cfg.replication,
            task_ttl_secs: cfg.task_ttl_secs,
            result_timeout: Duration::from_secs(cfg.result_timeout_secs),
            max_attempts: cfg.max_attempts,
            liveness_secs: cfg.liveness_secs,
            max_inflight: cfg.max_inflight,
            exit_when_done: cfg.exit_when_done,
            start_after_workers: cfg.start_after_workers,
            records_wait: Duration::from_secs(cfg.records_wait_secs),
            abandon_after: Duration::from_secs(cfg.result_timeout_secs.saturating_mul(10).max(30)),
            policy: cfg.policy.clone(),
            clock,
            gossip_heartbeat: Duration::from_millis(700),
            manifest_source: Some(files::ManifestSource {
                manifest: cfg.manifest.clone(),
                governance_root: cfg.governance_root.clone(),
            }),
            ct,
            witness,
        },
        skipped,
    ))
}

#[derive(Debug, Clone)]
struct LiveWorker {
    operator: OperatorId,
    last_seen: u64,
    active: bool,
    compatible: bool,
    ct_capable: bool,
}

#[derive(Debug, Clone)]
struct Batch {
    domains: Vec<String>,
    /// `(first_tile, tile_count)` for CT shard scans.
    ct: Option<(u64, u32)>,
    attempt: u32,
    queued_at: Instant,
    exclude: BTreeSet<KeyId>,
    first_issued: Option<Instant>,
}

/// A verifier for either task kind.
pub(crate) enum AnyVerifier {
    Domain(TaskVerifier),
    Ct(CtTaskVerifier),
}

impl AnyVerifier {
    pub(crate) fn missing(&self) -> Vec<KeyId> {
        match self {
            AnyVerifier::Domain(v) => v.missing(),
            AnyVerifier::Ct(v) => v.missing(),
        }
    }
    pub(crate) fn is_complete(&self) -> bool {
        match self {
            AnyVerifier::Domain(v) => v.is_complete(),
            AnyVerifier::Ct(v) => v.is_complete(),
        }
    }
    pub(crate) fn expires_at(&self) -> u64 {
        match self {
            AnyVerifier::Domain(v) => v.task().expires_at,
            AnyVerifier::Ct(v) => v.task().expires_at,
        }
    }
    pub(crate) fn attempt(&self) -> u32 {
        match self {
            AnyVerifier::Domain(v) => v.task().attempt,
            AnyVerifier::Ct(v) => v.task().attempt,
        }
    }
    pub(crate) fn task_digest(&self) -> Digest {
        match self {
            AnyVerifier::Domain(v) => v.task_digest(),
            AnyVerifier::Ct(v) => v.task_digest(),
        }
    }
    pub(crate) fn submit(&mut self, bytes: &[u8], m: &TrustManifest, now: u64) -> SubmitOutcome {
        match self {
            AnyVerifier::Domain(v) => v.submit(bytes, m, now),
            AnyVerifier::Ct(v) => v.submit(bytes, m, now),
        }
    }
}

/// Log access for CT verification (the coordinator's own fetches and engine).
/// Log access for CT verification: every tile root is proven against the log's checkpoint,
/// whose signature was verified with the pinned key.
struct LogOracle<'a> {
    auth: &'a dyn cybermesh_ct::LogAuthenticator,
    engine: &'a Engine,
    /// Tiles whose hash tiles contradicted the signed checkpoint.
    contradicted: std::sync::Mutex<BTreeSet<u64>>,
    /// Past this, nothing more is fetched (answers are then unavailable).
    deadline: Option<Instant>,
}

impl LogOracle<'_> {
    fn out_of_time(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }
}

impl CtOracle for LogOracle<'_> {
    fn tile_root(&self, log: &str, tile: u64) -> Option<Digest> {
        if self.out_of_time() {
            return None;
        }
        match self.auth.tile_root(tile) {
            Ok(r) => Some(Digest(r)),
            // Only a hash mismatch is a contradiction; a wrong-length body (an error page from a
            // CDN or captive portal) is merely unavailable.
            Err(e @ cybermesh_ct::CtError::Unauthenticated(_)) => {
                warn!(%log, tile, error = %e, "CT log hash tiles contradict its signed checkpoint");
                if let Ok(mut c) = self.contradicted.lock() {
                    c.insert(tile);
                }
                None
            }
            Err(_) => None,
        }
    }
    fn rescan(&self, _log: &str, tile: u64) -> Option<cybermesh_protocol::ct::TileScanResult> {
        if self.out_of_time() {
            return None;
        }
        let (entries, _) = self.auth.source().entries(tile).ok()?;
        scan_entries(&entries, tile, self.engine).ok()
    }
    fn proof_failed(&self, _log: &str, tile: u64) -> bool {
        self.contradicted.lock().is_ok_and(|c| c.contains(&tile))
    }
}

/// CT verifications finalizing at once (each may fetch and re-scan tiles from the log).
pub(crate) const MAX_CT_FINALIZING: usize = 2;

/// Settles a CT task against the log. Blocking: fetches the checkpoint, hash tiles and any
/// data tiles it must re-scan. Runs on a blocking thread, never on the event loop.
/// `log` is the pinned log the task names (None: no log access, so disagreement is
/// disputed); `seed` is this verifier's secret spot-check seed.
/// `anchor`: in follow mode, the coordinator's accepted head; the checkpoint used to verify
/// must provably extend it, so pending tasks are never checked against a forked view.
pub(crate) fn finalize_ct(
    v: CtTaskVerifier,
    engine: &Engine,
    log: Option<&CtLogInfo>,
    seed: &[u8; 32],
    now: u64,
    anchor: Option<&cybermesh_ct::Checkpoint>,
) -> VerificationRecord {
    let src = log.and_then(|l| open_log(l, Duration::from_secs(30)).ok());
    // Without a checkpoint signed by the pinned key there is no trusted log access: the task
    // is then settled as without log access (disagreement disputed, nothing confirmed).
    let auth = match (&src, log) {
        (Some(s), Some(l)) => match fetch_verified_checkpoint(&**s, l).and_then(|cp| {
            cybermesh_ct::checkpoint::check_fresh(&cp, now, max_checkpoint_age_secs(l))?;
            if let Some(a) = anchor {
                cybermesh_ct::authenticator(&**s, cp.clone()).prove_extends(a)?;
            }
            Ok(cp)
        }) {
            Ok(cp) => Some(cybermesh_ct::authenticator(&**s, cp)),
            Err(e) => {
                warn!(log = %l.log_id, error = %e, "CT checkpoint not verified; settling without log access");
                None
            }
        },
        _ => None,
    };
    let oracle = auth.as_ref().map(|a| LogOracle {
        auth: &**a,
        engine,
        contradicted: std::sync::Mutex::new(BTreeSet::new()),
        deadline: None,
    });
    v.finalize(
        Some(engine),
        oracle.as_ref().map(|o| o as &dyn CtOracle),
        seed,
        now,
    )
}

/// What `settle` needs to finish once a record exists.
struct SettleCtx {
    missing: Vec<KeyId>,
    forget_after: u64,
    task_digest: Digest,
    attempt: u32,
    batch: Batch,
    now: u64,
}

/// A CT verification finished on a blocking thread (`None` if it panicked).
struct CtFinalized {
    task_id: String,
    ctx: SettleCtx,
    record: Option<VerificationRecord>,
}

struct Inflight {
    verifier: AnyVerifier,
    deadline: Instant,
    batch: Batch,
}

fn rendezvous(task_id: &str, item: &[u8]) -> Digest {
    Digest::tagged("cybermesh/assign/v1", &[task_id.as_bytes(), item])
}

/// The verifier identity of `key` according to the manifest (it must hold the verifier role).
pub(crate) fn verifier_identity(
    m: &TrustManifest,
    key: &SecretKey,
) -> Result<VerifierId, NodeError> {
    let id = key.key_id();
    if m.key_with_role(&id, Role::Verifier).is_none() {
        return Err(NodeError::Config(
            "verifier key is not an enrolled verifier".into(),
        ));
    }
    let operator = m
        .operator_of(&id)
        .cloned()
        .ok_or_else(|| NodeError::Config("verifier key has no operator".into()))?;
    Ok(VerifierId { key: id, operator })
}

/// Signs and stores a verification record; returns its payload digest.
/// Signs and stores a verification record. Returns its payload digest and the signed
/// envelope bytes (also what is distributed on the `records` topic).
pub fn persist_record(
    dir: &Path,
    record: &VerificationRecord,
    verifier: &SecretKey,
) -> Result<(Digest, Vec<u8>), NodeError> {
    let bytes = canonical::to_vec(record)?;
    let env = Envelope::sign(payload_type::VERIFICATION, &bytes, verifier).to_vec()?;
    let path = dir.join(format!("{}-{}.json", record.task_id, record.attempt));
    files::write_atomic(&path, &env)?;
    Ok((Digest::of(&bytes), env))
}

/// What the coordinator remembers about a settled task to prove late equivocation.
struct SettledTask {
    forget_after: u64,
    task_digest: Digest,
    attempt: u32,
    /// Per worker: its accepted result's digest, and the digest of what it asserted.
    accepted: BTreeMap<KeyId, (Digest, Digest)>,
}

/// Late-equivocation faults kept in the report (further ones are only counted).
const MAX_LATE_FAULTS: usize = 1000;

struct Coordinator {
    s: CoordinatorSetup,
    topics: Topics,
    limits: Limits,
    workers: HashMap<KeyId, LiveWorker>,
    pending: VecDeque<Batch>,
    inflight: BTreeMap<String, Inflight>,
    reputation: ReputationBook,
    replay: ReplayCache,
    report: CoordinatorReport,
    /// Settled tasks: task id -> (forget after, worker -> accepted result digest). Lets the
    /// coordinator prove equivocation even when the conflicting result arrives late.
    settled: HashMap<String, SettledTask>,
    /// This coordinator's verifier identity (bound into every record it signs).
    verifier_id: VerifierId,
    engine_arc: Arc<Engine>,
    ct_permits: Arc<tokio::sync::Semaphore>,
    ct_finalized: tokio::sync::mpsc::UnboundedSender<CtFinalized>,
    /// CT verifications running in the background (exit waits for them).
    ct_finalizing: usize,
    records_in: crate::records::RecordStore,
    records_out: crate::records::RecordPublisher,
    follower: Option<crate::ct_follow::Follower>,
    ct_polling: bool,
    /// Consecutive polls whose checkpoint did not extend the accepted head.
    ct_inconsistent_streak: u32,
    ct_poll_tx: tokio::sync::mpsc::UnboundedSender<PollOutcome>,
    witness: Option<crate::ct_witness::Witness>,
    witness_tx: tokio::sync::mpsc::UnboundedSender<crate::ct_witness::JobOutcome>,
    fault_intake: crate::fault_proofs::ProofIntake<QueuedProof>,
    /// Finished proof checks. Unbounded, but at most MAX_CHECKS_IN_FLIGHT are outstanding.
    fault_tx: tokio::sync::mpsc::UnboundedSender<FaultChecked>,
}

impl Coordinator {
    /// Writes the reputation book atomically so quarantines survive crashes.
    fn persist_reputation(&self) {
        if let Err(e) =
            files::write_json(&self.s.state_dir.join("reputation.json"), &self.reputation)
        {
            warn!(error = %e, "failed to persist reputation");
        }
    }

    /// Workers that are currently live, enrolled and running a compatible engine.
    fn live_workers(&self) -> usize {
        let now = self.s.clock.now();
        self.workers
            .iter()
            .filter(|(k, w)| {
                w.active
                    && w.compatible
                    && now.saturating_sub(w.last_seen) <= self.s.liveness_secs
                    && self.s.manifest.key_with_role(k, Role::Worker).is_some()
            })
            .count()
    }

    fn choose_assignees(
        &self,
        task_id: &str,
        exclude: &BTreeSet<KeyId>,
        ct: bool,
    ) -> Option<Vec<KeyId>> {
        let now = self.s.clock.now();
        let (required, replication) = match (&self.s.ct, ct) {
            (Some(c), true) => (c.policy.min_operators.max(1), c.replication),
            _ => (self.s.policy.min_operators.max(1), self.s.replication),
        };
        let mut per_op: BTreeMap<&OperatorId, (Digest, &KeyId)> = BTreeMap::new();
        for (k, w) in &self.workers {
            let eligible = w.active
                && w.compatible
                && (!ct || w.ct_capable)
                && now.saturating_sub(w.last_seen) <= self.s.liveness_secs
                && !exclude.contains(k)
                && !self.reputation.is_quarantined(k)
                && self.s.manifest.key_with_role(k, Role::Worker).is_some();
            if !eligible {
                continue;
            }
            let score = rendezvous(task_id, k.as_str().as_bytes());
            per_op
                .entry(&w.operator)
                .and_modify(|cur| {
                    if score > cur.0 {
                        *cur = (score, k);
                    }
                })
                .or_insert((score, k));
        }
        if per_op.len() < required {
            return None;
        }
        let mut ops: Vec<(Digest, &KeyId)> = per_op
            .iter()
            .map(|(op, (_, k))| (rendezvous(task_id, op.as_str().as_bytes()), *k))
            .collect();
        ops.sort();
        ops.reverse();
        Some(
            ops.into_iter()
                .take(replication.max(required))
                .map(|(_, k)| k.clone())
                .collect(),
        )
    }

    async fn issue(&mut self, net: &NetworkHandle, mut batch: Batch) -> Result<(), Batch> {
        let now = self.s.clock.now();
        let Ok(task_bytes_id) = random_bytes::<16>() else {
            return Err(batch);
        };
        let task_id = hex_lower(&task_bytes_id);
        // Previous non-responders are avoided when possible, but exclusion is only a
        // preference: if it leaves too few operators, fall back to every eligible worker
        // (quarantined workers stay excluded through the reputation book).
        let mut avoid = batch.exclude.clone();
        avoid.extend(
            self.workers
                .keys()
                .filter(|k| self.reputation.is_unresponsive(k))
                .cloned(),
        );
        let is_ct = batch.ct.is_some();
        let Some(assignees) = self
            .choose_assignees(&task_id, &avoid, is_ct)
            .or_else(|| self.choose_assignees(&task_id, &BTreeSet::new(), is_ct))
        else {
            return Err(batch);
        };
        if let (Some((first_tile, tile_count)), Some(ctc)) = (batch.ct, self.s.ct.clone()) {
            return self
                .issue_ct(net, batch, task_id, assignees, first_tile, tile_count, &ctc)
                .await;
        }
        let ops: BTreeSet<_> = assignees
            .iter()
            .filter_map(|k| self.s.manifest.operator_of(k))
            .collect();
        let Ok(nonce) = generate_nonce() else {
            return Err(batch);
        };
        let task = TaskAnnouncement {
            v: PROTOCOL_VERSION,
            network_id: self.s.manifest.network_id.clone(),
            task_id: task_id.clone(),
            attempt: batch.attempt,
            kind: TaskKind::DomainRiskAssessment,
            issuer: self.s.issuer.key_id(),
            issued_at: now,
            expires_at: now + self.s.task_ttl_secs,
            nonce,
            engine: engine_spec(),
            evidence: self.s.engine.evidence().pins.clone(),
            domains: batch.domains.clone(),
            assignees,
            min_operators: u8::try_from(self.s.policy.min_operators.min(ops.len())).unwrap_or(1),
        };
        let Ok(bytes) = canonical::to_vec(&task) else {
            return Err(batch);
        };
        let env = Envelope::sign(payload_type::TASK, &bytes, &self.s.issuer);
        let Ok(env_bytes) = env.to_vec() else {
            return Err(batch);
        };
        if let Err(e) = net.publish(&self.topics.tasks, env_bytes).await {
            debug!(error = %e, "task publish failed; will retry");
            return Err(batch);
        }
        let Ok(verifier) = TaskVerifier::new(
            task.clone(),
            Digest::of(&bytes),
            self.verifier_id.clone(),
            self.s.policy.clone(),
            self.limits.clone(),
        ) else {
            return Err(batch);
        };
        let verifier = AnyVerifier::Domain(verifier);
        batch.first_issued.get_or_insert_with(Instant::now);
        info!(task = %task_id, attempt = batch.attempt, domains = batch.domains.len(), assignees = task.assignees.len(), "task issued");
        self.report.tasks_issued += 1;
        self.inflight.insert(
            task_id,
            Inflight {
                verifier,
                deadline: Instant::now() + self.s.result_timeout,
                batch,
            },
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn issue_ct(
        &mut self,
        net: &NetworkHandle,
        mut batch: Batch,
        task_id: String,
        assignees: Vec<KeyId>,
        first_tile: u64,
        tile_count: u32,
        ctc: &CtSetup,
    ) -> Result<(), Batch> {
        let now = self.s.clock.now();
        let ops: BTreeSet<_> = assignees
            .iter()
            .filter_map(|k| self.s.manifest.operator_of(k))
            .collect();
        let Ok(nonce) = generate_nonce() else {
            return Err(batch);
        };
        let task = CtScanTask {
            v: PROTOCOL_VERSION,
            network_id: self.s.manifest.network_id.clone(),
            task_id: task_id.clone(),
            attempt: batch.attempt,
            issuer: self.s.issuer.key_id(),
            issued_at: now,
            expires_at: now + self.s.task_ttl_secs,
            nonce,
            engine: engine_spec(),
            evidence: self.s.engine.evidence().pins.clone(),
            log_id: ctc.log.log_id.clone(),
            first_tile,
            tile_count,
            assignees,
            min_operators: u8::try_from(ctc.policy.min_operators.min(ops.len())).unwrap_or(1),
        };
        let Ok(bytes) = canonical::to_vec(&task) else {
            return Err(batch);
        };
        let Ok(env_bytes) = Envelope::sign(payload_type::CT_TASK, &bytes, &self.s.issuer).to_vec()
        else {
            return Err(batch);
        };
        if let Err(e) = net.publish(&self.topics.tasks, env_bytes).await {
            debug!(error = %e, "CT task publish failed; will retry");
            return Err(batch);
        }
        let Ok(verifier) = CtTaskVerifier::new(
            task.clone(),
            Digest::of(&bytes),
            self.verifier_id.clone(),
            ctc.policy.clone(),
            self.s.policy.clone(),
            self.limits.clone(),
        ) else {
            return Err(batch);
        };
        batch.first_issued.get_or_insert_with(Instant::now);
        info!(task = %task_id, attempt = batch.attempt, log = %ctc.log.log_id, first_tile, tile_count, assignees = task.assignees.len(), "CT task issued");
        self.report.tasks_issued += 1;
        self.inflight.insert(
            task_id,
            Inflight {
                verifier: AnyVerifier::Ct(verifier),
                // Downloading tiles takes longer than lexical analysis.
                deadline: Instant::now() + self.s.result_timeout * 4,
                batch,
            },
        );
        Ok(())
    }

    fn settle(&mut self, task_id: &str) {
        let Some(inf) = self.inflight.remove(task_id) else {
            return;
        };
        let ctx = SettleCtx {
            missing: inf.verifier.missing(),
            forget_after: inf.verifier.expires_at().saturating_add(3600),
            task_digest: inf.verifier.task_digest(),
            attempt: inf.verifier.attempt(),
            batch: inf.batch,
            now: self.s.clock.now(),
        };
        match inf.verifier {
            AnyVerifier::Domain(v) => {
                let record = v.finalize(Some(&self.s.engine), ctx.now);
                self.apply_record(task_id, ctx, record);
            }
            AnyVerifier::Ct(v) => {
                // Verification fetches tiles from the log: run it off the event loop, with
                // bounded concurrency, and apply the record when it comes back.
                self.ct_finalizing += 1;
                let engine = Arc::clone(&self.engine_arc);
                // A log proven to show a split view is not relied on: settle as without log
                // access (disagreement disputed, nothing confirmed).
                let ct = self.s.ct.clone().filter(|c| {
                    !self
                        .witness
                        .as_ref()
                        .is_some_and(|w| w.is_split(&c.log.log_id))
                });
                let permits = Arc::clone(&self.ct_permits);
                let tx = self.ct_finalized.clone();
                let task_id = task_id.to_owned();
                let anchor = self.follower.as_ref().and_then(|f| f.head().cloned());
                tokio::spawn(async move {
                    let _permit = permits.acquire_owned().await.ok();
                    let now = ctx.now;
                    let record = tokio::task::spawn_blocking(move || {
                        let seed = ct.as_ref().map_or([0u8; 32], |c| c.seed);
                        finalize_ct(
                            v,
                            &engine,
                            ct.as_ref().map(|c| &c.log),
                            &seed,
                            now,
                            anchor.as_ref(),
                        )
                    })
                    .await
                    .ok();
                    let _ = tx.send(CtFinalized {
                        task_id,
                        ctx,
                        record,
                    });
                });
            }
        }
    }

    fn on_ct_finalized(&mut self, done: CtFinalized) {
        self.ct_finalizing = self.ct_finalizing.saturating_sub(1);
        match done.record {
            Some(r) => self.apply_record(&done.task_id, done.ctx, r),
            None => {
                warn!(task = %done.task_id, "CT verification failed internally; batch will be retried");
                if let Some((first, count)) = done.ctx.batch.ct {
                    self.ct_batch_finished(first, count, false);
                }
            }
        }
    }

    /// Records, persists and acts on a finished verification (reputation, retries).
    fn apply_record(&mut self, task_id: &str, ctx: SettleCtx, record: VerificationRecord) {
        let SettleCtx {
            missing,
            forget_after,
            task_digest,
            attempt,
            batch,
            now,
        } = ctx;
        if let Some(ct) = &record.ct {
            self.report.ct_tiles_verified += if record.status == TaskStatus::Verified {
                u64::from(ct.tile_count)
            } else {
                0
            };
            self.report.ct_entries_verified += ct.entries;
            self.report.ct_matches += ct.matches.len() as u64;
            self.report.ct_tiles_rescanned += ct.tiles_rescanned.len() as u64;
        }
        self.reputation.record_missed(&missing);
        self.reputation.apply(&record);
        self.persist_reputation();
        self.report.faults += record.faults.len() as u64;
        match record.status {
            TaskStatus::Verified => self.report.verified += 1,
            TaskStatus::Disputed => self.report.disputed += 1,
            TaskStatus::Insufficient => self.report.insufficient += 1,
        }
        for f in &record.faults {
            warn!(worker = %f.worker.short(), operator = %f.operator, kind = ?f.kind, "provable fault; worker quarantined");
        }
        let dir = self.s.state_dir.join("records");
        match persist_record(&dir, &record, &self.s.verifier) {
            Ok((d, env)) => {
                self.records_out.queue(env, record.verified_at);
                self.report.records.push((d, record.clone()));
            }
            Err(e) => warn!(error = %e, "failed to persist verification record"),
        }
        let retry = record.status != TaskStatus::Verified
            && (batch.attempt as usize + 1) < self.s.max_attempts;
        if retry {
            let mut b = batch;
            b.attempt += 1;
            b.queued_at = Instant::now();
            // Exclude non-responders and faulted workers from the next attempt.
            b.exclude.extend(missing);
            b.exclude
                .extend(record.faults.iter().map(|f| f.worker.clone()));
            info!(task = %task_id, status = ?record.status, next_attempt = b.attempt, "reassigning");
            self.report.reassignments += 1;
            self.pending.push_front(b);
        } else {
            if let Some(t) = batch.first_issued {
                self.report
                    .settle_latency_ms
                    .push(u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX));
            }
            if let Some((first, count)) = batch.ct {
                self.ct_batch_finished(first, count, record.status == TaskStatus::Verified);
            }
        }
        self.settled.retain(|_, s| s.forget_after > now);
        if self.settled.len() < 10_000 {
            self.settled.insert(
                task_id.to_owned(),
                SettledTask {
                    forget_after,
                    task_digest,
                    attempt,
                    accepted: record
                        .accepted
                        .iter()
                        .map(|a| (a.worker.clone(), (a.result_digest, a.assessments_digest)))
                        .collect(),
                },
            );
        }
        info!(task = %task_id, status = ?record.status, recomputed = record.recomputed, published = record.publishable().count(), "task settled");
    }

    async fn on_result(&mut self, net: &NetworkHandle, m: &cybermesh_network::InboundMessage) {
        let now = self.s.clock.now();
        let parsed = parse_result(&m.data, &self.s.manifest, now, &self.limits);
        let v = match parsed {
            Ok(v) => v,
            Err(e) => {
                self.report.results_rejected += 1;
                warn!(error = %e, "rejected result message");
                net.report(m, crate::blame(e.proves_misbehaviour())).await;
                return;
            }
        };
        if self.replay.contains(&v.payload_digest) {
            self.report.results_replayed += 1;
            net.report(m, Acceptance::Ignore).await;
            return;
        }
        let task_id = v.task_id.clone();
        let Some(inf) = self.inflight.get_mut(&task_id) else {
            // Late result for a settled task: a signed result asserting something else, from a
            // worker whose result was already accepted, is provable equivocation (the same
            // answer signed again is not). Only a second result for the *same* task payload
            // and attempt proves it; a result answering a different payload (e.g. another
            // issuer re-using the task id) proves nothing about this worker.
            let prior = self
                .settled
                .get(&task_id)
                .filter(|s| s.task_digest == v.task_digest && s.attempt == v.attempt)
                .and_then(|s| s.accepted.get(&v.worker))
                .copied();
            let _ = self
                .replay
                .check_and_insert(v.payload_digest, now.saturating_add(3600), now);
            if let Some((prior, prior_claims)) = prior
                && prior != v.payload_digest
                && v.claims.is_some_and(|c| c != prior_claims)
                && !self.reputation.is_quarantined(&v.worker)
            {
                let fault = cybermesh_verifier::FaultRecord {
                    worker: v.worker.clone(),
                    operator: v.operator.clone(),
                    kind: cybermesh_verifier::FaultKind::Equivocation,
                    evidence: vec![prior, v.payload_digest],
                };
                warn!(worker = %fault.worker.short(), task = %task_id, "late equivocation proven; worker quarantined");
                self.reputation
                    .record_fault(&fault, &format!("task {task_id}"));
                let path = self
                    .s
                    .state_dir
                    .join("faults")
                    .join(format!("{task_id}-{}.json", fault.worker.short()));
                let _ = files::write_json(&path, &fault);
                let _ = files::write_atomic(
                    &self
                        .s
                        .state_dir
                        .join("faults")
                        .join(format!("{task_id}-{}.envelope.json", fault.worker.short())),
                    &m.data,
                );
                self.persist_reputation();
                self.report.faults += 1;
                if self.report.late_faults.len() < MAX_LATE_FAULTS {
                    self.report.late_faults.push(fault);
                }
                net.report(m, Acceptance::Reject).await;
                return;
            }
            net.report(m, Acceptance::Ignore).await;
            return;
        };
        let forget = inf.verifier.expires_at() + 3600;
        let _ = self.replay.check_and_insert(v.payload_digest, forget, now);
        let outcome = inf.verifier.submit(&m.data, &self.s.manifest, now);
        match &outcome {
            SubmitOutcome::Accepted => {
                self.report.results_accepted += 1;
                net.report(m, Acceptance::Accept).await;
            }
            SubmitOutcome::Duplicate => net.report(m, Acceptance::Ignore).await,
            SubmitOutcome::Rejected(r) => {
                self.report.results_rejected += 1;
                warn!(reason = %r, "result rejected");
                net.report(m, crate::blame(r.misbehaviour)).await;
            }
            SubmitOutcome::Fault(k) => {
                self.report.results_rejected += 1;
                warn!(kind = ?k, "result proves a fault");
                net.report(m, Acceptance::Reject).await;
            }
        }
        if self
            .inflight
            .get(&task_id)
            .is_some_and(|i| i.verifier.is_complete())
        {
            self.settle(&task_id);
        }
    }

    /// Other verifier operators whose records each settled task needs for a release.
    fn records_needed(&self) -> usize {
        let quorum = usize::from(self.s.manifest.min_verifiers);
        let available = self.s.manifest.verifier_operators().len();
        quorum.min(available).saturating_sub(1)
    }

    async fn on_record(&mut self, net: &NetworkHandle, m: &cybermesh_network::InboundMessage) {
        use crate::records::Received;
        let now = self.s.clock.now();
        let acc = match self.records_in.accept(&m.data, &self.s.manifest, now) {
            Received::Stored { operator } => {
                self.report.records_received += 1;
                debug!(%operator, "verification record received");
                Acceptance::Accept
            }
            Received::Duplicate | Received::Own => Acceptance::Ignore,
            Received::Ignored(e) => {
                // Not proof of misbehaviour (quota, clocks, manifest lag, local IO).
                self.report.records_refused += 1;
                debug!(error = %e, "verification record not stored");
                Acceptance::Ignore
            }
            Received::Rejected(e) => {
                self.report.records_refused += 1;
                debug!(error = %e, "refused verification record");
                Acceptance::Reject
            }
        };
        net.report(m, acc).await;
    }

    /// A fault proof from an independent verifier: checked here before anything is done.
    async fn on_fault(&mut self, net: &NetworkHandle, m: &cybermesh_network::InboundMessage) {
        use crate::fault_proofs::Admit;
        let now = self.s.clock.now();
        let v = match verify_fault_proof(&m.data, &self.s.manifest, now, &self.limits) {
            Ok(v) => v,
            Err(e) => {
                debug!(error = %e, "refused fault proof");
                net.report(m, crate::blame(e.proves_misbehaviour())).await;
                return;
            }
        };
        if v.signer == self.verifier_id.key {
            net.report(m, Acceptance::Ignore).await;
            return;
        }
        let p = v.message;
        if self.reputation.is_quarantined(&p.fault.worker) {
            net.report(m, Acceptance::Accept).await;
            return;
        }
        let reporter = p.reporter.clone();
        let fault = p.fault.clone();
        let queued = QueuedProof {
            proof: p,
            bytes: m.data.clone(),
        };
        match self
            .fault_intake
            .offer(&reporter, &fault, queued, Instant::now())
        {
            Admit::Queued => {
                net.report(m, Acceptance::Accept).await;
                self.report.peer_fault_proofs_received += 1;
                self.start_fault_checks();
            }
            Admit::Seen => net.report(m, Acceptance::Ignore).await,
            Admit::Full => {
                self.report.peer_fault_proofs_dropped += 1;
                net.report(m, Acceptance::Ignore).await;
            }
        }
    }

    /// Starts queued proof checks while check slots are free.
    fn start_fault_checks(&mut self) {
        while let Some((reporter, key, q)) = self.fault_intake.next_check() {
            let manifest = self.s.manifest.clone();
            let engine = Arc::clone(&self.engine_arc);
            let split = self
                .witness
                .as_ref()
                .map(crate::ct_witness::Witness::split_logs)
                .unwrap_or_default();
            let now = self.s.clock.now();
            let tx = self.fault_tx.clone();
            tokio::spawn(async move {
                let QueuedProof { proof, bytes } = q;
                let check = tokio::task::spawn_blocking(move || {
                    check_fault_proof_here(&proof, &manifest, &engine, &split, now)
                })
                .await
                .unwrap_or_else(|_| Check::Unconfirmed("the check failed internally".into()));
                let _ = tx.send(FaultChecked {
                    reporter,
                    key,
                    bytes,
                    check,
                });
            });
        }
    }

    /// Acts on a checked fault proof: a confirmed fault quarantines the worker.
    fn on_fault_checked(&mut self, done: FaultChecked) {
        let decided = !matches!(done.check, Check::Unconfirmed(_));
        self.fault_intake.done(&done.key, decided, Instant::now());
        self.start_fault_checks();
        match done.check {
            Check::Confirmed(fault) => {
                self.report.peer_faults_confirmed += 1;
                if self.reputation.is_quarantined(&fault.worker) {
                    return;
                }
                warn!(worker = %fault.worker.short(), operator = %fault.operator, kind = ?fault.kind, reporter = %done.reporter.short(),
                    "fault proven by another verifier and confirmed here; worker quarantined");
                self.reputation.record_fault(
                    &fault,
                    &format!(
                        "proven by verifier {} and confirmed by this coordinator",
                        done.reporter.short()
                    ),
                );
                self.persist_reputation();
                self.report.faults += 1;
                let tag = fault
                    .evidence
                    .first()
                    .map_or_else(|| "none".to_owned(), |d| d.hex()[..12].to_owned());
                let path = self
                    .s
                    .state_dir
                    .join("faults")
                    .join(format!("peer-{}-{tag}.json", fault.worker.short()));
                if let Err(e) = files::write_atomic(&path, &done.bytes) {
                    warn!(error = %e, "failed to keep the fault proof");
                }
            }
            Check::Refuted(reason) => {
                self.report.peer_faults_refuted += 1;
                info!(reporter = %done.reporter.short(), %reason, "fault proof refuted by this coordinator's own check");
            }
            Check::Unconfirmed(reason) => {
                self.report.peer_faults_unconfirmed += 1;
                debug!(reporter = %done.reporter.short(), %reason, "fault proof not confirmed here");
            }
        }
    }

    async fn on_checkpoint(&mut self, net: &NetworkHandle, m: &cybermesh_network::InboundMessage) {
        let acc = match &mut self.witness {
            Some(w) => w.on_message(&m.data, &self.s.manifest, self.s.clock.now()),
            None => Acceptance::Ignore,
        };
        net.report(m, acc).await;
    }

    /// A witnessing job finished. A proven split view of the followed log halts following:
    /// nothing more is scheduled from a log that showed organisations different trees.
    fn on_witness(&mut self, o: crate::ct_witness::JobOutcome) {
        let Some(w) = &mut self.witness else { return };
        let proven = w.on_outcome(o, self.s.clock.now());
        if !proven.is_empty() {
            self.halt_if_split();
        }
    }

    /// Halts following if a split view of the followed log has been proven, in this run or
    /// before a restart (the witness state survives restarts).
    fn halt_if_split(&mut self) {
        if let Some(log) = followed_log_split(self.s.ct.as_ref(), self.witness.as_ref())
            && !self.report.ct_follow_halted
        {
            self.report.ct_follow_halted = true;
            error!(log = %log, "CT follow halted: the log was proven to show a split view (see ct-split-views/); investigate, then remove it from ct-witness.json and run `cybermesh ct follow-reset`");
        }
    }

    /// A CT batch is finished (verified, or given up): advance the follow resume point.
    /// Only a verified batch advances the resume point; a given-up one is retried later.
    fn ct_batch_finished(&mut self, first_tile: u64, count: u32, verified: bool) {
        if let Some(f) = &mut self.follower {
            if verified {
                f.verified(first_tile);
            } else {
                f.gave_up(first_tile, count);
            }
            self.report.ct_tiles_unverified = f.unverified_tiles();
            if let Err(e) = f.persist() {
                warn!(error = %e, "failed to persist CT follow state");
            }
        }
    }

    /// Polls the followed log's checkpoint on a blocking thread.
    fn start_ct_poll(&mut self) {
        let (Some(ct), Some(f)) = (&self.s.ct, &self.follower) else {
            return;
        };
        self.ct_polling = true;
        let log = ct.log.clone();
        let head = f.head().cloned();
        let now = self.s.clock.now();
        let tx = self.ct_poll_tx.clone();
        // The outcome is always sent, even if the blocking poll panics, so polling resumes.
        tokio::spawn(async move {
            let outcome = tokio::task::spawn_blocking(move || {
                let src = open_log(&log, Duration::from_secs(30))
                    .map_err(|e| PollOutcome::Failed(e.to_string()))?;
                let cp = fetch_verified_checkpoint(&*src, &log)
                    .and_then(|cp| {
                        cybermesh_ct::checkpoint::check_fresh(
                            &cp,
                            now,
                            max_checkpoint_age_secs(&log),
                        )?;
                        Ok(cp)
                    })
                    .map_err(|e| PollOutcome::Failed(e.to_string()))?;
                if let Some(h) = &head
                    && cp.size < h.size
                {
                    // An older tree (a lagging mirror or CDN), not a rewrite: just stale.
                    return Err(PollOutcome::Failed(format!(
                        "checkpoint size {} is older than the accepted head {}",
                        cp.size, h.size
                    )));
                }
                if let Some(h) = head {
                    cybermesh_ct::authenticator(&*src, cp.clone())
                        .prove_extends(&h)
                        .map_err(|e| match e {
                            cybermesh_ct::CtError::Unauthenticated(m) => {
                                PollOutcome::Inconsistent(m)
                            }
                            other => PollOutcome::Failed(other.to_string()),
                        })?;
                }
                Ok(PollOutcome::Head(cp))
            })
            .await;
            let outcome = match outcome {
                Ok(Ok(o) | Err(o)) => o,
                Err(e) => PollOutcome::Failed(format!("poll panicked: {e}")),
            };
            let _ = tx.send(outcome);
        });
    }

    fn on_ct_poll(&mut self, outcome: PollOutcome) {
        self.ct_polling = false;
        let Some(f) = &mut self.follower else {
            return;
        };
        let log_id = self
            .s
            .ct
            .as_ref()
            .map(|c| c.log.log_id.clone())
            .unwrap_or_default();
        match outcome {
            PollOutcome::Head(cp) => {
                let size = cp.size;
                f.accept_head(cp);
                self.ct_inconsistent_streak = 0;
                self.report.ct_checkpoints_verified += 1;
                let pending_ct = self.pending.iter().filter(|b| b.ct.is_some()).count();
                // Given-up batches first (bounded retries), then newly completed tiles.
                let mut batches = f.retries();
                batches
                    .extend(f.schedule(pending_ct + batches.len(), 4 * self.s.max_inflight.max(1)));
                for (first, count) in &batches {
                    self.pending.push_back(Batch {
                        domains: Vec::new(),
                        ct: Some((*first, *count)),
                        attempt: 0,
                        queued_at: Instant::now(),
                        exclude: BTreeSet::new(),
                        first_issued: None,
                    });
                }
                self.report.ct_next_tile = f.next_tile();
                self.report.ct_lag_tiles = f.lag();
                if let Err(e) = f.persist() {
                    warn!(error = %e, "failed to persist CT follow state");
                }
                if !batches.is_empty() {
                    info!(log = %log_id, size, scheduled = batches.len(), next_tile = f.next_tile(), lag_tiles = f.lag(), "followed CT log grew");
                }
            }
            PollOutcome::Inconsistent(e) => {
                self.report.ct_log_inconsistencies += 1;
                self.ct_inconsistent_streak += 1;
                warn!(log = %log_id, error = %e, "CT log checkpoint does not extend the previous one: possible split view or rewritten history; not followed");
                if self.ct_inconsistent_streak >= MAX_INCONSISTENT_POLLS {
                    self.report.ct_follow_halted = true;
                    error!(log = %log_id, "CT follow halted after repeated inconsistent checkpoints; investigate the log, then `cybermesh ct follow-reset`");
                }
            }
            PollOutcome::Failed(e) => {
                self.report.ct_poll_failures += 1;
                warn!(log = %log_id, error = %e, "CT checkpoint poll failed");
            }
        }
    }

    async fn on_heartbeat(&mut self, net: &NetworkHandle, m: &cybermesh_network::InboundMessage) {
        let now = self.s.clock.now();
        match verify_heartbeat(&m.data, &self.s.manifest, now, &self.limits) {
            Ok(v) => {
                if self
                    .replay
                    .check_and_insert(v.payload_digest, v.message.sent_at + 600, now)
                    .is_err()
                {
                    net.report(m, Acceptance::Ignore).await;
                    return;
                }
                let h = v.message;
                let compatible =
                    h.engine == engine_spec() && h.evidence == self.s.engine.evidence().pins;
                if !compatible {
                    debug!(worker = %h.worker.short(), "worker evidence/engine differs from coordinator");
                }
                self.workers.insert(
                    h.worker.clone(),
                    LiveWorker {
                        operator: h.operator,
                        last_seen: h.sent_at.min(now),
                        active: h.state == WorkerState::Active,
                        compatible,
                        ct_capable: h.capabilities.contains(&TaskKind::CtShardScan),
                    },
                );
                net.report(m, Acceptance::Accept).await;
            }
            Err(e) => {
                debug!(error = %e, "rejected heartbeat");
                net.report(m, crate::blame(e.proves_misbehaviour())).await;
            }
        }
    }
}

fn hex_lower(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// Runs the coordinator.
pub async fn run_coordinator(
    setup: CoordinatorSetup,
    mut shutdown: watch::Receiver<bool>,
) -> Result<CoordinatorReport, NodeError> {
    let me = setup.issuer.key_id();
    let topics = Topics::for_network(&setup.manifest.network_id);
    let keypair = keypair_from_seed(&setup.issuer.seed())?;
    let net_cfg = NetConfig {
        listen: setup.listen.clone(),
        bootstrap: setup.bootstrap.clone(),
        allowed_peers: allowed_peers(&setup.manifest, &me),
        subscribe: [
            topics.results.clone(),
            topics.presence.clone(),
            topics.records.clone(),
            topics.faults.clone(),
        ]
        .into_iter()
        .chain(setup.witness.is_some().then(|| topics.checkpoints.clone()))
        .collect(),
        heartbeat: setup.gossip_heartbeat,
        // Per-author allowance (cost = 1 + KiB). Workers cap their own outbound traffic
        // (64 KiB/s by default); the coordinator allows comfortably more than that so honest
        // bursts of large results are never dropped, while still bounding each author.
        per_peer_burst: 4096,
        per_peer_refill_per_sec: 256,
        ..NetConfig::default()
    };
    let net = cybermesh_network::spawn(keypair, net_cfg)?;
    std::fs::create_dir_all(setup.state_dir.join("records"))
        .map_err(|e| NodeError::Io(e.to_string()))?;
    let rep_path = setup.state_dir.join("reputation.json");
    let reputation: ReputationBook = if rep_path.exists() {
        files::read_json(&rep_path)?
    } else {
        ReputationBook::default()
    };
    let mut pending: VecDeque<Batch> = setup
        .domains
        .chunks(setup.batch_size.max(1))
        .map(|c| Batch {
            domains: c.to_vec(),
            ct: None,
            attempt: 0,
            queued_at: Instant::now(),
            exclude: BTreeSet::new(),
            first_issued: None,
        })
        .collect();
    // Follow mode: schedule nothing now; the first checkpoint poll does (resuming from saved
    // state if there is any).
    let follower = match setup
        .ct
        .as_ref()
        .and_then(|ct| ct.follow.as_ref().map(|f| (ct, f)))
    {
        Some((ct, f)) => {
            let fl = crate::ct_follow::Follower::load_or_start(
                &setup.state_dir.join("ct-follow.json"),
                &ct.log.log_id,
                ct.first_tile,
                ct.tile_count,
                f.until_tile,
                ct.tiles_per_task,
                f.max_tiles_per_poll,
            )?;
            info!(log = %ct.log.log_id, resume_from = fl.next_tile(), poll_secs = f.poll.as_secs(), "following CT log");
            Some(fl)
        }
        None => None,
    };
    if let Some(ct) = setup.ct.as_ref().filter(|c| c.follow.is_none()) {
        let first = match ct.first_tile {
            Some(f) => Some(f),
            None => {
                let (log, count) = (ct.log.clone(), ct.tile_count);
                tokio::task::spawn_blocking(move || {
                    let src = open_log(&log, Duration::from_secs(30)).ok()?;
                    let cp = match fetch_verified_checkpoint(&*src, &log) {
                        Ok(cp) => cp,
                        Err(e) => {
                            warn!(log = %log.log_id, error = %e, "CT checkpoint not verified");
                            return None;
                        }
                    };
                    Some(cp.full_tiles().saturating_sub(count))
                })
                .await
                .ok()
                .flatten()
            }
        };
        match first {
            Some(first) => {
                let per = u64::from(ct.tiles_per_task);
                let mut t = first;
                while t < first + ct.tile_count {
                    let n = per.min(first + ct.tile_count - t);
                    pending.push_back(Batch {
                        domains: Vec::new(),
                        ct: Some((t, u32::try_from(n).unwrap_or(1))),
                        attempt: 0,
                        queued_at: Instant::now(),
                        exclude: BTreeSet::new(),
                        first_issued: None,
                    });
                    t += n;
                }
                info!(log = %ct.log.log_id, first_tile = first, tiles = ct.tile_count, "CT monitoring scheduled");
            }
            None => {
                warn!(log = %ct.log.log_id, "could not read the CT log checkpoint; CT monitoring skipped")
            }
        }
    }
    info!(peer = %net.local_peer_id, batches = pending.len(), domains = setup.domains.len(), "coordinator started");
    let (ct_finalized, mut ct_finalized_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ct_poll_tx, mut ct_poll_rx) = tokio::sync::mpsc::unbounded_channel::<PollOutcome>();
    let verifier_id = verifier_identity(&setup.manifest, &setup.verifier)?;
    let max_message = Limits::default().max_envelope_bytes;
    let records_in = crate::records::RecordStore::open(
        &setup.state_dir.join("received-records"),
        verifier_id.key.clone(),
        &setup.manifest,
        max_message,
        setup.clock.now(),
    )?;
    let mut records_out = crate::records::RecordPublisher::new(max_message);
    records_out.load_recent(&setup.state_dir.join("records"), setup.clock.now());
    let witness = match &setup.witness {
        Some(ws) => Some(crate::ct_witness::Witness::new(
            ws,
            &setup.verifier,
            &setup.manifest.network_id,
            &setup.state_dir,
        )?),
        None => None,
    };
    if let Some(w) = &witness {
        crate::ct_witness::log_started(w);
    }
    let (witness_tx, mut witness_rx) =
        tokio::sync::mpsc::unbounded_channel::<crate::ct_witness::JobOutcome>();
    let (fault_tx, mut fault_rx) = tokio::sync::mpsc::unbounded_channel::<FaultChecked>();
    let mut c = Coordinator {
        witness,
        witness_tx,
        fault_intake: crate::fault_proofs::ProofIntake::default(),
        fault_tx,
        follower,
        ct_polling: false,
        ct_inconsistent_streak: 0,
        ct_poll_tx,
        records_in,
        records_out,
        verifier_id,
        engine_arc: Arc::new(setup.engine.clone()),
        ct_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CT_FINALIZING)),
        ct_finalized,
        ct_finalizing: 0,
        report: CoordinatorReport {
            domains_total: setup.domains.len(),
            ..CoordinatorReport::default()
        },
        s: setup,
        topics,
        limits: Limits::default(),
        workers: HashMap::new(),
        pending,
        inflight: BTreeMap::new(),
        reputation,
        replay: ReplayCache::new(200_000),
        settled: HashMap::new(),
    };
    c.halt_if_split();
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let started = Instant::now();
    let mut warmed_up = c.s.start_after_workers == 0;
    let mut records_wait_since: Option<Instant> = None;
    let mut follow_tick = tokio::time::interval(
        c.s.ct
            .as_ref()
            .and_then(|ct| ct.follow.as_ref())
            .map_or(Duration::from_secs(3600), |f| f.poll),
    );
    let mut manifest_tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
            ev = net.next_event() => match ev {
                Some(NetEvent::Message(m)) => {
                    if m.topic == c.topics.results {
                        c.on_result(&net, &m).await;
                    } else if m.topic == c.topics.records {
                        c.on_record(&net, &m).await;
                    } else if m.topic == c.topics.presence {
                        c.on_heartbeat(&net, &m).await;
                    } else if m.topic == c.topics.checkpoints {
                        c.on_checkpoint(&net, &m).await;
                    } else if m.topic == c.topics.faults {
                        c.on_fault(&net, &m).await;
                    } else {
                        net.report(&m, Acceptance::Ignore).await;
                    }
                }
                Some(NetEvent::Listening(a)) => info!(%a, "listening"),
                Some(_) => {}
                None => break,
            },
            Some(done) = ct_finalized_rx.recv() => c.on_ct_finalized(done),
            Some(outcome) = ct_poll_rx.recv() => c.on_ct_poll(outcome),
            Some(o) = witness_rx.recv() => c.on_witness(o),
            Some(done) = fault_rx.recv() => c.on_fault_checked(done),
            _ = follow_tick.tick(), if c.follower.is_some() && !c.ct_polling && !c.report.ct_follow_halted => c.start_ct_poll(),
            _ = manifest_tick.tick() => {
                c.records_in.prune(c.s.clock.now());
                if let Some(src) = c.s.manifest_source.clone() {
                    match files::reload_manifest(&src, &c.s.manifest, c.s.clock.now()) {
                        files::Reload::Updated(m) => {
                            info!(sequence = m.sequence, "loaded newer trust manifest");
                            if m.key_with_role(&c.s.issuer.key_id(), Role::Issuer).is_none()
                                || m.key_with_role(&c.s.verifier.key_id(), Role::Verifier).is_none()
                            {
                                warn!("coordinator keys revoked or roles removed; stopping");
                                break;
                            }
                            net.set_allowed(allowed_peers(&m, &me)).await;
                            if let Err(e) = files::persist_manifest_state(&c.s.state_dir.join("manifest-state.json"), &m) {
                                warn!(error = %e, "failed to persist manifest state");
                            }
                            // Revoked workers disappear from assignment immediately.
                            c.workers.retain(|k, _| m.key_with_role(k, Role::Worker).is_some());
                            // Records of verifiers no longer enrolled are dropped.
                            if let Err(e) = c.records_in.rescan(&m, c.s.clock.now()) {
                                warn!(error = %e, "failed to re-check received records");
                            }
                            c.s.manifest = m;
                        }
                        files::Reload::Equivocation => {
                            warn!("manifest with the current sequence but different content; ignored");
                        }
                        files::Reload::Unchanged => {}
                    }
                }
            }
            _ = tick.tick() => {
                let expired: Vec<String> = c
                    .inflight
                    .iter()
                    .filter(|(_, i)| Instant::now() >= i.deadline)
                    .map(|(k, _)| k.clone())
                    .collect();
                for t in expired {
                    info!(task = %t, "result deadline reached");
                    c.settle(&t);
                }
                // Try each pending batch at most once per tick; a batch that cannot be
                // assigned goes to the back so it never blocks the others, and is abandoned
                // after `abandon_after`.
                if !warmed_up
                    && (c.live_workers() >= c.s.start_after_workers
                        || started.elapsed() >= c.s.abandon_after)
                {
                    warmed_up = true;
                    info!(live = c.live_workers(), "starting to issue tasks");
                    // Waiting for workers does not count towards abandoning a batch.
                    for b in &mut c.pending {
                        b.queued_at = Instant::now();
                    }
                }
                let mut attempts = c.pending.len();
                let manifest_valid = c.s.clock.now() < c.s.manifest.expires_at;
                while warmed_up
                    && manifest_valid
                    && c.inflight.len() < c.s.max_inflight
                    && attempts > 0
                {
                    attempts -= 1;
                    let Some(b) = c.pending.pop_front() else { break };
                    if let Err(b) = c.issue(&net, b).await {
                        if b.queued_at.elapsed() >= c.s.abandon_after {
                            warn!(domains = b.domains.len(), attempt = b.attempt, "abandoning batch: not enough distinct operators available");
                            c.report.domains_abandoned += b.domains.len();
                            if let Some((first, count)) = b.ct {
                                c.ct_batch_finished(first, count, false);
                            }
                        } else {
                            c.pending.push_back(b);
                        }
                    }
                }
                c.records_out.republish_due(
                    c.s.clock.now(),
                    crate::records::REPUBLISH_EVERY,
                    crate::records::REPUBLISH_WINDOW_SECS,
                );
                c.records_out.flush(&net, &c.topics.records).await;
                if let Some(w) = &mut c.witness {
                    let now = c.s.clock.now();
                    crate::ct_witness::start_jobs(w, &c.witness_tx, now);
                    crate::ct_witness::publish_due(w, &net, &c.topics.checkpoints, now).await;
                }
                if c.s.exit_when_done
                    && c.pending.is_empty()
                    && c.inflight.is_empty()
                    && c.ct_finalizing == 0
                    && c.fault_intake.is_idle()
                    && (c.report.ct_follow_halted
                        || c.follower.as_ref().is_none_or(crate::ct_follow::Follower::done))
                    // Wait for own records to go out only if peers need them for a quorum
                    // (with no other verifier subscribed, publishing cannot succeed).
                    && (c.records_needed() == 0 || c.records_out.is_idle())
                {
                    // Stay for the other verifiers' records (bounded), so this organisation's
                    // release signer can build from this node alone.
                    let started = *records_wait_since.get_or_insert_with(Instant::now);
                    let own: Vec<(String, Digest)> = c
                        .report
                        .records
                        .iter()
                        .map(|(_, r)| (r.task_id.clone(), r.task_digest))
                        .collect();
                    let complete = crate::records::quorum_records_present(
                        &c.records_in,
                        &own,
                        &c.verifier_id.operator,
                        c.records_needed(),
                    );
                    if complete || started.elapsed() >= c.s.records_wait {
                        if !complete {
                            warn!("leaving before every task has the other verifiers' records");
                        }
                        break;
                    }
                }
            }
        }
    }
    let _ = files::write_json(&rep_path, &c.reputation);
    c.report.records_published = c.records_out.published;
    c.report.records_too_large = c.records_out.too_large;
    c.report.received = std::mem::take(&mut c.records_in.received);
    let snap = net.stats.snapshot();
    c.report.net_bytes_in = snap.bytes_in;
    c.report.net_bytes_out = snap.bytes_out;
    c.report.net_dropped_rate_limited = snap.dropped_rate_limited;
    c.report.net_dropped_queue_full = snap.dropped_queue_full;
    c.report.net_penalised_peers = snap.penalised_peers;
    c.report.cpu_ms = crate::governor::process_cpu_ms();
    (c.report.ct_http_bytes, c.report.ct_http_requests) = cybermesh_ct::http::transfer_totals();
    c.report.ct_witness = c.witness.as_ref().map(|w| w.stats.clone());
    let _ = files::write_json(&c.s.state_dir.join("coordinator-report.json"), &c.report);
    net.shutdown().await;
    Ok(c.report)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use cybermesh_analysis::EvidenceBundle;
    use cybermesh_protocol::testkit::{TestNetwork, sign_bytes, test_key};
    use cybermesh_verifier::{FaultKind, FaultRecord};

    use super::*;

    #[test]
    fn a_proof_about_a_log_proven_split_is_not_confirmed() {
        let net = TestNetwork::new(&[("org-a", 1), ("org-b", 1)], 1_800_000_000);
        let log = CtLogInfo {
            log_id: "split-log".into(),
            description: String::new(),
            api: cybermesh_analysis::CtLogApi::Static,
            monitoring_url: "http://127.0.0.1:9/".into(),
            origin: "127.0.0.1/log".into(),
            public_key: "not used: the check stops before any log access".into(),
        };
        let engine = Engine::new(EvidenceBundle {
            ct_logs: vec![log],
            ..EvidenceBundle::default()
        });
        let task = sign_bytes(
            payload_type::CT_TASK,
            &serde_json::json!({ "log_id": "split-log" }),
            &test_key("issuer"),
        );
        let p = FaultProof {
            v: cybermesh_protocol::PROTOCOL_VERSION,
            network_id: "net".into(),
            reporter: test_key("reporter").key_id(),
            reported_at: 1_800_000_000,
            fault: FaultRecord {
                worker: test_key("worker").key_id(),
                operator: cybermesh_protocol::OperatorId::new("org-b").unwrap(),
                kind: FaultKind::IncorrectResult,
                evidence: vec![Digest::of(b"result")],
            },
            task: String::from_utf8(task).unwrap(),
            results: vec![],
        };
        let split = BTreeSet::from(["split-log".to_owned()]);
        let check = check_fault_proof_here(&p, &net.manifest, &engine, &split, 1_800_000_000);
        assert!(
            matches!(&check, Check::Unconfirmed(r) if r.contains("split view")),
            "{check:?}"
        );
    }
}
