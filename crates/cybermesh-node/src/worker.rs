//! The worker runtime.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use cybermesh_analysis::{Engine, EvidenceBundle, engine_spec};
use cybermesh_crypto::{Digest, Envelope, KeyId, SecretKey, canonical, generate_nonce};
use cybermesh_ct::TileSource as _;
use cybermesh_ct::http::HttpTileSource;
use cybermesh_ct::scan_tile;
use cybermesh_network::{
    Acceptance, NetConfig, NetEvent, NetworkHandle, Topics, keypair_from_seed, peer_id_of,
};
use cybermesh_protocol::ct::{CtScanResult, CtScanTask, TileScanResult, verify_ct_task};
use cybermesh_protocol::replay::ReplayCache;
use cybermesh_protocol::validate::{peek_payload_type, verify_task};
use cybermesh_protocol::{
    Clock, Heartbeat, Limits, OperatorId, PROTOCOL_VERSION, ResourceUsage, TaskAnnouncement,
    TaskKind, TaskResult, TrustManifest, WorkerState, payload_type,
};
use serde::Serialize;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::NodeError;
use crate::config::WorkerConfig;
use crate::files;
use crate::governor::{
    Decision, Governor, PauseReason, ResourcePolicy, ResourceSnapshot, process_cpu,
};

/// Everything a worker needs, already loaded and verified.
#[derive(Debug)]
pub struct WorkerSetup {
    pub key: SecretKey,
    pub manifest: TrustManifest,
    pub engine: Engine,
    pub listen: Vec<cybermesh_network::Multiaddr>,
    pub bootstrap: Vec<cybermesh_network::Multiaddr>,
    pub state_dir: PathBuf,
    pub control_dir: PathBuf,
    pub heartbeat: Duration,
    pub resources: ResourcePolicy,
    pub clock: Arc<dyn Clock>,
    pub gossip_heartbeat: Duration,
    pub adversary: Option<String>,
    /// Reload the manifest from here every minute (None in tests).
    pub manifest_source: Option<files::ManifestSource>,
}

/// Live status written to `state_dir/status.json` for administrators.
#[derive(Debug, Clone, Serialize, Default)]
pub struct WorkerStatus {
    pub key_id: String,
    pub operator: String,
    pub peer_id: String,
    pub state: String,
    pub pause_reason: Option<PauseReason>,
    pub tasks_completed: u64,
    pub tasks_refused: u64,
    pub assignments_dropped: u64,
    pub messages_rejected: u64,
    pub queue_depth: usize,
    pub outbox_depth: usize,
    pub resources: ResourceSnapshot,
    pub net_bytes_in: u64,
    pub net_bytes_out: u64,
    /// Bytes downloaded from CT logs.
    pub ct_bytes_fetched: u64,
    /// CPU time of this process (ms), and what it received from CT logs (bytes after
    /// decompression, requests), for cost comparisons.
    pub cpu_ms: u64,
    pub ct_http_bytes: u64,
    pub ct_http_requests: u64,
    pub net_dropped_rate_limited: u64,
    pub connected_peers: u64,
    pub updated_at: u64,
}

/// Parses multiaddrs from strings.
pub fn parse_addrs(v: &[String]) -> Result<Vec<cybermesh_network::Multiaddr>, NodeError> {
    v.iter()
        .map(|s| {
            s.parse()
                .map_err(|e| NodeError::Config(format!("bad multiaddr {s}: {e}")))
        })
        .collect()
}

/// Loads a worker from its configuration file.
pub fn setup_from_config(
    cfg: &WorkerConfig,
    clock: Arc<dyn Clock>,
) -> Result<WorkerSetup, NodeError> {
    let key = SecretKey::read_from_file(&cfg.key)?;
    let (manifest, _root) = files::load_manifest_checked(
        &cfg.manifest,
        &cfg.governance_root,
        &cfg.state_dir.join("manifest-state.json"),
        clock.now(),
    )?;
    if manifest.network_id != cfg.network_id {
        return Err(NodeError::Config(
            "manifest is for a different network".into(),
        ));
    }
    if manifest
        .key_with_role(&key.key_id(), cybermesh_protocol::Role::Worker)
        .is_none()
    {
        return Err(NodeError::Config(
            "this key is not an enrolled, non-revoked worker in the manifest".into(),
        ));
    }
    let engine = Engine::new(EvidenceBundle::load(&cfg.evidence_dir)?);
    if cfg.adversary.is_some() && !cfg!(feature = "adversary-sim") {
        return Err(NodeError::Config(
            "adversary mode requires a build with the adversary-sim feature".into(),
        ));
    }
    Ok(WorkerSetup {
        key,
        manifest,
        engine,
        listen: parse_addrs(&cfg.listen)?,
        bootstrap: parse_addrs(&cfg.bootstrap)?,
        state_dir: cfg.state_dir.clone(),
        control_dir: cfg.control_dir.clone(),
        heartbeat: Duration::from_secs(cfg.heartbeat_secs.max(1)),
        resources: cfg.resources.clone(),
        clock,
        gossip_heartbeat: Duration::from_millis(700),
        adversary: cfg.adversary.clone(),
        manifest_source: Some(files::ManifestSource {
            manifest: cfg.manifest.clone(),
            governance_root: cfg.governance_root.clone(),
        }),
    })
}

/// Peer ids of every enrolled, non-revoked member except `me`.
pub fn allowed_peers(m: &TrustManifest, me: &KeyId) -> Vec<cybermesh_network::PeerId> {
    m.members
        .iter()
        .filter(|x| &x.public_key.key_id() != me && !m.is_revoked(&x.public_key.key_id()))
        .filter_map(|x| peer_id_of(&x.public_key).ok())
        .collect()
}

struct Outgoing {
    bytes: Vec<u8>,
    deadline: u64,
    next_try: Instant,
}

/// Worker state machine; the async loop in [`run_worker`] drives it.
/// A queued, verified assignment.
enum Queued {
    Domain(TaskAnnouncement, Digest),
    Ct(CtScanTask, Digest),
}

impl Queued {
    fn expires_at(&self) -> u64 {
        match self {
            Queued::Domain(t, _) => t.expires_at,
            Queued::Ct(t, _) => t.expires_at,
        }
    }
}

/// Outcome of a background CT scan.
enum CtOutcome {
    Done(Vec<TileScanResult>, u64),
    /// Cancelled (STOP, shutdown) or the task expired mid-scan.
    Abandoned(&'static str),
    Failed(String),
}

/// The single CT scan running in the background, if any.
struct CtJob {
    task: CtScanTask,
    digest: Digest,
    cancel: Arc<AtomicBool>,
    cpu0: Duration,
    t0: Instant,
}

/// Message from the scan thread back to the event loop.
struct CtDone {
    task_id: String,
    outcome: CtOutcome,
}

/// Sleeps in short steps while `hold` is set or until `until`, returning false if the scan
/// must stop (cancelled or past its deadline).
fn ct_wait(
    cancel: &AtomicBool,
    hold: &AtomicBool,
    until: Option<Instant>,
    deadline: Instant,
) -> bool {
    loop {
        if cancel.load(Ordering::Relaxed) || Instant::now() >= deadline {
            return false;
        }
        let held = hold.load(Ordering::Relaxed);
        let waiting = until.is_some_and(|u| Instant::now() < u);
        if !held && !waiting {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

struct Worker {
    s: WorkerSetup,
    id: KeyId,
    operator: OperatorId,
    topics: Topics,
    limits: Limits,
    replay: ReplayCache,
    queue: VecDeque<Queued>,
    engine_arc: Arc<Engine>,
    ct_job: Option<CtJob>,
    /// Set while the governor pauses or throttles the worker; the scan thread waits.
    ct_hold: Arc<AtomicBool>,
    ct_done: tokio::sync::mpsc::UnboundedSender<CtDone>,
    outbox: VecDeque<Outgoing>,
    governor: Governor,
    status: WorkerStatus,
    cpu_resume_at: Option<Instant>,
    #[allow(dead_code)]
    last_result: Option<Vec<u8>>,
}

impl Worker {
    async fn on_task_message(
        &mut self,
        net: &NetworkHandle,
        m: &cybermesh_network::InboundMessage,
    ) {
        let now = self.s.clock.now();
        if now >= self.s.manifest.expires_at {
            // Never act on authority from an expired manifest.
            net.report(m, Acceptance::Ignore).await;
            return;
        }
        if peek_payload_type(&m.data, &self.limits).as_deref() == Some(payload_type::CT_TASK) {
            self.on_ct_task(net, m, now).await;
            return;
        }
        let v = match verify_task(&m.data, &self.s.manifest, now, &self.limits) {
            Ok(v) => v,
            Err(e) => {
                self.status.messages_rejected += 1;
                let acc = crate::blame(e.proves_misbehaviour());
                debug!(error = %e, "rejected task message");
                net.report(m, acc).await;
                return;
            }
        };
        let forget = v.message.expires_at + self.limits.max_clock_skew_secs;
        if self
            .replay
            .check_and_insert(v.payload_digest, forget, now)
            .is_err()
        {
            net.report(m, Acceptance::Ignore).await;
            return;
        }
        net.report(m, Acceptance::Accept).await;
        if !v.message.assignees.contains(&self.id) {
            return;
        }
        if self.queue.len() >= self.s.resources.max_queue {
            self.status.assignments_dropped += 1;
            warn!(task = %v.message.task_id, "task queue full; dropping assignment");
            return;
        }
        info!(task = %v.message.task_id, attempt = v.message.attempt, domains = v.message.domains.len(), "accepted assignment");
        self.queue
            .push_back(Queued::Domain(v.message, v.payload_digest));
    }

    async fn on_ct_task(
        &mut self,
        net: &NetworkHandle,
        m: &cybermesh_network::InboundMessage,
        now: u64,
    ) {
        let v = match verify_ct_task(&m.data, &self.s.manifest, now, &self.limits) {
            Ok(v) => v,
            Err(e) => {
                self.status.messages_rejected += 1;
                let acc = crate::blame(e.proves_misbehaviour());
                debug!(error = %e, "rejected CT task message");
                net.report(m, acc).await;
                return;
            }
        };
        let forget = v.message.expires_at + self.limits.max_clock_skew_secs;
        if self
            .replay
            .check_and_insert(v.payload_digest, forget, now)
            .is_err()
        {
            net.report(m, Acceptance::Ignore).await;
            return;
        }
        net.report(m, Acceptance::Accept).await;
        if !v.message.assignees.contains(&self.id) {
            return;
        }
        if !self.s.resources.ct_scanning {
            self.status.tasks_refused += 1;
            warn!(task = %v.message.task_id, "assigned a CT scan but ct_scanning is disabled; refusing");
            return;
        }
        if self.queue.len() >= self.s.resources.max_queue {
            self.status.assignments_dropped += 1;
            return;
        }
        info!(task = %v.message.task_id, log = %v.message.log_id, tiles = v.message.tile_count, "accepted CT assignment");
        self.queue
            .push_back(Queued::Ct(v.message, v.payload_digest));
    }

    /// Starts a CT scan on a blocking thread. The event loop stays responsive; the scan
    /// waits while the worker is paused or throttled, stops when cancelled or when the task
    /// expires, and reports back over `ct_done`.
    fn start_ct(&mut self, task: CtScanTask, digest: Digest) {
        if let Err(e) = self.engine_arc.check_pins(&task.engine, &task.evidence) {
            self.status.tasks_refused += 1;
            warn!(task = %task.task_id, error = %e, "refused CT task");
            return;
        }
        let Some(log) = self
            .engine_arc
            .evidence()
            .ct_logs
            .iter()
            .find(|l| l.log_id == task.log_id)
            .cloned()
        else {
            self.status.tasks_refused += 1;
            warn!(task = %task.task_id, log = %task.log_id, "log is not in the pinned ct-logs evidence");
            return;
        };
        let engine = Arc::clone(&self.engine_arc);
        let kib = self.s.resources.ct_fetch_kib_per_sec;
        let (first, count) = (task.first_tile, task.tile_count);
        let remaining = task.expires_at.saturating_sub(self.s.clock.now());
        let deadline = Instant::now() + Duration::from_secs(remaining);
        let cancel = Arc::new(AtomicBool::new(false));
        let (c, hold, tx, task_id) = (
            Arc::clone(&cancel),
            Arc::clone(&self.ct_hold),
            self.ct_done.clone(),
            task.task_id.clone(),
        );
        tokio::task::spawn_blocking(move || {
            let run = || -> CtOutcome {
                let src = match HttpTileSource::new(&log, Duration::from_secs(30)) {
                    Ok(s) => s,
                    Err(e) => return CtOutcome::Failed(e.to_string()),
                };
                let started = Instant::now();
                let mut out = Vec::with_capacity(count as usize);
                let mut bytes = 0u64;
                let mut pace: Option<Instant> = None;
                for n in first..first.saturating_add(u64::from(count)) {
                    if !ct_wait(&c, &hold, pace, deadline) {
                        return CtOutcome::Abandoned("cancelled or expired");
                    }
                    let data = match src.data_tile(n) {
                        Ok(d) => d,
                        Err(e) => return CtOutcome::Failed(e.to_string()),
                    };
                    bytes += data.len() as u64;
                    if !ct_wait(&c, &hold, None, deadline) {
                        return CtOutcome::Abandoned("cancelled or expired");
                    }
                    match scan_tile(&data, n, &engine) {
                        Ok(t) => out.push(t),
                        Err(e) => return CtOutcome::Failed(e.to_string()),
                    }
                    if kib > 0 {
                        let min = Duration::from_secs_f64(bytes as f64 / (kib as f64 * 1024.0));
                        pace = Some(started + min);
                    }
                }
                CtOutcome::Done(out, bytes)
            };
            let outcome = run();
            let _ = tx.send(CtDone { task_id, outcome });
        });
        self.ct_job = Some(CtJob {
            task,
            digest,
            cancel,
            cpu0: process_cpu(),
            t0: Instant::now(),
        });
    }

    /// Stops the running CT scan (STOP, shutdown).
    fn cancel_ct(&mut self) {
        if let Some(j) = &self.ct_job {
            j.cancel.store(true, Ordering::Relaxed);
        }
    }

    async fn finish_ct(&mut self, net: &NetworkHandle, done: CtDone) {
        let Some(job) = self.ct_job.take_if(|j| j.task.task_id == done.task_id) else {
            return;
        };
        let (task, digest) = (job.task, job.digest);
        let (tiles, fetched) = match done.outcome {
            CtOutcome::Done(t, b) => (t, b),
            CtOutcome::Abandoned(why) => {
                info!(task = %task.task_id, reason = why, "CT scan abandoned");
                return;
            }
            CtOutcome::Failed(e) => {
                self.status.tasks_refused += 1;
                warn!(task = %task.task_id, error = %e, "CT scan failed");
                return;
            }
        };
        // Process CPU over the job's lifetime (includes concurrent domain tasks; informational).
        let usage = ResourceUsage {
            cpu_micros: u64::try_from(process_cpu().saturating_sub(job.cpu0).as_micros())
                .unwrap_or(u64::MAX),
            wall_micros: u64::try_from(job.t0.elapsed().as_micros()).unwrap_or(u64::MAX),
        };
        if task.expires_at <= self.s.clock.now() {
            return;
        }
        let (Ok(input_digest), Ok(nonce)) = (task.input_digest(), generate_nonce()) else {
            return;
        };
        let count = task.tile_count;
        let result = CtScanResult {
            v: PROTOCOL_VERSION,
            network_id: self.s.manifest.network_id.clone(),
            task_id: task.task_id.clone(),
            attempt: task.attempt,
            task_digest: digest,
            input_digest,
            worker: self.id.clone(),
            operator: self.operator.clone(),
            engine: engine_spec(),
            evidence: self.engine_arc.evidence().pins.clone(),
            log_id: task.log_id.clone(),
            tiles,
            completed_at: self.s.clock.now(),
            nonce,
            usage,
            fetched_bytes: fetched,
        };
        let Ok(bytes) = canonical::to_vec(&result) else {
            return;
        };
        let Ok(signed) = Envelope::sign(payload_type::CT_RESULT, &bytes, &self.s.key).to_vec()
        else {
            return;
        };
        #[allow(unused_mut)]
        let mut messages = vec![signed];
        #[cfg(feature = "adversary-sim")]
        if let Some(mode) = &self.s.adversary {
            messages =
                crate::adversary::apply_ct(mode, &result, &self.s.key, self.last_result.as_deref());
        }
        self.last_result = messages.first().cloned();
        for m in messages {
            self.send(net, m, task.expires_at).await;
        }
        self.status.tasks_completed += 1;
        self.status.ct_bytes_fetched += fetched;
        info!(task = %task.task_id, tiles = count, kib = fetched / 1024, cpu_us = result.usage.cpu_micros, "CT result submitted");
    }

    fn build_result(
        &mut self,
        task: &TaskAnnouncement,
        digest: Digest,
    ) -> Result<TaskResult, String> {
        let cpu0 = process_cpu();
        let t0 = Instant::now();
        let assessments = self.s.engine.assess_task(task).map_err(|e| e.to_string())?;
        let usage = ResourceUsage {
            cpu_micros: u64::try_from(process_cpu().saturating_sub(cpu0).as_micros())
                .unwrap_or(u64::MAX),
            wall_micros: u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX),
        };
        Ok(TaskResult {
            v: PROTOCOL_VERSION,
            network_id: self.s.manifest.network_id.clone(),
            task_id: task.task_id.clone(),
            attempt: task.attempt,
            task_digest: digest,
            input_digest: task.input_digest().map_err(|e| e.to_string())?,
            worker: self.id.clone(),
            operator: self.operator.clone(),
            engine: engine_spec(),
            evidence: self.s.engine.evidence().pins.clone(),
            assessments,
            completed_at: self.s.clock.now(),
            nonce: generate_nonce().map_err(|e| e.to_string())?,
            usage,
        })
    }

    fn sign(&self, r: &TaskResult) -> Vec<u8> {
        let bytes = canonical::to_vec(r).unwrap_or_default();
        Envelope::sign(payload_type::RESULT, &bytes, &self.s.key)
            .to_vec()
            .unwrap_or_default()
    }

    async fn execute_next(&mut self, net: &NetworkHandle) {
        // One CT scan at a time; domain tasks keep running while it is in progress.
        let next = if self.ct_job.is_some() {
            self.queue
                .iter()
                .position(|q| matches!(q, Queued::Domain(..)))
        } else {
            Some(0)
        };
        let Some(item) = next.and_then(|i| self.queue.remove(i)) else {
            return;
        };
        let now = self.s.clock.now();
        if item.expires_at() <= now {
            return;
        }
        let (task, digest) = match item {
            Queued::Domain(t, d) => (t, d),
            Queued::Ct(t, d) => return self.start_ct(t, d),
        };
        match self.build_result(&task, digest) {
            Ok(result) => {
                #[allow(unused_mut)]
                let mut messages = vec![self.sign(&result)];
                #[cfg(feature = "adversary-sim")]
                if let Some(mode) = &self.s.adversary {
                    messages = crate::adversary::apply(
                        mode,
                        &result,
                        &self.s.key,
                        self.last_result.as_deref(),
                    );
                }
                self.last_result = messages.first().cloned();
                for bytes in messages {
                    self.send(net, bytes, task.expires_at).await;
                }
                self.status.tasks_completed += 1;
                info!(task = %task.task_id, cpu_us = result.usage.cpu_micros, "result submitted");
            }
            Err(e) => {
                self.status.tasks_refused += 1;
                warn!(task = %task.task_id, error = %e, "refused task");
            }
        }
    }

    async fn send(&mut self, net: &NetworkHandle, bytes: Vec<u8>, deadline: u64) {
        if net
            .publish(&self.topics.results, bytes.clone())
            .await
            .is_err()
            && self.outbox.len() < 64
        {
            self.outbox.push_back(Outgoing {
                bytes,
                deadline,
                next_try: Instant::now() + Duration::from_secs(1),
            });
        }
    }

    async fn flush_outbox(&mut self, net: &NetworkHandle) {
        let now = self.s.clock.now();
        let mut keep = VecDeque::new();
        while let Some(mut o) = self.outbox.pop_front() {
            if o.deadline <= now {
                continue;
            }
            if o.next_try > Instant::now() {
                keep.push_back(o);
                continue;
            }
            if net
                .publish(&self.topics.results, o.bytes.clone())
                .await
                .is_err()
            {
                o.next_try = Instant::now() + Duration::from_secs(2);
                keep.push_back(o);
            }
        }
        self.outbox = keep;
    }

    async fn heartbeat(&mut self, net: &NetworkHandle) {
        let state = if self.status.pause_reason.is_some() {
            WorkerState::Paused
        } else {
            WorkerState::Active
        };
        let Ok(nonce) = generate_nonce() else { return };
        let hb = Heartbeat {
            v: PROTOCOL_VERSION,
            network_id: self.s.manifest.network_id.clone(),
            worker: self.id.clone(),
            operator: self.operator.clone(),
            sent_at: self.s.clock.now(),
            nonce,
            state,
            engine: engine_spec(),
            evidence: self.s.engine.evidence().pins.clone(),
            queue_depth: u16::try_from(self.queue.len()).unwrap_or(u16::MAX),
            capabilities: if self.s.resources.ct_scanning {
                vec![TaskKind::DomainRiskAssessment, TaskKind::CtShardScan]
            } else {
                vec![TaskKind::DomainRiskAssessment]
            },
        };
        let Ok(bytes) = canonical::to_vec(&hb) else {
            return;
        };
        let env = Envelope::sign(payload_type::HEARTBEAT, &bytes, &self.s.key);
        if let Ok(b) = env.to_vec() {
            let _ = net.publish(&self.topics.presence, b).await;
        }
    }

    fn write_status(&mut self, net: &NetworkHandle) {
        let snap = net.stats.snapshot();
        self.status.queue_depth = self.queue.len();
        self.status.outbox_depth = self.outbox.len();
        self.status.resources = self.governor.snapshot();
        self.status.net_bytes_in = snap.bytes_in;
        self.status.net_bytes_out = snap.bytes_out;
        self.status.net_dropped_rate_limited = snap.dropped_rate_limited;
        self.status.connected_peers = snap.connected_peers;
        self.status.cpu_ms = crate::governor::process_cpu_ms();
        (self.status.ct_http_bytes, self.status.ct_http_requests) =
            cybermesh_ct::http::transfer_totals();
        self.status.updated_at = self.s.clock.now();
        let _ = files::write_json(&self.s.state_dir.join("status.json"), &self.status);
    }
}

/// Runs a worker until `shutdown` flips to true or an administrator STOP file appears.
pub async fn run_worker(
    setup: WorkerSetup,
    mut shutdown: watch::Receiver<bool>,
) -> Result<WorkerStatus, NodeError> {
    let id = setup.key.key_id();
    let operator = setup
        .manifest
        .operator_of(&id)
        .cloned()
        .ok_or_else(|| NodeError::Config("worker key not enrolled".into()))?;
    let topics = Topics::for_network(&setup.manifest.network_id);
    let keypair = keypair_from_seed(&setup.key.seed())?;
    let net_cfg = NetConfig {
        listen: setup.listen.clone(),
        bootstrap: setup.bootstrap.clone(),
        allowed_peers: allowed_peers(&setup.manifest, &id),
        subscribe: vec![topics.tasks.clone()],
        heartbeat: setup.gossip_heartbeat,
        outbound_bytes_per_sec: (setup.resources.outbound_kib_per_sec > 0)
            .then_some(setup.resources.outbound_kib_per_sec * 1024),
        ..NetConfig::default()
    };
    let net = cybermesh_network::spawn(keypair, net_cfg)?;
    std::fs::create_dir_all(&setup.state_dir).map_err(|e| NodeError::Io(e.to_string()))?;
    std::fs::create_dir_all(&setup.control_dir).map_err(|e| NodeError::Io(e.to_string()))?;
    info!(worker = %id.short(), %operator, peer = %net.local_peer_id, "worker started");

    let governor = Governor::new(setup.resources.clone(), &setup.control_dir);
    let (ct_done, mut ct_rx) = tokio::sync::mpsc::unbounded_channel::<CtDone>();
    let heartbeat_every = setup.heartbeat;
    let mut w = Worker {
        status: WorkerStatus {
            key_id: id.to_string(),
            operator: operator.to_string(),
            peer_id: net.local_peer_id.to_string(),
            state: "starting".into(),
            ..WorkerStatus::default()
        },
        id,
        operator,
        topics,
        limits: Limits::default(),
        replay: ReplayCache::new(50_000),
        queue: VecDeque::new(),
        engine_arc: Arc::new(setup.engine.clone()),
        ct_job: None,
        ct_hold: Arc::new(AtomicBool::new(false)),
        ct_done,
        outbox: VecDeque::new(),
        governor,
        cpu_resume_at: None,
        last_result: None,
        s: setup,
    };

    let mut manifest_tick = tokio::time::interval(Duration::from_secs(60));
    let mut hb = tokio::time::interval(heartbeat_every);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut last_status = Instant::now() - Duration::from_secs(10);
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
            ev = net.next_event() => {
                match ev {
                    Some(NetEvent::Message(m)) => {
                        if m.topic == w.topics.tasks {
                            w.on_task_message(&net, &m).await;
                        } else {
                            net.report(&m, Acceptance::Ignore).await;
                        }
                    }
                    Some(NetEvent::PeerConnected(p)) => debug!(%p, "peer connected"),
                    Some(NetEvent::PeerDisconnected(p)) => debug!(%p, "peer disconnected"),
                    Some(NetEvent::Listening(a)) => info!(%a, "listening"),
                    None => break,
                }
            }
            Some(done) = ct_rx.recv() => w.finish_ct(&net, done).await,
            _ = hb.tick() => w.heartbeat(&net).await,
            _ = manifest_tick.tick() => {
                if let Some(src) = w.s.manifest_source.clone() {
                    match files::reload_manifest(&src, &w.s.manifest, w.s.clock.now()) {
                        files::Reload::Updated(m) => {
                            info!(sequence = m.sequence, "loaded newer trust manifest");
                            if m.key_with_role(&w.id, cybermesh_protocol::Role::Worker).is_none() {
                                warn!("this worker's key is revoked or no longer enrolled; stopping");
                                break;
                            }
                            net.set_allowed(allowed_peers(&m, &w.id)).await;
                            if let Err(e) = files::persist_manifest_state(&w.s.state_dir.join("manifest-state.json"), &m) {
                                warn!(error = %e, "failed to persist manifest state");
                            }
                            w.s.manifest = m;
                        }
                        files::Reload::Equivocation => {
                            warn!("manifest with the current sequence but different content; ignored (report to governance)");
                        }
                        files::Reload::Unchanged => {}
                    }
                }
                if w.s.clock.now() >= w.s.manifest.expires_at {
                    w.status.state = "manifest-expired".into();
                }
            }
            _ = tick.tick() => {
                let now = w.s.clock.now();
                match w.governor.decide(now) {
                    Decision::Stop => {
                        info!("STOP requested by administrator");
                        break;
                    }
                    Decision::Pause(r) => {
                        w.ct_hold.store(true, Ordering::Relaxed);
                        if w.status.pause_reason != Some(r) {
                            info!(reason = ?r, "pausing");
                        }
                        w.status.pause_reason = Some(r);
                        w.status.state = "paused".into();
                    }
                    Decision::Run => {
                        let throttled = match w.cpu_resume_at {
                            Some(t) if Instant::now() < t => true,
                            _ => {
                                w.cpu_resume_at = w.governor.cpu_wait().map(|d| Instant::now() + d);
                                w.cpu_resume_at.is_some()
                            }
                        };
                        w.ct_hold.store(throttled, Ordering::Relaxed);
                        if throttled {
                            w.status.pause_reason = Some(PauseReason::CpuBudget);
                            w.status.state = "throttled".into();
                        } else {
                            w.status.pause_reason = None;
                            w.status.state = "active".into();
                            w.execute_next(&net).await;
                        }
                    }
                }
                w.flush_outbox(&net).await;
                if last_status.elapsed() >= Duration::from_secs(2) {
                    w.write_status(&net);
                    last_status = Instant::now();
                }
            }
        }
    }
    w.cancel_ct();
    w.status.state = "stopped".into();
    w.write_status(&net);
    net.shutdown().await;
    Ok(w.status)
}

#[cfg(test)]
mod tests {
    /// A default build must never honour an adversary configuration.
    #[cfg(not(feature = "adversary-sim"))]
    #[test]
    fn adversary_mode_is_not_compiled_into_default_builds() {
        assert!(!cfg!(feature = "adversary-sim"));
    }
}
