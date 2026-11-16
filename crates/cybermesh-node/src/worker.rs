//! The worker runtime.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cybermesh_analysis::{Engine, EvidenceBundle, engine_spec};
use cybermesh_crypto::{Digest, Envelope, KeyId, SecretKey, canonical, generate_nonce};
use cybermesh_network::{Acceptance, NetConfig, NetEvent, NetworkHandle, Topics, keypair_from_seed, peer_id_of};
use cybermesh_protocol::replay::ReplayCache;
use cybermesh_protocol::validate::verify_task;
use cybermesh_protocol::{
    Clock, Heartbeat, Limits, OperatorId, PROTOCOL_VERSION, ProtocolError, ResourceUsage,
    TaskAnnouncement, TaskResult, TrustManifest, WorkerState, payload_type,
};
use serde::Serialize;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::NodeError;
use crate::config::WorkerConfig;
use crate::files;
use crate::governor::{Decision, Governor, PauseReason, ResourcePolicy, ResourceSnapshot, process_cpu};

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
pub fn setup_from_config(cfg: &WorkerConfig, clock: Arc<dyn Clock>) -> Result<WorkerSetup, NodeError> {
    let key = SecretKey::read_from_file(&cfg.key)?;
    let (manifest, _root) = files::load_manifest(&cfg.manifest, &cfg.governance_root, clock.now())?;
    if manifest.network_id != cfg.network_id {
        return Err(NodeError::Config("manifest is for a different network".into()));
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
struct Worker {
    s: WorkerSetup,
    id: KeyId,
    operator: OperatorId,
    topics: Topics,
    limits: Limits,
    replay: ReplayCache,
    queue: VecDeque<(TaskAnnouncement, Digest)>,
    outbox: VecDeque<Outgoing>,
    governor: Governor,
    status: WorkerStatus,
    cpu_resume_at: Option<Instant>,
    #[allow(dead_code)]
    last_result: Option<Vec<u8>>,
}

impl Worker {
    async fn on_task_message(&mut self, net: &NetworkHandle, m: &cybermesh_network::InboundMessage) {
        let now = self.s.clock.now();
        let v = match verify_task(&m.data, &self.s.manifest, now, &self.limits) {
            Ok(v) => v,
            Err(e) => {
                self.status.messages_rejected += 1;
                let acc = match e {
                    ProtocolError::Expired | ProtocolError::NotYetValid => Acceptance::Ignore,
                    _ => Acceptance::Reject,
                };
                debug!(error = %e, "rejected task message");
                net.report(m, acc).await;
                return;
            }
        };
        let forget = v.message.expires_at + self.limits.max_clock_skew_secs;
        if self.replay.check_and_insert(v.payload_digest, forget, now).is_err() {
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
        self.queue.push_back((v.message, v.payload_digest));
    }

    fn build_result(&mut self, task: &TaskAnnouncement, digest: Digest) -> Result<TaskResult, String> {
        let cpu0 = process_cpu();
        let t0 = Instant::now();
        let assessments = self
            .s
            .engine
            .assess_task(task)
            .map_err(|e| e.to_string())?;
        let usage = ResourceUsage {
            cpu_micros: u64::try_from(process_cpu().saturating_sub(cpu0).as_micros()).unwrap_or(u64::MAX),
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
        let Some((task, digest)) = self.queue.pop_front() else {
            return;
        };
        let now = self.s.clock.now();
        if task.expires_at <= now {
            return;
        }
        match self.build_result(&task, digest) {
            Ok(result) => {
                #[allow(unused_mut)]
                let mut messages = vec![self.sign(&result)];
                #[cfg(feature = "adversary-sim")]
                if let Some(mode) = &self.s.adversary {
                    messages = crate::adversary::apply(mode, &result, &self.s.key, self.last_result.as_deref());
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
        if net.publish(&self.topics.results, bytes.clone()).await.is_err() && self.outbox.len() < 64 {
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
            if net.publish(&self.topics.results, o.bytes.clone()).await.is_err() {
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
        };
        let Ok(bytes) = canonical::to_vec(&hb) else { return };
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
        outbox: VecDeque::new(),
        governor,
        cpu_resume_at: None,
        last_result: None,
        s: setup,
    };

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
            _ = hb.tick() => w.heartbeat(&net).await,
            _ = tick.tick() => {
                let now = w.s.clock.now();
                match w.governor.decide(now) {
                    Decision::Stop => {
                        info!("STOP requested by administrator");
                        break;
                    }
                    Decision::Pause(r) => {
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
    w.status.state = "stopped".into();
    w.write_status(&net);
    net.shutdown().await;
    Ok(w.status)
}
