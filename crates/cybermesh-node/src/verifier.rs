//! Independent verifier node.
//!
//! An organisation other than the coordinator's runs this to verify the network's work
//! itself. It follows the issuer's signed tasks and the workers' signed results, settles every
//! task with its **own** engine, evidence, CT log access and secret spot-check seed, and
//! writes verification records signed with its **own** key. Release builders require records
//! from `min_verifiers` distinct verifier operators (trust manifest), so once that quorum is
//! 2 or more, neither the coordinator nor any other single verifier can publish an entry.
//!
//! It never issues or assigns tasks. Faults it proves go into its own records and its own
//! `reputation.json`; they do not change the coordinator's assignments.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cybermesh_analysis::{Engine, EvidenceBundle, engine_spec};
use cybermesh_crypto::{Digest, KeyId, SecretKey, random_bytes};
use cybermesh_network::{
    Acceptance, InboundMessage, NetConfig, NetEvent, NetworkHandle, Topics, keypair_from_seed,
};
use cybermesh_protocol::ct::verify_ct_task;
use cybermesh_protocol::replay::ReplayCache;
use cybermesh_protocol::validate::{peek_payload_type, verify_task};
use cybermesh_protocol::{Clock, Limits, ProtocolError, Role, TrustManifest, payload_type};
use cybermesh_verifier::ct::{CtPolicy, CtTaskVerifier};
use cybermesh_verifier::{
    Policy, ReputationBook, SubmitOutcome, TaskStatus, TaskVerifier, VerificationRecord, VerifierId,
};
use serde::Serialize;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::NodeError;
use crate::config::VerifierConfig;
use crate::coordinator::{
    AnyVerifier, MAX_CT_FINALIZING, finalize_ct, parse_result, persist_record, verifier_identity,
};
use crate::files;
use crate::worker::{allowed_peers, parse_addrs};

/// Results that arrive before their task (gossip does not order topics) are held briefly,
/// within count, byte and per-worker budgets.
const MAX_EARLY_RESULTS: usize = 1024;
const MAX_EARLY_BYTES: usize = 16 << 20;
const MAX_EARLY_PER_WORKER: usize = 32;
const EARLY_RESULT_TTL: Duration = Duration::from_secs(120);
/// Tasks followed at once (any enrolled issuer can publish tasks).
const MAX_PENDING_TASKS: usize = 1024;
/// Settled tasks remembered, so late results are dropped instead of buffered.
const MAX_SETTLED: usize = 20_000;
/// Tasks settled per 250 ms tick (domain tasks are recomputed on the event loop).
const MAX_SETTLES_PER_TICK: usize = 16;
/// CT verifications running or waiting for a permit; further CT tasks wait in `pending`.
const MAX_CT_QUEUED: usize = 8;

/// Everything an independent verifier needs to run.
#[derive(Debug)]
pub struct VerifierSetup {
    pub key: SecretKey,
    pub manifest: TrustManifest,
    pub engine: Engine,
    pub listen: Vec<cybermesh_network::Multiaddr>,
    pub bootstrap: Vec<cybermesh_network::Multiaddr>,
    pub state_dir: PathBuf,
    /// Settle a task this long after first seeing it (four times as long for CT tasks), or
    /// earlier when every assignee has answered.
    pub result_timeout: Duration,
    pub policy: Policy,
    pub ct_policy: CtPolicy,
    /// Secret seed for this verifier's own CT spot checks.
    pub ct_seed: [u8; 32],
    pub clock: Arc<dyn Clock>,
    pub gossip_heartbeat: Duration,
    pub manifest_source: Option<files::ManifestSource>,
    /// Exit after this long with nothing in flight, once at least one task was settled
    /// (tests and demos). `None`: run until stopped.
    pub idle_exit: Option<Duration>,
    /// With `idle_exit`: how long to keep waiting for the other verifiers' records of the
    /// tasks this verifier settled (when the manifest requires more than one verifier).
    pub records_wait: Duration,
}

/// Counters written to `verifier-report.json` on exit.
#[derive(Debug, Clone, Default, Serialize)]
pub struct VerifierReport {
    pub verifier: String,
    pub operator: String,
    pub tasks_seen: u64,
    pub tasks_rejected: u64,
    /// Tasks not followed because `MAX_PENDING_TASKS` were in flight.
    pub tasks_dropped: u64,
    /// Tasks whose engine or evidence differs from this verifier's. It cannot recompute
    /// them; their records say `recomputed: false` and do not count towards a release quorum
    /// of 2 or more.
    pub tasks_incompatible: u64,
    pub verified: u64,
    pub disputed: u64,
    pub insufficient: u64,
    pub faults: u64,
    pub results_accepted: u64,
    pub results_rejected: u64,
    pub results_replayed: u64,
    pub results_buffered_early: u64,
    /// Early results dropped because a budget was full, and late results for settled tasks.
    pub results_dropped: u64,
    /// Own records published on the `records` topic (including re-publications).
    pub records_published: u64,
    /// Own records too large for one network message (kept only as files).
    pub records_too_large: u64,
    /// Valid records of other verifiers received and stored in `received-records/`.
    pub records_received: u64,
    /// Records refused from the network (invalid, too old, from the future, store full).
    pub records_refused: u64,
    pub net_bytes_in: u64,
    pub net_bytes_out: u64,
    pub net_dropped_rate_limited: u64,
    pub net_dropped_queue_full: u64,
    /// CPU time of this process (ms), and what it received from CT logs (bytes after
    /// decompression, requests), for cost comparisons.
    pub cpu_ms: u64,
    pub ct_http_bytes: u64,
    pub ct_http_requests: u64,
    #[serde(skip)]
    pub records: Vec<(Digest, VerificationRecord)>,
    /// The other verifiers' records received (also in `received-records/`).
    #[serde(skip)]
    pub received: Vec<(Digest, VerificationRecord)>,
}

/// Loads a verifier from its configuration file.
pub fn setup_from_config(
    cfg: &VerifierConfig,
    clock: Arc<dyn Clock>,
) -> Result<VerifierSetup, NodeError> {
    let key = SecretKey::read_from_file(&cfg.key)?;
    let (manifest, _) = files::load_manifest_checked(
        &cfg.manifest,
        &cfg.governance_root,
        &cfg.state_dir.join("manifest-state.json"),
        clock.now(),
    )?;
    verifier_identity(&manifest, &key)?;
    cfg.policy.validate().map_err(NodeError::Config)?;
    Ok(VerifierSetup {
        key,
        engine: Engine::new(EvidenceBundle::load(&cfg.evidence_dir)?),
        manifest,
        listen: parse_addrs(&cfg.listen)?,
        bootstrap: parse_addrs(&cfg.bootstrap)?,
        state_dir: cfg.state_dir.clone(),
        result_timeout: Duration::from_secs(cfg.result_timeout_secs),
        policy: cfg.policy.clone(),
        ct_policy: cfg.ct_policy.clone(),
        ct_seed: random_bytes::<32>()?,
        clock,
        gossip_heartbeat: Duration::from_millis(700),
        manifest_source: Some(files::ManifestSource {
            manifest: cfg.manifest.clone(),
            governance_root: cfg.governance_root.clone(),
        }),
        idle_exit: cfg.idle_exit_secs.map(Duration::from_secs),
        records_wait: Duration::from_secs(cfg.records_wait_secs),
    })
}

/// (task id, attempt, task payload digest). The digest stops a different task that reuses
/// an id (from another enrolled issuer) from displacing the real one.
type TaskKey = (String, u32, Digest);

struct Pending {
    verifier: AnyVerifier,
    deadline: Instant,
}

/// A result held until its task arrives.
struct Early {
    at: Instant,
    worker: KeyId,
    payload_digest: Digest,
    bytes: Vec<u8>,
}

struct CtFinalized {
    record: Option<VerificationRecord>,
    missing: Vec<KeyId>,
}

struct Verifier {
    s: VerifierSetup,
    id: VerifierId,
    topics: Topics,
    limits: Limits,
    engine_arc: Arc<Engine>,
    pending: BTreeMap<TaskKey, Pending>,
    /// Settled tasks -> forget after (unix seconds).
    settled: HashMap<TaskKey, u64>,
    early: HashMap<TaskKey, Vec<Early>>,
    early_count: usize,
    early_bytes: usize,
    early_per_worker: HashMap<KeyId, usize>,
    early_order: VecDeque<(Instant, TaskKey)>,
    replay: ReplayCache,
    reputation: ReputationBook,
    report: VerifierReport,
    ct_permits: Arc<tokio::sync::Semaphore>,
    ct_done: tokio::sync::mpsc::UnboundedSender<CtFinalized>,
    ct_finalizing: usize,
    last_activity: Instant,
    records_in: crate::records::RecordStore,
    records_out: crate::records::RecordPublisher,
}

impl Verifier {
    fn persist_reputation(&self) {
        if let Err(e) =
            files::write_json(&self.s.state_dir.join("reputation.json"), &self.reputation)
        {
            warn!(error = %e, "failed to persist reputation");
        }
    }

    /// Authenticates a task message; returns its key, expiry and a verifier for it.
    fn parse_task(
        &mut self,
        data: &[u8],
        now: u64,
    ) -> Result<(TaskKey, u64, Result<AnyVerifier, ProtocolError>), ProtocolError> {
        let pins = &self.s.engine.evidence().pins;
        if peek_payload_type(data, &self.limits).as_deref() == Some(payload_type::CT_TASK) {
            let v = verify_ct_task(data, &self.s.manifest, now, &self.limits)?;
            let t = v.message;
            if t.engine != engine_spec() || &t.evidence != pins {
                self.report.tasks_incompatible += 1;
            }
            let key = (t.task_id.clone(), t.attempt, v.payload_digest);
            let exp = t.expires_at;
            let ver = CtTaskVerifier::new(
                t,
                v.payload_digest,
                self.id.clone(),
                self.s.ct_policy.clone(),
                self.s.policy.clone(),
                self.limits.clone(),
            )
            .map(AnyVerifier::Ct);
            Ok((key, exp, ver))
        } else {
            // `verify_task` accepts only domain-risk-assessment tasks.
            let v = verify_task(data, &self.s.manifest, now, &self.limits)?;
            let t = v.message;
            if t.engine != engine_spec() || &t.evidence != pins {
                self.report.tasks_incompatible += 1;
            }
            let key = (t.task_id.clone(), t.attempt, v.payload_digest);
            let exp = t.expires_at;
            let ver = TaskVerifier::new(
                t,
                v.payload_digest,
                self.id.clone(),
                self.s.policy.clone(),
                self.limits.clone(),
            )
            .map(AnyVerifier::Domain);
            Ok((key, exp, ver))
        }
    }

    async fn on_task(&mut self, net: &NetworkHandle, m: &InboundMessage) {
        let now = self.s.clock.now();
        if now >= self.s.manifest.expires_at {
            net.report(m, Acceptance::Ignore).await;
            return;
        }
        let (key, expires_at, verifier) = match self.parse_task(&m.data, now) {
            Ok(x) => x,
            Err(e) => {
                self.report.tasks_rejected += 1;
                debug!(error = %e, "rejected task message");
                let acc = match e {
                    ProtocolError::Expired | ProtocolError::NotYetValid => Acceptance::Ignore,
                    _ => Acceptance::Reject,
                };
                net.report(m, acc).await;
                return;
            }
        };
        if self.pending.contains_key(&key) || self.settled.contains_key(&key) {
            net.report(m, Acceptance::Ignore).await;
            return;
        }
        if self.pending.len() >= MAX_PENDING_TASKS {
            self.report.tasks_dropped += 1;
            warn!(task = %key.0, "too many tasks in flight; not following this one");
            net.report(m, Acceptance::Ignore).await;
            return;
        }
        let Ok(verifier) = verifier else {
            net.report(m, Acceptance::Ignore).await;
            return;
        };
        // Only tasks actually followed enter the replay cache.
        let forget = expires_at.saturating_add(self.limits.max_clock_skew_secs);
        if self.replay.check_and_insert(key.2, forget, now).is_err() {
            net.report(m, Acceptance::Ignore).await;
            return;
        }
        net.report(m, Acceptance::Accept).await;
        self.last_activity = Instant::now();
        self.report.tasks_seen += 1;
        let timeout = match verifier {
            AnyVerifier::Ct(_) => self.s.result_timeout * 4,
            AnyVerifier::Domain(_) => self.s.result_timeout,
        };
        self.pending.insert(
            key.clone(),
            Pending {
                verifier,
                deadline: Instant::now() + timeout,
            },
        );
        debug!(task = %key.0, attempt = key.1, "following task");
        // Results that arrived before the task.
        if let Some(early) = self.early.remove(&key) {
            for e in early {
                self.release_early_budget(&e);
                self.submit(&key, &e.bytes, e.payload_digest, now);
            }
        }
        self.settle_if_complete(&key);
    }

    fn release_early_budget(&mut self, e: &Early) {
        self.early_count = self.early_count.saturating_sub(1);
        self.early_bytes = self.early_bytes.saturating_sub(e.bytes.len());
        if let Some(n) = self.early_per_worker.get_mut(&e.worker) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.early_per_worker.remove(&e.worker);
            }
        }
    }

    fn submit(
        &mut self,
        key: &TaskKey,
        bytes: &[u8],
        payload_digest: Digest,
        now: u64,
    ) -> Option<SubmitOutcome> {
        let p = self.pending.get_mut(key)?;
        let forget = p.verifier.expires_at().saturating_add(3600);
        let outcome = p.verifier.submit(bytes, &self.s.manifest, now);
        match &outcome {
            SubmitOutcome::Accepted => {
                self.report.results_accepted += 1;
                // Only accepted results enter the replay cache, so rejected junk cannot
                // fill it and lock out new tasks.
                let _ = self.replay.check_and_insert(payload_digest, forget, now);
            }
            SubmitOutcome::Duplicate => {}
            SubmitOutcome::Rejected(r) => {
                self.report.results_rejected += 1;
                debug!(reason = %r, "result rejected");
            }
            SubmitOutcome::Fault(k) => {
                self.report.results_rejected += 1;
                warn!(kind = ?k, "result proves a fault");
            }
        }
        Some(outcome)
    }

    async fn on_result(&mut self, net: &NetworkHandle, m: &InboundMessage) {
        let now = self.s.clock.now();
        let meta = match parse_result(&m.data, &self.s.manifest, now, &self.limits) {
            Ok(v) => v,
            Err(e) => {
                self.report.results_rejected += 1;
                debug!(error = %e, "rejected result message");
                net.report(m, Acceptance::Reject).await;
                return;
            }
        };
        if self.replay.contains(&meta.payload_digest) {
            self.report.results_replayed += 1;
            net.report(m, Acceptance::Ignore).await;
            return;
        }
        let key = (meta.task_id, meta.attempt, meta.task_digest);
        if self.settled.contains_key(&key) {
            // Late: this verifier has already signed its record for the task.
            self.report.results_dropped += 1;
            net.report(m, Acceptance::Ignore).await;
            return;
        }
        self.last_activity = Instant::now();
        let Some(outcome) = self.submit(&key, &m.data, meta.payload_digest, now) else {
            self.buffer_early(key, meta.worker, meta.payload_digest, &m.data);
            net.report(m, Acceptance::Ignore).await;
            return;
        };
        let acc = match outcome {
            SubmitOutcome::Accepted => Acceptance::Accept,
            SubmitOutcome::Duplicate => Acceptance::Ignore,
            SubmitOutcome::Rejected(_) | SubmitOutcome::Fault(_) => Acceptance::Reject,
        };
        net.report(m, acc).await;
        self.settle_if_complete(&key);
    }

    /// Holds an authenticated result whose task has not arrived yet, within budgets.
    fn buffer_early(&mut self, key: TaskKey, worker: KeyId, payload_digest: Digest, bytes: &[u8]) {
        let per_worker = self.early_per_worker.get(&worker).copied().unwrap_or(0);
        if self.early_count >= MAX_EARLY_RESULTS
            || self.early_bytes.saturating_add(bytes.len()) > MAX_EARLY_BYTES
            || per_worker >= MAX_EARLY_PER_WORKER
        {
            self.report.results_dropped += 1;
            return;
        }
        let at = Instant::now();
        self.early_count += 1;
        self.early_bytes += bytes.len();
        self.early_per_worker.insert(worker.clone(), per_worker + 1);
        self.early.entry(key.clone()).or_default().push(Early {
            at,
            worker,
            payload_digest,
            bytes: bytes.to_vec(),
        });
        self.early_order.push_back((at, key));
        self.report.results_buffered_early += 1;
    }

    fn settle_if_complete(&mut self, key: &TaskKey) {
        if self
            .pending
            .get(key)
            .is_some_and(|p| p.verifier.is_complete())
        {
            self.settle(key);
        }
    }

    fn remember_settled(&mut self, key: TaskKey, forget_after: u64) {
        if self.settled.len() >= MAX_SETTLED {
            let now = self.s.clock.now();
            self.settled.retain(|_, f| *f > now);
        }
        if self.settled.len() < MAX_SETTLED {
            self.settled.insert(key, forget_after);
        }
    }

    fn settle(&mut self, key: &TaskKey) {
        let Some(p) = self.pending.remove(key) else {
            return;
        };
        let now = self.s.clock.now();
        let missing = p.verifier.missing();
        self.remember_settled(key.clone(), p.verifier.expires_at().saturating_add(3600));
        match p.verifier {
            AnyVerifier::Domain(v) => {
                let record = v.finalize(Some(&self.s.engine), now);
                self.apply_record(record, &missing);
            }
            AnyVerifier::Ct(v) => {
                self.ct_finalizing += 1;
                let log = self
                    .s
                    .engine
                    .evidence()
                    .ct_logs
                    .iter()
                    .find(|l| l.log_id == v.task().log_id)
                    .cloned();
                let engine = Arc::clone(&self.engine_arc);
                let seed = self.s.ct_seed;
                let permits = Arc::clone(&self.ct_permits);
                let tx = self.ct_done.clone();
                tokio::spawn(async move {
                    let _permit = permits.acquire_owned().await.ok();
                    let record = tokio::task::spawn_blocking(move || {
                        finalize_ct(v, &engine, log.as_ref(), &seed, now, None)
                    })
                    .await
                    .ok();
                    let _ = tx.send(CtFinalized { record, missing });
                });
            }
        }
    }

    /// Settles tasks past their deadline, a bounded number per tick. CT tasks wait while
    /// `MAX_CT_QUEUED` CT verifications are already running or queued.
    fn settle_due(&mut self) {
        let now = Instant::now();
        let ct_busy = self.ct_finalizing >= MAX_CT_QUEUED;
        let due: Vec<TaskKey> = self
            .pending
            .iter()
            .filter(|(_, p)| now >= p.deadline)
            .filter(|(_, p)| !(ct_busy && matches!(p.verifier, AnyVerifier::Ct(_))))
            .map(|(k, _)| k.clone())
            .take(MAX_SETTLES_PER_TICK)
            .collect();
        for k in due {
            if self.ct_finalizing >= MAX_CT_QUEUED
                && self
                    .pending
                    .get(&k)
                    .is_some_and(|p| matches!(p.verifier, AnyVerifier::Ct(_)))
            {
                continue;
            }
            self.settle(&k);
        }
    }

    fn apply_record(&mut self, record: VerificationRecord, missing: &[KeyId]) {
        self.last_activity = Instant::now();
        self.reputation.record_missed(missing);
        self.reputation.apply(&record);
        self.persist_reputation();
        self.report.faults += record.faults.len() as u64;
        match record.status {
            TaskStatus::Verified => self.report.verified += 1,
            TaskStatus::Disputed => self.report.disputed += 1,
            TaskStatus::Insufficient => self.report.insufficient += 1,
        }
        for f in &record.faults {
            warn!(worker = %f.worker.short(), operator = %f.operator, kind = ?f.kind, "provable fault");
        }
        match persist_record(&self.s.state_dir.join("records"), &record, &self.s.key) {
            Ok((d, env)) => {
                self.records_out.queue(env, record.verified_at);
                info!(task = %record.task_id, status = ?record.status, recomputed = record.recomputed, published = record.publishable().count(), "task verified independently");
                self.report.records.push((d, record));
            }
            Err(e) => warn!(error = %e, "failed to persist verification record"),
        }
    }

    /// Other verifier operators whose records each settled task needs for a release.
    fn records_needed(&self) -> usize {
        let quorum = usize::from(self.s.manifest.min_verifiers);
        let available = self.s.manifest.verifier_operators().len();
        quorum.min(available).saturating_sub(1)
    }

    async fn on_record(&mut self, net: &NetworkHandle, m: &InboundMessage) {
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

    fn expire_early_results(&mut self) {
        while let Some((at, _)) = self.early_order.front() {
            if at.elapsed() < EARLY_RESULT_TTL {
                break;
            }
            let Some((at, key)) = self.early_order.pop_front() else {
                break;
            };
            let Some(mut list) = self.early.remove(&key) else {
                continue;
            };
            let (expired, kept): (Vec<Early>, Vec<Early>) =
                list.drain(..).partition(|e| e.at == at);
            for e in &expired {
                self.release_early_budget(e);
            }
            if !kept.is_empty() {
                self.early.insert(key, kept);
            }
        }
        let now = self.s.clock.now();
        if self.settled.len() > MAX_SETTLED / 2 {
            self.settled.retain(|_, f| *f > now);
        }
    }
}

/// Runs an independent verifier until `shutdown` flips (or, with `idle_exit`, until idle).
pub async fn run_verifier(
    setup: VerifierSetup,
    mut shutdown: watch::Receiver<bool>,
) -> Result<VerifierReport, NodeError> {
    let id = verifier_identity(&setup.manifest, &setup.key)?;
    let topics = Topics::for_network(&setup.manifest.network_id);
    let keypair = keypair_from_seed(&setup.key.seed())?;
    let net_cfg = NetConfig {
        listen: setup.listen.clone(),
        bootstrap: setup.bootstrap.clone(),
        allowed_peers: allowed_peers(&setup.manifest, &id.key),
        subscribe: vec![
            topics.tasks.clone(),
            topics.results.clone(),
            topics.records.clone(),
        ],
        heartbeat: setup.gossip_heartbeat,
        // Same per-author allowance as the coordinator: results arrive in bursts.
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
    info!(verifier = %id.key.short(), operator = %id.operator, peer = %net.local_peer_id, "independent verifier started");
    let (ct_done, mut ct_rx) = tokio::sync::mpsc::unbounded_channel::<CtFinalized>();
    let max_message = Limits::default().max_envelope_bytes;
    let records_in = crate::records::RecordStore::open(
        &setup.state_dir.join("received-records"),
        id.key.clone(),
        &setup.manifest,
        max_message,
        setup.clock.now(),
    )?;
    let mut records_out = crate::records::RecordPublisher::new(max_message);
    records_out.load_recent(&setup.state_dir.join("records"), setup.clock.now());
    let mut v = Verifier {
        records_in,
        records_out,
        report: VerifierReport {
            verifier: id.key.to_string(),
            operator: id.operator.to_string(),
            ..VerifierReport::default()
        },
        engine_arc: Arc::new(setup.engine.clone()),
        id,
        topics,
        limits: Limits::default(),
        pending: BTreeMap::new(),
        settled: HashMap::new(),
        early: HashMap::new(),
        early_count: 0,
        early_bytes: 0,
        early_per_worker: HashMap::new(),
        early_order: VecDeque::new(),
        replay: ReplayCache::new(200_000),
        reputation,
        ct_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CT_FINALIZING)),
        ct_done,
        ct_finalizing: 0,
        last_activity: Instant::now(),
        s: setup,
    };
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut manifest_tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
            ev = net.next_event() => match ev {
                Some(NetEvent::Message(m)) => {
                    if m.topic == v.topics.tasks {
                        v.on_task(&net, &m).await;
                    } else if m.topic == v.topics.results {
                        v.on_result(&net, &m).await;
                    } else if m.topic == v.topics.records {
                        v.on_record(&net, &m).await;
                    } else {
                        net.report(&m, Acceptance::Ignore).await;
                    }
                }
                Some(NetEvent::Listening(a)) => info!(%a, "listening"),
                Some(_) => {}
                None => break,
            },
            Some(done) = ct_rx.recv() => {
                v.ct_finalizing = v.ct_finalizing.saturating_sub(1);
                match done.record {
                    Some(r) => v.apply_record(r, &done.missing),
                    None => warn!("CT verification failed internally; task dropped"),
                }
            }
            _ = manifest_tick.tick() => {
                v.records_in.prune(v.s.clock.now());
                if let Some(src) = v.s.manifest_source.clone() {
                    match files::reload_manifest(&src, &v.s.manifest, v.s.clock.now()) {
                        files::Reload::Updated(m) => {
                            info!(sequence = m.sequence, "loaded newer trust manifest");
                            if m.key_with_role(&v.id.key, Role::Verifier).is_none() {
                                warn!("this verifier's key is revoked or lost its role; stopping");
                                break;
                            }
                            net.set_allowed(allowed_peers(&m, &v.id.key)).await;
                            // Records of verifiers no longer enrolled are dropped.
                            if let Err(e) = v.records_in.rescan(&m, v.s.clock.now()) {
                                warn!(error = %e, "failed to re-check received records");
                            }
                            if let Err(e) = files::persist_manifest_state(&v.s.state_dir.join("manifest-state.json"), &m) {
                                warn!(error = %e, "failed to persist manifest state");
                            }
                            v.s.manifest = m;
                        }
                        files::Reload::Equivocation => {
                            warn!("manifest with the current sequence but different content; ignored");
                        }
                        files::Reload::Unchanged => {}
                    }
                }
            }
            _ = tick.tick() => {
                v.settle_due();
                v.expire_early_results();
                v.records_out.republish_due(
                    v.s.clock.now(),
                    crate::records::REPUBLISH_EVERY,
                    crate::records::REPUBLISH_WINDOW_SECS,
                );
                v.records_out.flush(&net, &v.topics.records).await;
                if let Some(idle) = v.s.idle_exit
                    && v.report.tasks_seen > 0
                    && v.pending.is_empty()
                    && v.ct_finalizing == 0
                    && (v.records_needed() == 0 || v.records_out.is_idle())
                    && v.last_activity.elapsed() >= idle
                {
                    // Stay for the other verifiers' records (bounded), so this organisation's
                    // release signer can build from this node alone.
                    let own: Vec<(String, Digest)> = v
                        .report
                        .records
                        .iter()
                        .map(|(_, r)| (r.task_id.clone(), r.task_digest))
                        .collect();
                    let complete = crate::records::quorum_records_present(
                        &v.records_in,
                        &own,
                        &v.id.operator,
                        v.records_needed(),
                    );
                    if complete || v.last_activity.elapsed() >= idle + v.s.records_wait {
                        if !complete {
                            warn!("leaving before every task has the other verifiers' records");
                        }
                        break;
                    }
                }
            }
        }
    }
    v.persist_reputation();
    v.report.records_published = v.records_out.published;
    v.report.records_too_large = v.records_out.too_large;
    v.report.received = std::mem::take(&mut v.records_in.received);
    let snap = net.stats.snapshot();
    v.report.net_bytes_in = snap.bytes_in;
    v.report.net_bytes_out = snap.bytes_out;
    v.report.net_dropped_rate_limited = snap.dropped_rate_limited;
    v.report.net_dropped_queue_full = snap.dropped_queue_full;
    v.report.cpu_ms = crate::governor::process_cpu_ms();
    (v.report.ct_http_bytes, v.report.ct_http_requests) = cybermesh_ct::http::transfer_totals();
    let _ = files::write_json(&v.s.state_dir.join("verifier-report.json"), &v.report);
    net.shutdown().await;
    Ok(v.report)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use cybermesh_analysis::EvidenceBundle;
    use cybermesh_protocol::SystemClock;
    use cybermesh_protocol::testkit::TestNetwork;

    use super::*;

    fn verifier() -> Verifier {
        let net = TestNetwork::new(&[("org-a", 1), ("org-b", 1), ("org-c", 1)], 1_800_000_000);
        let (key, op) = &net.other_verifiers[0];
        let (ct_done, _rx) = tokio::sync::mpsc::unbounded_channel();
        Verifier {
            s: VerifierSetup {
                key: SecretKey::from_seed(&key.seed()),
                manifest: net.manifest.clone(),
                engine: Engine::new(EvidenceBundle::default()),
                listen: vec![],
                bootstrap: vec![],
                state_dir: std::env::temp_dir(),
                result_timeout: Duration::from_secs(5),
                policy: Policy::default(),
                ct_policy: CtPolicy::default(),
                ct_seed: [1; 32],
                clock: Arc::new(SystemClock),
                gossip_heartbeat: Duration::from_millis(100),
                manifest_source: None,
                idle_exit: None,
                records_wait: Duration::from_secs(1),
            },
            id: VerifierId {
                key: key.key_id(),
                operator: op.clone(),
            },
            topics: Topics::for_network(&net.network_id),
            limits: Limits::default(),
            engine_arc: Arc::new(Engine::new(EvidenceBundle::default())),
            pending: BTreeMap::new(),
            settled: HashMap::new(),
            early: HashMap::new(),
            early_count: 0,
            early_bytes: 0,
            early_per_worker: HashMap::new(),
            early_order: VecDeque::new(),
            replay: ReplayCache::new(1000),
            reputation: ReputationBook::default(),
            report: VerifierReport::default(),
            ct_permits: Arc::new(tokio::sync::Semaphore::new(1)),
            ct_done,
            ct_finalizing: 0,
            last_activity: Instant::now(),
            records_in: crate::records::RecordStore::open(
                &std::env::temp_dir().join(format!("cm-records-{}", std::process::id())),
                key.key_id(),
                &net.manifest,
                256 * 1024,
                1_800_000_000,
            )
            .unwrap(),
            records_out: crate::records::RecordPublisher::new(256 * 1024),
        }
    }

    fn key(i: u32) -> TaskKey {
        (format!("{i:032x}"), 0, Digest::of(&i.to_be_bytes()))
    }

    #[test]
    fn early_results_are_bounded_per_worker_and_in_bytes() {
        let mut v = verifier();
        let w1 = SecretKey::from_seed(&[1; 32]).key_id();
        let w2 = SecretKey::from_seed(&[2; 32]).key_id();
        // One worker cannot take more than its share, whatever task ids it invents.
        for i in 0..100 {
            v.buffer_early(key(i), w1.clone(), Digest::of(&[1]), b"x");
        }
        assert_eq!(v.early_count, MAX_EARLY_PER_WORKER);
        assert_eq!(v.report.results_dropped, 100 - MAX_EARLY_PER_WORKER as u64);
        // A byte budget bounds memory regardless of how many workers send.
        let big = vec![0u8; MAX_EARLY_BYTES / 2 + 1];
        v.buffer_early(key(1000), w2.clone(), Digest::of(&[2]), &big);
        v.buffer_early(key(1001), w2.clone(), Digest::of(&[3]), &big);
        assert!(v.early_bytes <= MAX_EARLY_BYTES);
        assert_eq!(v.early_per_worker.get(&w2), Some(&1));
        // Draining releases the budget.
        let drained = v.early.remove(&key(1000)).unwrap();
        for e in &drained {
            v.release_early_budget(e);
        }
        assert_eq!(v.early_per_worker.get(&w2), None);
        assert_eq!(v.early_count, MAX_EARLY_PER_WORKER);
    }
}
