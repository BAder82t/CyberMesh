//! The coordinator: approved task issuer and independent result verifier.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cybermesh_analysis::{Engine, EvidenceBundle, engine_spec, normalize_domain};
use cybermesh_crypto::{
    Digest, Envelope, KeyId, SecretKey, canonical, generate_nonce, random_bytes,
};
use cybermesh_network::{
    Acceptance, NetConfig, NetEvent, NetworkHandle, Topics, keypair_from_seed,
};
use cybermesh_protocol::replay::ReplayCache;
use cybermesh_protocol::validate::{verify_heartbeat, verify_result};
use cybermesh_protocol::{
    Clock, Limits, OperatorId, PROTOCOL_VERSION, Role, TaskAnnouncement, TaskKind, TrustManifest,
    WorkerState, payload_type,
};
use cybermesh_verifier::{
    Policy, ReputationBook, SubmitOutcome, TaskStatus, TaskVerifier, VerificationRecord,
};
use serde::Serialize;
use tokio::sync::watch;
use tracing::{debug, info, warn};

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
    pub policy: Policy,
    pub clock: Arc<dyn Clock>,
    pub gossip_heartbeat: Duration,
    /// Reload the manifest from here every minute (None in tests).
    pub manifest_source: Option<files::ManifestSource>,
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
    let (manifest, _) = files::load_manifest(&cfg.manifest, &cfg.governance_root, clock.now())?;
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
            abandon_after: Duration::from_secs(cfg.result_timeout_secs.saturating_mul(10).max(30)),
            policy: cfg.policy.clone(),
            clock,
            gossip_heartbeat: Duration::from_millis(700),
            manifest_source: Some(files::ManifestSource {
                manifest: cfg.manifest.clone(),
                governance_root: cfg.governance_root.clone(),
            }),
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
}

#[derive(Debug, Clone)]
struct Batch {
    domains: Vec<String>,
    attempt: u32,
    queued_at: Instant,
    exclude: BTreeSet<KeyId>,
    first_issued: Option<Instant>,
}

struct Inflight {
    verifier: TaskVerifier,
    deadline: Instant,
    batch: Batch,
}

fn rendezvous(task_id: &str, item: &[u8]) -> Digest {
    Digest::tagged("cybermesh/assign/v1", &[task_id.as_bytes(), item])
}

/// Signs and stores a verification record; returns its payload digest.
pub fn persist_record(
    dir: &Path,
    record: &VerificationRecord,
    verifier: &SecretKey,
) -> Result<Digest, NodeError> {
    let bytes = canonical::to_vec(record)?;
    let env = Envelope::sign(payload_type::VERIFICATION, &bytes, verifier);
    let path = dir.join(format!("{}-{}.json", record.task_id, record.attempt));
    files::write_atomic(&path, &env.to_vec()?)?;
    Ok(Digest::of(&bytes))
}

/// What the coordinator remembers about a settled task to prove late equivocation.
struct SettledTask {
    forget_after: u64,
    task_digest: Digest,
    attempt: u32,
    accepted: BTreeMap<KeyId, Digest>,
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

    fn choose_assignees(&self, task_id: &str, exclude: &BTreeSet<KeyId>) -> Option<Vec<KeyId>> {
        let now = self.s.clock.now();
        let mut per_op: BTreeMap<&OperatorId, (Digest, &KeyId)> = BTreeMap::new();
        for (k, w) in &self.workers {
            let eligible = w.active
                && w.compatible
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
        let required = self.s.policy.min_operators.max(1);
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
                .take(self.s.replication.max(required))
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
        let Some(assignees) = self
            .choose_assignees(&task_id, &avoid)
            .or_else(|| self.choose_assignees(&task_id, &BTreeSet::new()))
        else {
            return Err(batch);
        };
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
            self.s.policy.clone(),
            self.limits.clone(),
        ) else {
            return Err(batch);
        };
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

    fn settle(&mut self, task_id: &str) {
        let Some(inf) = self.inflight.remove(task_id) else {
            return;
        };
        let missing = inf.verifier.missing();
        let assignees = inf.verifier.task().assignees.clone();
        let forget_after = inf.verifier.task().expires_at.saturating_add(3600);
        let task_digest = inf.verifier.task_digest();
        let attempt = inf.verifier.task().attempt;
        let now = self.s.clock.now();
        let record = inf.verifier.finalize(Some(&self.s.engine), now);
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
            Ok(d) => self.report.records.push((d, record.clone())),
            Err(e) => warn!(error = %e, "failed to persist verification record"),
        }
        let retry = record.status != TaskStatus::Verified
            && (inf.batch.attempt as usize + 1) < self.s.max_attempts;
        if retry {
            let mut b = inf.batch.clone();
            b.attempt += 1;
            b.queued_at = Instant::now();
            // Exclude non-responders and faulted workers from the next attempt.
            b.exclude.extend(missing);
            b.exclude
                .extend(record.faults.iter().map(|f| f.worker.clone()));
            info!(task = %task_id, status = ?record.status, next_attempt = b.attempt, "reassigning");
            self.report.reassignments += 1;
            self.pending.push_front(b);
        } else if let Some(t) = inf.batch.first_issued {
            self.report
                .settle_latency_ms
                .push(u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX));
        }
        let _ = assignees;
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
                        .map(|a| (a.worker.clone(), a.result_digest))
                        .collect(),
                },
            );
        }
        info!(task = %task_id, status = ?record.status, recomputed = record.recomputed, published = record.publishable().count(), "task settled");
    }

    async fn on_result(&mut self, net: &NetworkHandle, m: &cybermesh_network::InboundMessage) {
        let now = self.s.clock.now();
        let v = match verify_result(&m.data, &self.s.manifest, now, &self.limits) {
            Ok(v) => v,
            Err(e) => {
                self.report.results_rejected += 1;
                warn!(error = %e, "rejected result message");
                net.report(m, Acceptance::Reject).await;
                return;
            }
        };
        if self.replay.contains(&v.payload_digest) {
            self.report.results_replayed += 1;
            net.report(m, Acceptance::Ignore).await;
            return;
        }
        let task_id = v.message.task_id.clone();
        let Some(inf) = self.inflight.get_mut(&task_id) else {
            // Late result for a settled task: a different signed result from a worker whose
            // result was already accepted is provable equivocation.
            // Only a second result for the *same* task payload and attempt proves
            // equivocation; a result answering a different payload (e.g. another issuer
            // re-using the task id) proves nothing about this worker.
            let prior = self
                .settled
                .get(&task_id)
                .filter(|s| {
                    s.task_digest == v.message.task_digest && s.attempt == v.message.attempt
                })
                .and_then(|s| s.accepted.get(&v.message.worker))
                .copied();
            let _ = self
                .replay
                .check_and_insert(v.payload_digest, now.saturating_add(3600), now);
            if let Some(prior) = prior
                && prior != v.payload_digest
                && !self.reputation.is_quarantined(&v.message.worker)
            {
                let fault = cybermesh_verifier::FaultRecord {
                    worker: v.message.worker.clone(),
                    operator: v.message.operator.clone(),
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
        let forget = inf.verifier.task().expires_at + 3600;
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
                net.report(m, Acceptance::Reject).await;
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
                    },
                );
                net.report(m, Acceptance::Accept).await;
            }
            Err(e) => {
                debug!(error = %e, "rejected heartbeat");
                net.report(m, Acceptance::Reject).await;
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
        subscribe: vec![topics.results.clone(), topics.presence.clone()],
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
    let pending: VecDeque<Batch> = setup
        .domains
        .chunks(setup.batch_size.max(1))
        .map(|c| Batch {
            domains: c.to_vec(),
            attempt: 0,
            queued_at: Instant::now(),
            exclude: BTreeSet::new(),
            first_issued: None,
        })
        .collect();
    info!(peer = %net.local_peer_id, batches = pending.len(), domains = setup.domains.len(), "coordinator started");
    let mut c = Coordinator {
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
    let mut tick = tokio::time::interval(Duration::from_millis(250));
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
                    } else if m.topic == c.topics.presence {
                        c.on_heartbeat(&net, &m).await;
                    } else {
                        net.report(&m, Acceptance::Ignore).await;
                    }
                }
                Some(NetEvent::Listening(a)) => info!(%a, "listening"),
                Some(_) => {}
                None => break,
            },
            _ = manifest_tick.tick() => {
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
                            // Revoked workers disappear from assignment immediately.
                            c.workers.retain(|k, _| m.key_with_role(k, Role::Worker).is_some());
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
                let mut attempts = c.pending.len();
                let manifest_valid = c.s.clock.now() < c.s.manifest.expires_at;
                while manifest_valid && c.inflight.len() < c.s.max_inflight && attempts > 0 {
                    attempts -= 1;
                    let Some(b) = c.pending.pop_front() else { break };
                    if let Err(b) = c.issue(&net, b).await {
                        if b.queued_at.elapsed() >= c.s.abandon_after {
                            warn!(domains = b.domains.len(), attempt = b.attempt, "abandoning batch: not enough distinct operators available");
                            c.report.domains_abandoned += b.domains.len();
                        } else {
                            c.pending.push_back(b);
                        }
                    }
                }
                if c.s.exit_when_done && c.pending.is_empty() && c.inflight.is_empty() {
                    break;
                }
            }
        }
    }
    let _ = files::write_json(&rep_path, &c.reputation);
    let snap = net.stats.snapshot();
    c.report.net_bytes_in = snap.bytes_in;
    c.report.net_bytes_out = snap.bytes_out;
    c.report.net_dropped_rate_limited = snap.dropped_rate_limited;
    c.report.net_dropped_queue_full = snap.dropped_queue_full;
    let _ = files::write_json(&c.s.state_dir.join("coordinator-report.json"), &c.report);
    net.shutdown().await;
    Ok(c.report)
}
