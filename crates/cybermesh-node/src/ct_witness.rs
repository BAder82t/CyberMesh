//! Witnessing CT logs: catching a log that shows organisations different trees.
//!
//! A CT log could show one tree to some organisations and another tree to others (a *split
//! view*), for example to hide a certificate from the monitors that would flag it. One
//! organisation checking its own successive checkpoints cannot see this. Organisations that
//! compare their views can, and the two signed checkpoints then prove it.
//!
//! Each verifier node (the coordinator and every independent verifier) that witnesses a log:
//! - polls the log's checkpoint, accepts it only if it is signed by the pinned key, fresh,
//!   and consistent with the last one it accepted, and persists it (`ct-witness.json`);
//! - cosigns it (C2SP `cosignature/v1`, [`cybermesh_ct::witness`]) and publishes it on the
//!   `checkpoints` topic, signed as a [`CheckpointObservation`];
//! - compares every peer's observation with its own view, using hash tiles authenticated
//!   against its own checkpoint ([`cybermesh_ct::LogAuthenticator::consistency_with`]).
//!
//! When two checkpoints signed by the log cannot belong to one append-only log, the node
//! writes a [`SplitViewProof`] that anyone can check offline (`cybermesh ct
//! verify-split-view`) and reports it, so that the caller stops relying on the log. It stops
//! comparing, but keeps publishing its own view (still consistent with everything it
//! cosigned), so organisations that share its view see the conflict too. A comparison whose
//! tiles cannot be read or do not match proves nothing and is retried a few times.
//!
//! Cost bounds: one checkpoint request per log per poll; per peer and log, at most one
//! pending observation and one comparison per [`CHECK_EVERY`]; a comparison downloads a few
//! hash tiles of the node's own (larger) checkpoint, cached across the observations it
//! compares.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cybermesh_analysis::CtLogInfo;
use cybermesh_crypto::{Envelope, KeyId, SecretKey, canonical};
use cybermesh_ct::checkpoint::{MAX_CHECKPOINT_AGE_SECS, MAX_CHECKPOINT_SKEW_SECS, check_fresh};
use cybermesh_ct::witness::{SplitViewProof, cosign, verify_cosignature};
use cybermesh_ct::{Checkpoint, CtError, LogKey, TileSource, verify_checkpoint};
use cybermesh_network::{Acceptance, NetworkHandle};
use cybermesh_protocol::ct::{
    CT_CHECKPOINT, CheckpointObservation, verify_checkpoint_observation, witness_key_name,
};
use cybermesh_protocol::{Limits, PROTOCOL_VERSION, Role, TrustManifest};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::{NodeError, files};

pub const DEFAULT_POLL_SECS: u64 = 60;
pub const DEFAULT_PUBLISH_SECS: u64 = 300;
/// Peers' checkpoints signed longer ago than this are not compared (witnesses report their
/// latest checkpoint).
pub const MAX_PEER_CHECKPOINT_AGE_SECS: u64 = 86_400;
/// A peer's observation of a log is compared at most this often.
pub const CHECK_EVERY: Duration = Duration::from_secs(60);
/// Comparisons that could not be completed are tried this many times.
const MAX_ATTEMPTS: u32 = 3;
/// (size, root) pairs remembered per log as consistent with this node's view.
const MAX_CHECKED: usize = 4096;
/// Observations compared per job.
const MAX_PER_JOB: usize = 8;
/// A comparison job stops starting new comparisons after this long (the rest count as
/// inconclusive), so a slow or hostile log cannot hold its job slot indefinitely.
const JOB_BUDGET: Duration = Duration::from_secs(120);
/// Witnesses tracked per log (a safety cap; the manifest bounds the verifiers).
const MAX_PEERS_PER_LOG: usize = 256;
/// Timeout of each request to a log.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Logs to witness and how often.
#[derive(Debug, Clone)]
pub struct WitnessSetup {
    pub logs: Vec<CtLogInfo>,
    pub poll: Duration,
    pub publish: Duration,
}

/// Counters for the node's report.
#[derive(Debug, Clone, Default, Serialize)]
pub struct WitnessStats {
    /// Own checkpoints accepted (signed, fresh and consistent with the previous one).
    pub checkpoints_accepted: u64,
    /// Polls that failed (log unavailable, unverifiable or stale checkpoint).
    pub polls_failed: u64,
    /// Cosigned observations published.
    pub published: u64,
    /// Peers' observations accepted, and refused.
    pub received: u64,
    pub refused: u64,
    /// Comparisons with this node's view that showed one append-only log.
    pub consistent: u64,
    /// Comparisons that could not be completed (hash tiles unavailable or not matching).
    pub inconclusive: u64,
    /// Split views proven, and the files holding the proofs.
    pub split_views: u64,
    pub proofs: Vec<String>,
}

/// A newly proven split view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitView {
    pub log_id: String,
    pub proof_file: PathBuf,
}

/// A proof file (`ct-split-views/*.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitViewEvidence {
    pub log_id: String,
    pub detected_at: u64,
    /// The node that found it.
    pub detected_by: KeyId,
    /// The witness whose observation showed the other view (`None`: the log contradicted
    /// itself in this node's own view).
    pub reported_by: Option<KeyId>,
    /// That witness's signed observation (DSSE envelope JSON).
    pub observation: Option<String>,
    pub proof: SplitViewProof,
}

#[derive(Debug, Clone)]
struct Head {
    note: String,
    cp: Checkpoint,
}

#[derive(Debug, Clone)]
struct PeerObs {
    note: String,
    cp: Checkpoint,
    envelope: String,
    attempts: u32,
    last_try: Option<Instant>,
}

struct LogState {
    info: CtLogInfo,
    key: LogKey,
    head: Option<Head>,
    /// A saved checkpoint that no longer verifies with the pinned key: the log is not
    /// witnessed (its no-regress guarantee would be lost), and the note is kept as saved.
    stale_head: Option<String>,
    /// The proof of a split view, once proven.
    proof: Option<SplitViewEvidence>,
    pending: BTreeMap<KeyId, PeerObs>,
    checked: HashSet<(u64, [u8; 32])>,
    next_poll: Instant,
    next_publish: Instant,
    busy: bool,
    split: bool,
}

/// `ct-witness.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Persisted {
    logs: BTreeMap<String, PersistedLog>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedLog {
    /// The last accepted checkpoint, as signed by the log.
    head: Option<String>,
    /// A split view was proven: the log is not relied on until this is cleared.
    #[serde(default)]
    split: bool,
    /// The proof, also kept here in case its file could not be written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof: Option<SplitViewEvidence>,
}

/// Blocking work for one log, run by [`run_job`] off the event loop.
#[derive(Debug, Clone)]
pub struct Job {
    log_id: String,
    info: CtLogInfo,
    head: Option<Head>,
    compare: Vec<(KeyId, PeerObs)>,
}

/// The result of a [`Job`].
#[derive(Debug)]
pub struct JobOutcome {
    log_id: String,
    result: Outcome,
}

#[derive(Debug)]
enum Outcome {
    Polled(Result<Polled, String>),
    Compared(Vec<(KeyId, PeerObs, Compared)>),
}

#[derive(Debug)]
enum Polled {
    Advanced(Head),
    Unchanged,
    Split(SplitViewProof),
}

#[derive(Debug)]
enum Compared {
    Consistent,
    Split(SplitViewProof),
    Inconclusive(String),
}

/// Fetches and checks the log's checkpoint against `head`.
fn poll(
    src: &dyn TileSource,
    key: &LogKey,
    head: Option<&Head>,
    now: u64,
) -> Result<Polled, CtError> {
    let note = src.checkpoint()?;
    let cp = verify_checkpoint(&note, key)?;
    check_fresh(&cp, now, MAX_CHECKPOINT_AGE_SECS)?;
    let Some(h) = head else {
        return Ok(Polled::Advanced(Head { note, cp }));
    };
    let (larger, smaller, grew) = if cp.size >= h.cp.size {
        ((&note, &cp), (&h.note, &h.cp), cp.size > h.cp.size)
    } else {
        ((&h.note, &h.cp), (&note, &cp), false)
    };
    let c = cybermesh_ct::authenticator(src, larger.1.clone()).consistency_with(smaller.1)?;
    Ok(
        match SplitViewProof::new(key.origin(), larger.0, smaller.0, &c) {
            Some(p) => Polled::Split(p),
            None if grew => Polled::Advanced(Head { note, cp }),
            None => Polled::Unchanged,
        },
    )
}

/// Runs a job against `src`, the log's tiles (blocking).
pub fn run_job(job: Job, src: &dyn TileSource, now: u64) -> JobOutcome {
    let result = match LogKey::from_info(&job.info) {
        Err(e) => Outcome::Polled(Err(e.to_string())),
        Ok(key) if job.compare.is_empty() => {
            Outcome::Polled(poll(src, &key, job.head.as_ref(), now).map_err(|e| e.to_string()))
        }
        Ok(key) => {
            let mut out = Vec::new();
            match &job.head {
                None => {
                    for (w, o) in job.compare {
                        out.push((w, o, Compared::Inconclusive("no own checkpoint".into())));
                    }
                }
                Some(h) => {
                    let auth = cybermesh_ct::authenticator(src, h.cp.clone());
                    let started = std::time::Instant::now();
                    for (w, o) in job.compare {
                        if started.elapsed() > JOB_BUDGET {
                            out.push((
                                w,
                                o,
                                Compared::Inconclusive("job time budget used up".into()),
                            ));
                            continue;
                        }
                        let r = match auth.consistency_with(&o.cp) {
                            Err(e) => Compared::Inconclusive(e.to_string()),
                            Ok(c) => {
                                match SplitViewProof::new(key.origin(), &h.note, &o.note, &c) {
                                    Some(p) => Compared::Split(p),
                                    None => Compared::Consistent,
                                }
                            }
                        };
                        out.push((w, o, r));
                    }
                }
            }
            Outcome::Compared(out)
        }
    };
    JobOutcome {
        log_id: job.log_id,
        result,
    }
}

/// Runs a job against the log over HTTPS (blocking).
#[must_use]
pub fn run_job_http(job: Job, now: u64) -> JobOutcome {
    match cybermesh_ct::http::open_log(&job.info, HTTP_TIMEOUT) {
        Ok(src) => run_job(job, &*src, now),
        Err(e) => JobOutcome {
            log_id: job.log_id,
            result: if job.compare.is_empty() {
                Outcome::Polled(Err(e.to_string()))
            } else {
                Outcome::Compared(
                    job.compare
                        .into_iter()
                        .map(|(w, o)| (w, o, Compared::Inconclusive(e.to_string())))
                        .collect(),
                )
            },
        },
    }
}

/// Most logs one node witnesses.
pub const MAX_WITNESSED_LOGS: usize = 16;

/// The witnessing setup from configuration: `cfg.logs` plus `followed` (the coordinator's
/// followed log), all from the pinned `ct-logs` evidence. `None` if there is nothing to
/// witness.
pub fn setup_from_config(
    cfg: Option<&crate::config::CtWitnessConfig>,
    followed: Option<&str>,
    evidence: &cybermesh_analysis::EvidenceBundle,
) -> Result<Option<WitnessSetup>, NodeError> {
    let default = crate::config::CtWitnessConfig::default();
    let c = cfg.unwrap_or(&default);
    let mut ids: Vec<&str> = c.logs.iter().map(String::as_str).collect();
    ids.extend(followed);
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return Ok(None);
    }
    if ids.len() > MAX_WITNESSED_LOGS {
        return Err(NodeError::Config(format!(
            "ct_witness: at most {MAX_WITNESSED_LOGS} logs"
        )));
    }
    if !(10..=3600).contains(&c.poll_secs) || !(60..=3600).contains(&c.publish_secs) {
        return Err(NodeError::Config(
            "ct_witness: poll_secs must be 10..=3600 and publish_secs 60..=3600".into(),
        ));
    }
    let logs = ids
        .iter()
        .map(|id| {
            evidence
                .ct_logs
                .iter()
                .find(|l| l.log_id == *id)
                .cloned()
                .ok_or_else(|| {
                    NodeError::Config(format!(
                        "ct_witness: log {id} is not in the ct-logs evidence"
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(WitnessSetup {
        logs,
        poll: Duration::from_secs(c.poll_secs),
        publish: Duration::from_secs(c.publish_secs),
    }))
}

/// Witnessing state of one node.
pub struct Witness {
    key: SecretKey,
    id: KeyId,
    name: String,
    network_id: String,
    poll: Duration,
    publish: Duration,
    logs: BTreeMap<String, LogState>,
    state_path: PathBuf,
    /// Saved state of logs not configured now, carried through unchanged.
    others: BTreeMap<String, PersistedLog>,
    proofs_dir: PathBuf,
    limits: Limits,
    pub stats: WitnessStats,
}

impl std::fmt::Debug for Witness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Witness")
            .field("name", &self.name)
            .field("logs", &self.logs.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Witness {
    /// Witnesses `setup.logs` with `key` (a verifier key), keeping state in `state_dir`.
    pub fn new(
        setup: &WitnessSetup,
        key: &SecretKey,
        network_id: &str,
        state_dir: &Path,
    ) -> Result<Self, NodeError> {
        let state_path = state_dir.join("ct-witness.json");
        let mut persisted: Persisted = if state_path.exists() {
            files::read_json(&state_path)?
        } else {
            Persisted::default()
        };
        let now = Instant::now();
        let mut logs = BTreeMap::new();
        for info in &setup.logs {
            let key = LogKey::from_info(info)
                .map_err(|e| NodeError::Config(format!("{}: {e}", info.log_id)))?;
            let saved = persisted.logs.remove(&info.log_id).unwrap_or_default();
            let (mut head, mut stale_head) = (None, None);
            if let Some(note) = saved.head {
                match verify_checkpoint(&note, &key) {
                    Ok(cp) => head = Some(Head { note, cp }),
                    Err(e) => {
                        // Starting afresh would lose the guarantee never to cosign a tree
                        // inconsistent with one cosigned before.
                        error!(log = %info.log_id, error = %e, state = %state_path.display(),
                            "the saved witness checkpoint no longer verifies with the pinned key (key or origin changed?); this log is not witnessed. After checking the log's new key, remove its entry from the state file");
                        stale_head = Some(note);
                    }
                }
            }
            if saved.split {
                warn!(log = %info.log_id, "a split view of this log was proven earlier; it is not relied on (see ct-split-views/)");
            }
            logs.insert(
                info.log_id.clone(),
                LogState {
                    info: info.clone(),
                    key,
                    head,
                    stale_head,
                    proof: saved.proof,
                    pending: BTreeMap::new(),
                    checked: HashSet::new(),
                    next_poll: now,
                    next_publish: now,
                    busy: false,
                    split: saved.split,
                },
            );
        }
        let id = key.key_id();
        Ok(Self {
            key: SecretKey::from_seed(&key.seed()),
            name: witness_key_name(network_id, &id),
            id,
            network_id: network_id.to_owned(),
            poll: setup.poll,
            publish: setup.publish,
            logs,
            state_path,
            others: persisted.logs,
            proofs_dir: state_dir.join("ct-split-views"),
            limits: Limits::default(),
            stats: WitnessStats::default(),
        })
    }

    /// The note key name of this witness's cosignatures.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether a split view of `log_id` has been proven (the log must not be relied on).
    #[must_use]
    pub fn is_split(&self, log_id: &str) -> bool {
        self.logs.get(log_id).is_some_and(|l| l.split)
    }

    /// The logs with a proven split view.
    #[must_use]
    pub fn split_logs(&self) -> BTreeSet<String> {
        self.logs
            .iter()
            .filter(|(_, l)| l.split)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Size of the last accepted checkpoint of `log_id`.
    #[must_use]
    pub fn head_size(&self, log_id: &str) -> Option<u64> {
        self.logs
            .get(log_id)
            .and_then(|l| l.head.as_ref())
            .map(|h| h.cp.size)
    }

    /// Writes `ct-witness.json`; false if it could not be written.
    fn persist(&self) -> bool {
        let mut logs = self.others.clone();
        for (k, l) in &self.logs {
            logs.insert(
                k.clone(),
                PersistedLog {
                    head: l
                        .head
                        .as_ref()
                        .map(|h| h.note.clone())
                        .or_else(|| l.stale_head.clone()),
                    split: l.split,
                    proof: l.proof.clone(),
                },
            );
        }
        match files::write_json(&self.state_path, &Persisted { logs }) {
            Ok(()) => true,
            Err(e) => {
                warn!(error = %e, "failed to persist witness state");
                false
            }
        }
    }

    /// Work due now: a checkpoint poll, or a comparison of peers' observations, per log
    /// (one job per log at a time).
    pub fn jobs_due(&mut self, now: Instant) -> Vec<Job> {
        let mut jobs = Vec::new();
        for (log_id, st) in &mut self.logs {
            if st.busy || st.stale_head.is_some() {
                continue;
            }
            // Due comparisons go first: a poll can be due every time the job slot frees up
            // (a slow log), and would otherwise starve them. They cannot starve polls in
            // turn, since each peer is compared at most once per `CHECK_EVERY`.
            let mut compare = Vec::new();
            if let Some(head) = st.head.as_ref().filter(|_| !st.split) {
                for (w, o) in &mut st.pending {
                    if compare.len() >= MAX_PER_JOB {
                        break;
                    }
                    if o.cp.size <= head.cp.size
                        && o.last_try.is_none_or(|t| now >= t + CHECK_EVERY)
                    {
                        o.last_try = Some(now);
                        o.attempts += 1;
                        compare.push((w.clone(), o.clone()));
                    }
                }
            }
            if !compare.is_empty() {
                st.busy = true;
                jobs.push(Job {
                    log_id: log_id.clone(),
                    info: st.info.clone(),
                    head: st.head.clone(),
                    compare,
                });
            } else if now >= st.next_poll {
                st.next_poll = now + self.poll;
                st.busy = true;
                jobs.push(Job {
                    log_id: log_id.clone(),
                    info: st.info.clone(),
                    head: st.head.clone(),
                    compare: Vec::new(),
                });
            }
        }
        jobs
    }

    /// Applies a finished job. Returns the split views it proved.
    pub fn on_outcome(&mut self, o: JobOutcome, now: u64) -> Vec<SplitView> {
        let mut proven = Vec::new();
        let Some(st) = self.logs.get_mut(&o.log_id) else {
            return proven;
        };
        st.busy = false;
        match o.result {
            Outcome::Polled(Ok(Polled::Advanced(h))) => {
                debug!(log = %o.log_id, size = h.cp.size, "witnessed checkpoint");
                // Saved before it can be cosigned (C2SP tlog-witness): if it cannot be
                // saved, the previous checkpoint stays the one this node cosigns.
                let previous = st.head.replace(h);
                if self.persist() {
                    self.stats.checkpoints_accepted += 1;
                } else {
                    self.stats.polls_failed += 1;
                    if let Some(st) = self.logs.get_mut(&o.log_id) {
                        st.head = previous;
                    }
                }
            }
            Outcome::Polled(Ok(Polled::Unchanged)) => {}
            Outcome::Polled(Ok(Polled::Split(p))) => {
                proven.extend(self.record_split(&o.log_id, p, None, now));
            }
            Outcome::Polled(Err(e)) => {
                self.stats.polls_failed += 1;
                debug!(log = %o.log_id, error = %e, "witness checkpoint poll failed");
            }
            Outcome::Compared(results) => {
                for (w, obs, r) in results {
                    let same = |st: &LogState| {
                        st.pending
                            .get(&w)
                            .is_some_and(|p| p.cp.size == obs.cp.size && p.cp.root == obs.cp.root)
                    };
                    match r {
                        Compared::Consistent => {
                            self.stats.consistent += 1;
                            if let Some(st) = self.logs.get_mut(&o.log_id) {
                                if same(st) {
                                    st.pending.remove(&w);
                                }
                                if st.checked.len() >= MAX_CHECKED {
                                    st.checked.clear();
                                }
                                st.checked.insert((obs.cp.size, obs.cp.root));
                            }
                        }
                        Compared::Split(p) => {
                            if let Some(st) = self.logs.get_mut(&o.log_id) {
                                st.pending.remove(&w);
                            }
                            proven.extend(self.record_split(
                                &o.log_id,
                                p,
                                Some((w, obs.envelope)),
                                now,
                            ));
                        }
                        Compared::Inconclusive(e) => {
                            self.stats.inconclusive += 1;
                            debug!(log = %o.log_id, witness = %w.short(), error = %e, "checkpoint comparison inconclusive");
                            if let Some(st) = self.logs.get_mut(&o.log_id)
                                && same(st)
                                && st
                                    .pending
                                    .get(&w)
                                    .is_some_and(|p| p.attempts >= MAX_ATTEMPTS)
                            {
                                st.pending.remove(&w);
                            }
                        }
                    }
                }
            }
        }
        proven
    }

    fn record_split(
        &mut self,
        log_id: &str,
        proof: SplitViewProof,
        reported: Option<(KeyId, String)>,
        now: u64,
    ) -> Option<SplitView> {
        let st = self.logs.get_mut(log_id)?;
        if st.split {
            return None;
        }
        // The proof was built from two verified checkpoints; one that does not check out
        // would be a bug, and is never acted on.
        let sizes = match proof.verify(&st.key) {
            Ok((l, s)) => (l.size, s.size),
            Err(e) => {
                error!(log = %log_id, error = %e, "internal error: a split-view proof did not verify; ignored");
                return None;
            }
        };
        st.split = true;
        st.pending.clear();
        let (reported_by, observation) = reported.map_or((None, None), |(w, e)| (Some(w), Some(e)));
        let ev = SplitViewEvidence {
            log_id: log_id.to_owned(),
            detected_at: now,
            detected_by: self.id.clone(),
            reported_by,
            observation,
            proof,
        };
        let file = self
            .proofs_dir
            .join(format!("{log_id}-{}-{}-{now}.json", sizes.0, sizes.1));
        if let Err(e) = std::fs::create_dir_all(&self.proofs_dir)
            .map_err(|e| NodeError::Io(e.to_string()))
            .and_then(|()| files::write_json(&file, &ev))
        {
            error!(error = %e, "failed to write the split-view proof file (it is also in the witness state)");
        }
        st.proof = Some(ev.clone());
        error!(log = %log_id, larger = sizes.0, smaller = sizes.1, reported_by = ?ev.reported_by.as_ref().map(KeyId::short), proof = %file.display(),
            "CT log proven to show a split view: it signed two trees that cannot both be correct; the log is no longer relied on");
        self.stats.split_views += 1;
        self.stats.proofs.push(file.display().to_string());
        self.persist();
        Some(SplitView {
            log_id: log_id.to_owned(),
            proof_file: file,
        })
    }

    /// Handles a message from the `checkpoints` topic.
    pub fn on_message(&mut self, bytes: &[u8], manifest: &TrustManifest, now: u64) -> Acceptance {
        let v = match verify_checkpoint_observation(bytes, manifest, now, &self.limits) {
            Ok(v) => v,
            // Clocks, or a signer this node's manifest does not know yet (it may lag), are
            // ignored; only proof of misbehaviour counts against the sender.
            Err(e) => {
                self.stats.refused += 1;
                debug!(error = %e, "refused checkpoint observation");
                return crate::blame(e.proves_misbehaviour());
            }
        };
        if v.signer == self.id {
            return Acceptance::Ignore;
        }
        let o = v.message;
        let Some(st) = self
            .logs
            .get_mut(&o.log_id)
            .filter(|st| st.stale_head.is_none())
        else {
            return Acceptance::Ignore;
        };
        // A log signature that does not verify may be pinned-evidence drift between nodes:
        // ignored, not held against the sender.
        let Ok(cp) = verify_checkpoint(&o.checkpoint, &st.key) else {
            self.stats.refused += 1;
            return Acceptance::Ignore;
        };
        let Some(pk) = manifest.key_with_role(&o.witness, Role::Verifier) else {
            return Acceptance::Ignore;
        };
        // Without its cosignature the observation is unusable; but the cosigner name format is
        // a protocol detail a newer release could change, so it is not proof of misbehaviour.
        if verify_cosignature(
            &o.checkpoint,
            &witness_key_name(&self.network_id, &o.witness),
            &pk,
        )
        .is_err()
        {
            self.stats.refused += 1;
            return Acceptance::Ignore;
        }
        let signed = cp.signed_at_ms / 1000;
        if signed > now.saturating_add(MAX_CHECKPOINT_SKEW_SECS)
            || now.saturating_sub(signed) > MAX_PEER_CHECKPOINT_AGE_SECS
        {
            self.stats.refused += 1;
            return Acceptance::Ignore;
        }
        self.stats.received += 1;
        if st.split || st.checked.contains(&(cp.size, cp.root)) {
            return Acceptance::Accept;
        }
        let replace = st
            .pending
            .get(&o.witness)
            .is_none_or(|p| cp.size > p.cp.size || (cp.size == p.cp.size && cp.root != p.cp.root));
        if replace && (st.pending.contains_key(&o.witness) || st.pending.len() < MAX_PEERS_PER_LOG)
        {
            st.pending.insert(
                o.witness,
                PeerObs {
                    note: o.checkpoint,
                    cp,
                    envelope: String::from_utf8_lossy(bytes).into_owned(),
                    attempts: 0,
                    last_try: None,
                },
            );
        }
        Acceptance::Accept
    }

    /// Signed observations due for publication: each log's latest accepted checkpoint,
    /// cosigned, every `publish` interval.
    pub fn publications_due(&mut self, now: Instant, now_secs: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for (log_id, st) in &mut self.logs {
            if now < st.next_publish {
                continue;
            }
            let Some(h) = &st.head else { continue };
            if now_secs.saturating_sub(h.cp.signed_at_ms / 1000) > MAX_PEER_CHECKPOINT_AGE_SECS {
                continue;
            }
            st.next_publish = now + self.publish;
            let note = match cosign(&h.note, &self.name, &self.key, now_secs) {
                Ok(n) => n,
                Err(e) => {
                    warn!(log = %log_id, error = %e, "failed to cosign checkpoint");
                    continue;
                }
            };
            let obs = CheckpointObservation {
                v: PROTOCOL_VERSION,
                network_id: self.network_id.clone(),
                log_id: log_id.clone(),
                witness: self.id.clone(),
                observed_at: now_secs,
                checkpoint: note,
            };
            match canonical::to_vec(&obs)
                .ok()
                .and_then(|p| Envelope::sign(CT_CHECKPOINT, &p, &self.key).to_vec().ok())
            {
                Some(b) => out.push(b),
                None => warn!(log = %log_id, "failed to encode checkpoint observation"),
            }
        }
        out
    }
}

/// Starts the jobs due now on blocking threads; outcomes arrive on `tx`. The channel is
/// unbounded, but each log has at most one job (and so one outcome) in flight.
pub fn start_jobs(
    w: &mut Witness,
    tx: &tokio::sync::mpsc::UnboundedSender<JobOutcome>,
    now_secs: u64,
) {
    for job in w.jobs_due(Instant::now()) {
        let tx = tx.clone();
        let log_id = job.log_id.clone();
        let compare = job.compare.clone();
        tokio::spawn(async move {
            let o = tokio::task::spawn_blocking(move || run_job_http(job, now_secs))
                .await
                .unwrap_or_else(|_| JobOutcome {
                    log_id,
                    result: if compare.is_empty() {
                        Outcome::Polled(Err("witness job panicked".into()))
                    } else {
                        Outcome::Compared(
                            compare
                                .into_iter()
                                .map(|(w, o)| (w, o, Compared::Inconclusive("panicked".into())))
                                .collect(),
                        )
                    },
                });
            let _ = tx.send(o);
        });
    }
}

/// Publishes the observations due now on `topic`.
pub async fn publish_due(w: &mut Witness, net: &NetworkHandle, topic: &str, now_secs: u64) {
    for bytes in w.publications_due(Instant::now(), now_secs) {
        match net.publish(topic, bytes).await {
            Ok(()) => w.stats.published += 1,
            Err(e) => debug!(error = %e, "checkpoint observation not published"),
        }
    }
}

/// Logs a first acceptance once per log (operators see that witnessing works).
pub fn log_started(w: &Witness) {
    for (id, st) in &w.logs {
        if !st.split {
            info!(log = %id, witness = %w.name, "witnessing CT log checkpoints");
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use cybermesh_ct::mock::{MockLog, demo_entries};
    use cybermesh_protocol::testkit::{TestNetwork, sign_bytes};

    use super::*;

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn setup(log: &MockLog) -> WitnessSetup {
        WitnessSetup {
            logs: vec![log.log_info("mock-log", "http://127.0.0.1:9/")],
            poll: Duration::from_secs(60),
            publish: Duration::from_secs(300),
        }
    }

    /// Runs every job due at `at` against `src` and applies the outcomes.
    fn step(w: &mut Witness, src: &MockLog, at: Instant) -> Vec<SplitView> {
        let mut proven = Vec::new();
        for job in w.jobs_due(at) {
            let o = run_job(job, src, now_secs());
            proven.extend(w.on_outcome(o, now_secs()));
        }
        proven
    }

    fn publish(w: &mut Witness, at: Instant) -> Vec<u8> {
        let mut v = w.publications_due(at, now_secs());
        assert_eq!(v.len(), 1);
        v.remove(0)
    }

    #[test]
    fn two_views_of_one_log_are_caught_and_proven_on_both_sides() {
        let n = TestNetwork::new(&[("org-a", 1), ("org-b", 1)], now_secs());
        // One log key, two views sharing only the first tile.
        let base = MockLog::build("mock.example/log", &demo_entries(1)).unwrap();
        let mut a = base.clone();
        a.extend(&demo_entries(2)).unwrap();
        let mut b = base.clone();
        b.extend(&demo_entries(1)).unwrap();
        let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut wa = Witness::new(&setup(&base), &n.verifier, &n.network_id, da.path()).unwrap();
        let kb = &n.other_verifiers[0].0;
        let mut wb = Witness::new(&setup(&base), kb, &n.network_id, db.path()).unwrap();
        let t0 = Instant::now();
        assert!(step(&mut wa, &a, t0).is_empty());
        assert!(step(&mut wb, &b, t0).is_empty());
        assert_eq!(
            (wa.head_size("mock-log"), wb.head_size("mock-log")),
            (Some(768), Some(512))
        );
        let (oa, ob) = (publish(&mut wa, t0), publish(&mut wb, t0));

        // A holds the larger tree: B's checkpoint is compared at once and proven forked.
        assert_eq!(
            wa.on_message(&ob, &n.manifest, now_secs()),
            Acceptance::Accept
        );
        let proven = step(&mut wa, &a, t0);
        assert_eq!(proven.len(), 1);
        assert!(wa.is_split("mock-log"));
        let ev: SplitViewEvidence = files::read_json(&proven[0].proof_file).unwrap();
        assert_eq!(ev.reported_by, Some(kb.key_id()));
        assert_eq!(ev.detected_by, n.verifier.key_id());
        let key = LogKey::from_info(&base.log_info("mock-log", "http://127.0.0.1:9/")).unwrap();
        let (l, s) = ev.proof.verify(&key).unwrap();
        assert_eq!((l.size, s.size), (768, 512));
        // B's own cosignature is in the proof: B's view is attributable outside CyberMesh.
        verify_cosignature(&ev.proof.smaller, wb.name(), &kb.public_key()).unwrap();
        // A no longer relies on or compares the log, also after a restart, but keeps
        // publishing its own view so that organisations sharing it see the conflict too.
        assert_eq!(
            wa.publications_due(t0 + Duration::from_secs(301), now_secs())
                .len(),
            1
        );
        assert!(
            wa.jobs_due(t0 + Duration::from_secs(61))
                .iter()
                .all(|j| j.compare.is_empty())
        );
        assert_eq!(
            wa.on_message(&ob, &n.manifest, now_secs()),
            Acceptance::Accept
        );
        assert!(wa.logs["mock-log"].pending.is_empty());
        let again = Witness::new(&setup(&base), &n.verifier, &n.network_id, da.path()).unwrap();
        assert!(again.is_split("mock-log"));

        // B is behind: A's larger checkpoint waits until B's own view grows past it ...
        assert_eq!(
            wb.on_message(&oa, &n.manifest, now_secs()),
            Acceptance::Accept
        );
        assert!(step(&mut wb, &b, t0).is_empty());
        let mut b2 = b.clone();
        b2.extend(&demo_entries(2)).unwrap();
        // ... then B proves it too, from its own (grown) view.
        let proven = step(&mut wb, &b2, t0 + Duration::from_secs(61));
        assert!(proven.is_empty(), "the poll only advances B's head");
        assert_eq!(wb.head_size("mock-log"), Some(1024));
        let proven = step(&mut wb, &b2, t0 + Duration::from_secs(62));
        assert_eq!(proven.len(), 1);
        assert_eq!(wb.stats.split_views, 1);
    }

    #[test]
    fn one_view_is_confirmed_and_a_log_rewriting_itself_is_proven() {
        let n = TestNetwork::new(&[("org-a", 1), ("org-b", 1)], now_secs());
        let mut log = MockLog::build("mock.example/log", &demo_entries(2)).unwrap();
        let d = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut wa = Witness::new(&setup(&log), &n.verifier, &n.network_id, d.0.path()).unwrap();
        let kb = &n.other_verifiers[0].0;
        let mut wb = Witness::new(&setup(&log), kb, &n.network_id, d.1.path()).unwrap();
        let t0 = Instant::now();
        step(&mut wa, &log, t0);
        let oa = publish(&mut wa, t0);
        let before = log.clone();
        log.extend(&demo_entries(1)).unwrap();
        step(&mut wb, &log, t0);
        let ob = publish(&mut wb, t0);
        // B compares A's older checkpoint with its newer tree: consistent.
        assert_eq!(
            wb.on_message(&oa, &n.manifest, now_secs()),
            Acceptance::Accept
        );
        assert!(step(&mut wb, &log, t0).is_empty());
        assert_eq!(wb.stats.consistent, 1);
        // A first has to catch up; then B's checkpoint is consistent with A's view too.
        assert_eq!(
            wa.on_message(&ob, &n.manifest, now_secs()),
            Acceptance::Accept
        );
        assert!(step(&mut wa, &before, t0).is_empty());
        assert_eq!(wa.stats.consistent, 0);
        assert!(step(&mut wa, &log, t0 + Duration::from_secs(61)).is_empty());
        assert!(step(&mut wa, &log, t0 + Duration::from_secs(62)).is_empty());
        assert_eq!(wa.stats.consistent, 1);
        assert!(wa.split_logs().is_empty() && wb.split_logs().is_empty());
        // The same checkpoint again is already known consistent: nothing to compare.
        assert_eq!(
            wa.on_message(&ob, &n.manifest, now_secs()),
            Acceptance::Accept
        );
        assert!(wa.jobs_due(t0 + Duration::from_secs(70)).is_empty());

        // The log rewrites history in A's own view: A proves it from its two checkpoints.
        let mut rewritten = before.clone();
        rewritten.extend(&demo_entries(2)).unwrap();
        let proven = step(&mut wa, &rewritten, t0 + Duration::from_secs(130));
        assert_eq!(proven.len(), 1);
        let ev: SplitViewEvidence = files::read_json(&proven[0].proof_file).unwrap();
        assert_eq!(ev.reported_by, None);
        assert_eq!(wa.stats.checkpoints_accepted, 2);
    }

    #[test]
    fn observations_are_refused_unless_signed_cosigned_and_current() {
        let n = TestNetwork::new(&[("org-a", 1), ("org-b", 1)], now_secs());
        let log = MockLog::build("mock.example/log", &demo_entries(1)).unwrap();
        let d = tempfile::tempdir().unwrap();
        let mut wa = Witness::new(&setup(&log), &n.verifier, &n.network_id, d.path()).unwrap();
        let kb = &n.other_verifiers[0].0;
        let note = log.checkpoint().unwrap();
        let obs =
            |checkpoint: String, witness: KeyId, log_id: &str, at: u64| CheckpointObservation {
                v: PROTOCOL_VERSION,
                network_id: n.network_id.clone(),
                log_id: log_id.into(),
                witness,
                observed_at: at,
                checkpoint,
            };
        let name_b = witness_key_name(&n.network_id, &kb.key_id());
        let good = cosign(&note, &name_b, kb, now_secs()).unwrap();
        let send = |w: &mut Witness, o: &CheckpointObservation, k: &SecretKey| {
            w.on_message(&sign_bytes(CT_CHECKPOINT, o, k), &n.manifest, now_secs())
        };
        assert_eq!(
            send(
                &mut wa,
                &obs(good.clone(), kb.key_id(), "mock-log", now_secs()),
                kb
            ),
            Acceptance::Accept
        );
        // Cosigned by another key, or under another name: unusable, refused, but not proof
        // of misbehaviour (a newer release could name cosigners differently).
        let wrong = cosign(&note, &name_b, &n.workers[0].key, now_secs()).unwrap();
        assert_eq!(
            send(
                &mut wa,
                &obs(wrong, kb.key_id(), "mock-log", now_secs()),
                kb
            ),
            Acceptance::Ignore
        );
        let wrong = cosign(&note, "cybermesh/other/x", kb, now_secs()).unwrap();
        assert_eq!(
            send(
                &mut wa,
                &obs(wrong, kb.key_id(), "mock-log", now_secs()),
                kb
            ),
            Acceptance::Ignore
        );
        // Claiming to be another verifier: proof of misbehaviour.
        assert_eq!(
            send(
                &mut wa,
                &obs(good.clone(), n.verifier.key_id(), "mock-log", now_secs()),
                kb
            ),
            Acceptance::Reject
        );
        // Not a verifier: refused by the protocol, but ignored rather than penalised (the
        // same answer as for a signer a lagging manifest does not know yet).
        let w0 = &n.workers[0].key;
        assert_eq!(
            send(
                &mut wa,
                &obs(good.clone(), w0.key_id(), "mock-log", now_secs()),
                w0
            ),
            Acceptance::Ignore
        );
        // A note the log did not sign, a log not witnessed here, a stale observation, an
        // echo of this node's own: ignored.
        let forged = cosign(
            &note.replacen("\n256\n", "\n257\n", 1),
            &name_b,
            kb,
            now_secs(),
        )
        .unwrap();
        assert_eq!(
            send(
                &mut wa,
                &obs(forged, kb.key_id(), "mock-log", now_secs()),
                kb
            ),
            Acceptance::Ignore
        );
        assert_eq!(
            send(
                &mut wa,
                &obs(good.clone(), kb.key_id(), "other-log", now_secs()),
                kb
            ),
            Acceptance::Ignore
        );
        assert_eq!(
            send(
                &mut wa,
                &obs(good.clone(), kb.key_id(), "mock-log", now_secs() - 7200),
                kb
            ),
            Acceptance::Ignore
        );
        let mine = cosign(&note, wa.name(), &n.verifier, now_secs()).unwrap();
        assert_eq!(
            send(
                &mut wa,
                &obs(mine, n.verifier.key_id(), "mock-log", now_secs()),
                &n.verifier
            ),
            Acceptance::Ignore
        );
        assert_eq!(wa.stats.received, 1);
    }

    #[test]
    fn nothing_unsaved_is_cosigned_and_saved_state_is_kept() {
        let n = TestNetwork::new(&[("org-a", 1), ("org-b", 1)], now_secs());
        let mut log = MockLog::build("mock.example/log", &demo_entries(2)).unwrap();

        // The state cannot be written: the checkpoint is not adopted, so not cosigned.
        let gone = tempfile::tempdir().unwrap();
        let dir = gone.path().join("state");
        std::fs::create_dir_all(&dir).unwrap();
        let mut w = Witness::new(&setup(&log), &n.verifier, &n.network_id, &dir).unwrap();
        // A directory where the state file belongs: every write fails.
        std::fs::create_dir_all(dir.join("ct-witness.json").join("x")).unwrap();
        let t0 = Instant::now();
        step(&mut w, &log, t0);
        assert_eq!(w.head_size("mock-log"), None);
        assert_eq!(w.stats.polls_failed, 1);
        assert!(w.publications_due(t0, now_secs()).is_empty());

        // A mirror serving an older checkpoint of the same tree changes nothing.
        let d = tempfile::tempdir().unwrap();
        let mut w = Witness::new(&setup(&log), &n.verifier, &n.network_id, d.path()).unwrap();
        let t0 = Instant::now();
        let older = log.clone();
        log.extend(&demo_entries(1)).unwrap();
        step(&mut w, &log, t0);
        assert_eq!(w.head_size("mock-log"), Some(768));
        assert!(step(&mut w, &older, t0 + Duration::from_secs(61)).is_empty());
        assert_eq!(w.head_size("mock-log"), Some(768));
        assert_eq!(w.stats.checkpoints_accepted, 1);

        // Logs not configured now keep their saved state.
        let other = WitnessSetup {
            logs: vec![log.log_info("other-log", "http://127.0.0.1:9/")],
            ..setup(&log)
        };
        let mut w2 = Witness::new(&other, &n.verifier, &n.network_id, d.path()).unwrap();
        step(&mut w2, &log, Instant::now());
        assert_eq!(w2.head_size("other-log"), Some(768));
        let back = Witness::new(&setup(&log), &n.verifier, &n.network_id, d.path()).unwrap();
        assert_eq!(back.head_size("mock-log"), Some(768));

        // A saved checkpoint that no longer verifies (the pinned key or origin changed):
        // the log is not witnessed, rather than starting afresh, and the note is kept.
        let moved = MockLog::build("moved.example/log", &demo_entries(1)).unwrap();
        let mut w3 = Witness::new(&setup(&moved), &n.verifier, &n.network_id, d.path()).unwrap();
        let t3 = Instant::now();
        assert!(w3.jobs_due(t3).is_empty());
        assert!(w3.publications_due(t3, now_secs()).is_empty());
        let kb = &n.other_verifiers[0].0;
        let name_b = witness_key_name(&n.network_id, &kb.key_id());
        let obs = CheckpointObservation {
            v: PROTOCOL_VERSION,
            network_id: n.network_id.clone(),
            log_id: "mock-log".into(),
            witness: kb.key_id(),
            observed_at: now_secs(),
            checkpoint: cosign(&moved.checkpoint().unwrap(), &name_b, kb, now_secs()).unwrap(),
        };
        let bytes = sign_bytes(CT_CHECKPOINT, &obs, kb);
        assert_eq!(
            w3.on_message(&bytes, &n.manifest, now_secs()),
            Acceptance::Ignore
        );
        let saved: Persisted = files::read_json(&d.path().join("ct-witness.json")).unwrap();
        assert!(saved.logs["mock-log"].head.is_some());

        // A witness this node's manifest does not know yet (it may lag): ignored, not
        // held against the peer.
        let newcomer = cybermesh_crypto::SecretKey::from_seed(&[42; 32]);
        let mut late = obs.clone();
        late.witness = newcomer.key_id();
        let bytes = sign_bytes(CT_CHECKPOINT, &late, &newcomer);
        let fresh = tempfile::tempdir().unwrap();
        let mut w4 =
            Witness::new(&setup(&moved), &n.verifier, &n.network_id, fresh.path()).unwrap();
        assert_eq!(
            w4.on_message(&bytes, &n.manifest, now_secs()),
            Acceptance::Ignore
        );
    }

    #[test]
    fn due_comparisons_are_never_starved_by_polls() {
        // Polls are due again every time the log's job slot frees up (a poll that takes
        // longer than the tick on a loaded machine). A pending comparison must still run.
        let n = TestNetwork::new(&[("org-a", 1), ("org-b", 1)], now_secs());
        let log = MockLog::build("mock.example/log", &demo_entries(1)).unwrap();
        let d = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut wa = Witness::new(&setup(&log), &n.verifier, &n.network_id, d.0.path()).unwrap();
        let kb = &n.other_verifiers[0].0;
        let mut wb = Witness::new(&setup(&log), kb, &n.network_id, d.1.path()).unwrap();
        let t0 = Instant::now();
        step(&mut wa, &log, t0);
        step(&mut wb, &log, t0);
        let ob = publish(&mut wb, t0);
        assert_eq!(
            wa.on_message(&ob, &n.manifest, now_secs()),
            Acceptance::Accept
        );
        // A poll is due as well: the comparison goes first ...
        let at = t0 + Duration::from_secs(61);
        let jobs = wa.jobs_due(at);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].compare.len(), 1, "the comparison runs first");
        for job in jobs {
            let o = run_job(job, &log, now_secs());
            wa.on_outcome(o, now_secs());
        }
        assert_eq!(wa.stats.consistent, 1);
        // ... and the poll right after it.
        let jobs = wa.jobs_due(at);
        assert!(
            jobs.len() == 1 && jobs[0].compare.is_empty(),
            "then the poll"
        );
    }

    #[test]
    fn unreadable_tiles_prove_nothing_and_are_given_up() {
        let n = TestNetwork::new(&[("org-a", 1), ("org-b", 1)], now_secs());
        let base = MockLog::build("mock.example/log", &demo_entries(1)).unwrap();
        let mut a = base.clone();
        a.extend(&demo_entries(2)).unwrap();
        let mut b = base.clone();
        b.extend(&demo_entries(1)).unwrap();
        let d = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut wa = Witness::new(&setup(&base), &n.verifier, &n.network_id, d.0.path()).unwrap();
        let kb = &n.other_verifiers[0].0;
        let mut wb = Witness::new(&setup(&base), kb, &n.network_id, d.1.path()).unwrap();
        let t0 = Instant::now();
        step(&mut wa, &a, t0);
        step(&mut wb, &b, t0);
        let ob = publish(&mut wb, t0);
        wa.on_message(&ob, &n.manifest, now_secs());
        // The tiles A is served no longer match A's signed checkpoint: the level-1 tile
        // holding the three data-tile roots, which every comparison here reads.
        let mut broken = a.clone();
        let p = cybermesh_ct::tile::hash_tile_path(1, 0, Some(3));
        let mut bytes = broken.files[&p].clone();
        bytes[0] ^= 1;
        broken.replace_file(&p, bytes);
        for i in 0..u64::from(MAX_ATTEMPTS) {
            // A poll may be due at the same moment (one job per log at a time): step twice.
            let at = t0 + CHECK_EVERY * u32::try_from(i).unwrap();
            assert!(step(&mut wa, &broken, at).is_empty(), "attempt {i}");
            assert!(step(&mut wa, &broken, at).is_empty(), "attempt {i}");
        }
        assert_eq!(wa.stats.inconclusive, u64::from(MAX_ATTEMPTS));
        assert!(!wa.is_split("mock-log"));
        // Given up: nothing left to compare.
        assert!(
            wa.jobs_due(t0 + CHECK_EVERY * 10)
                .iter()
                .all(|j| j.compare.is_empty())
        );
    }
}
