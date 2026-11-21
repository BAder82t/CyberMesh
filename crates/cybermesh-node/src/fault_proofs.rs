//! Fault proofs between verifiers and the coordinator.
//!
//! An independent verifier can prove a fault the coordinator missed: each verifier spot-checks
//! CT tiles chosen by its own secret seed. Its verification record only names the fault, so
//! the verifier also publishes a [`FaultProof`] on the `faults` topic, carrying the signed task
//! and the worker's own signed results ([`Evidence`] keeps them while the task is followed).
//!
//! The coordinator re-checks every proof itself before acting
//! ([`cybermesh_verifier::fault_proof::check_fault_proof`]): it quarantines the worker only on
//! a fault it confirms, so a verifier cannot get an honest worker excluded. Checks run off the
//! event loop, at most [`MAX_CHECKS_IN_FLIGHT`] at a time and each within [`CHECK_BUDGET`];
//! [`ProofIntake`] queues at most [`MAX_QUEUED_PER_REPORTER`] per reporting verifier and takes
//! reporters in turn.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cybermesh_crypto::{Digest, KeyId, SecretKey};
use cybermesh_network::NetworkHandle;
use cybermesh_protocol::PROTOCOL_VERSION;
use cybermesh_verifier::fault_proof::{FaultProof, sign_fault_proof};
use cybermesh_verifier::{FaultKind, FaultRecord};
use tracing::{debug, warn};

/// Signed results kept per followed task for fault proofs (bytes).
pub const MAX_EVIDENCE_BYTES: usize = 2 << 20;
/// Evidence kept for settled tasks, to prove a worker's later contradicting result (bytes).
pub const MAX_LATE_BYTES: usize = 32 << 20;
/// Proofs waiting to be published.
const MAX_OUTBOX: usize = 256;
/// A proof that could not be published (no peer subscribed yet) is retried for this long.
const PUBLISH_RETRY_FOR: Duration = Duration::from_secs(600);
/// Proof checks running at once at the coordinator.
pub const MAX_CHECKS_IN_FLIGHT: usize = 2;
/// Proofs queued per reporting verifier.
pub const MAX_QUEUED_PER_REPORTER: usize = 8;
/// Proofs remembered as already handled.
const MAX_SEEN: usize = 16_384;
/// A proof whose check could not decide it is not checked again before this.
pub const RECHECK_AFTER: Duration = Duration::from_secs(300);
/// Wall-clock budget for one proof check (log fetches and re-scans); past it, the check stops
/// and the proof stays unconfirmed.
pub const CHECK_BUDGET: Duration = Duration::from_secs(120);

/// The signed task and the signed results a verifier received for one task attempt.
#[derive(Debug, Default, Clone)]
pub struct Evidence {
    pub task: Vec<u8>,
    results: BTreeMap<Digest, Vec<u8>>,
    bytes: usize,
}

impl Evidence {
    #[must_use]
    pub fn new(task: Vec<u8>) -> Self {
        Self {
            bytes: task.len(),
            task,
            results: BTreeMap::new(),
        }
    }

    /// Bytes held.
    #[must_use]
    pub fn size(&self) -> usize {
        self.bytes
    }

    /// Keeps a signed result (by its payload digest), within [`MAX_EVIDENCE_BYTES`].
    pub fn keep(&mut self, digest: Digest, bytes: &[u8]) {
        if self.results.contains_key(&digest) || self.bytes + bytes.len() > MAX_EVIDENCE_BYTES {
            return;
        }
        self.bytes += bytes.len();
        self.results.insert(digest, bytes.to_vec());
    }

    /// Signed proofs for `faults`, as `key` (this verifier). Faults whose results were not
    /// kept, or that are too large for one message, are counted in the second value.
    #[must_use]
    pub fn proofs(
        &self,
        faults: &[FaultRecord],
        network_id: &str,
        key: &SecretKey,
        now: u64,
        max_message: usize,
    ) -> (Vec<Vec<u8>>, usize) {
        let mut out = Vec::new();
        let mut skipped = 0;
        let Ok(task) = String::from_utf8(self.task.clone()) else {
            return (out, faults.len());
        };
        for f in faults {
            let results: Option<Vec<String>> = f
                .evidence
                .iter()
                .map(|d| {
                    self.results
                        .get(d)
                        .and_then(|b| String::from_utf8(b.clone()).ok())
                })
                .collect();
            let Some(results) = results.filter(|r| !r.is_empty() && r.len() <= 2) else {
                skipped += 1;
                continue;
            };
            let p = FaultProof {
                v: PROTOCOL_VERSION,
                network_id: network_id.to_owned(),
                reporter: key.key_id(),
                reported_at: now,
                fault: f.clone(),
                task: task.clone(),
                results,
            };
            match sign_fault_proof(&p, key) {
                Ok(b) if b.len() <= max_message => out.push(b),
                _ => skipped += 1,
            }
        }
        (out, skipped)
    }
}

/// A settled task's evidence and what each worker's accepted result asserted.
#[derive(Debug)]
struct SettledTask {
    evidence: Arc<Evidence>,
    /// Per worker: the accepted result's payload digest, and the digest of what it asserted.
    accepted: BTreeMap<KeyId, (Digest, Digest)>,
    /// Workers already proven to have contradicted themselves on this task.
    proven: BTreeSet<KeyId>,
    forget_after: u64,
}

/// Evidence of settled tasks, kept within [`MAX_LATE_BYTES`] (oldest dropped first), so a
/// verifier can still prove a worker equivocated when a contradicting result arrives after
/// the task settled.
#[derive(Debug)]
pub struct SettledEvidence<K> {
    tasks: HashMap<K, SettledTask>,
    order: VecDeque<K>,
    bytes: usize,
}

impl<K> Default for SettledEvidence<K> {
    fn default() -> Self {
        Self {
            tasks: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
        }
    }
}

impl<K: Hash + Eq + Clone> SettledEvidence<K> {
    /// Keeps a settled task's evidence. Nothing is kept for a task with no accepted result
    /// (there is nothing to contradict) or with more evidence than the whole budget.
    pub fn keep(
        &mut self,
        key: K,
        evidence: Arc<Evidence>,
        accepted: BTreeMap<KeyId, (Digest, Digest)>,
        forget_after: u64,
    ) {
        let size = evidence.size();
        if accepted.is_empty() || size > MAX_LATE_BYTES || self.tasks.contains_key(&key) {
            return;
        }
        while self.bytes + size > MAX_LATE_BYTES {
            let Some(old) = self.order.pop_front() else {
                break;
            };
            if let Some(t) = self.tasks.remove(&old) {
                self.bytes = self.bytes.saturating_sub(t.evidence.size());
            }
        }
        self.bytes += size;
        self.order.push_back(key.clone());
        self.tasks.insert(
            key,
            SettledTask {
                evidence,
                accepted,
                proven: BTreeSet::new(),
                forget_after,
            },
        );
    }

    /// A late result by `worker` for a settled task, with payload digest `digest` and
    /// asserting `claims`. If the worker's accepted result asserted something else, the
    /// worker equivocated: returns that result's digest and the task's evidence, once per
    /// worker and task. The same answer signed again, or a result for a task not kept,
    /// proves nothing.
    pub fn contradiction(
        &mut self,
        key: &K,
        worker: &KeyId,
        digest: Digest,
        claims: Digest,
    ) -> Option<(Digest, Arc<Evidence>)> {
        let t = self.tasks.get_mut(key)?;
        let (prior, prior_claims) = *t.accepted.get(worker)?;
        if prior == digest || prior_claims == claims || !t.proven.insert(worker.clone()) {
            return None;
        }
        Some((prior, Arc::clone(&t.evidence)))
    }

    /// Forgets tasks past their `forget_after` (unix seconds).
    pub fn expire(&mut self, now: u64) {
        let gone: Vec<K> = self
            .tasks
            .iter()
            .filter(|(_, t)| t.forget_after <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &gone {
            if let Some(t) = self.tasks.remove(k) {
                self.bytes = self.bytes.saturating_sub(t.evidence.size());
            }
        }
        self.order.retain(|k| self.tasks.contains_key(k));
    }

    /// Bytes held.
    #[must_use]
    pub fn size(&self) -> usize {
        self.bytes
    }
}

/// Proofs waiting to be published, retried while no peer is subscribed yet.
#[derive(Debug, Default)]
pub struct ProofOutbox {
    queue: VecDeque<(Instant, Vec<u8>)>,
    pub published: u64,
    pub dropped: u64,
}

impl ProofOutbox {
    pub fn queue(&mut self, proofs: Vec<Vec<u8>>) {
        for p in proofs {
            if self.queue.len() >= MAX_OUTBOX {
                self.dropped += 1;
                continue;
            }
            self.queue.push_back((Instant::now(), p));
        }
    }

    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.queue.is_empty()
    }

    /// The proofs waiting to be published.
    #[cfg(test)]
    #[must_use]
    pub fn queued(&self) -> Vec<Vec<u8>> {
        self.queue.iter().map(|(_, b)| b.clone()).collect()
    }

    /// Publishes what it can; keeps the rest for a while.
    pub async fn flush(&mut self, net: &NetworkHandle, topic: &str) {
        let mut keep = VecDeque::new();
        while let Some((at, bytes)) = self.queue.pop_front() {
            match net.publish(topic, bytes.clone()).await {
                Ok(()) | Err(cybermesh_network::NetError::Duplicate) => self.published += 1,
                Err(e) if at.elapsed() < PUBLISH_RETRY_FOR => {
                    debug!(error = %e, "fault proof not published yet");
                    keep.push_back((at, bytes));
                }
                Err(e) => {
                    self.dropped += 1;
                    warn!(error = %e, "fault proof dropped after retries");
                }
            }
        }
        self.queue = keep;
    }
}

/// What identifies a claimed fault: the worker, the kind, and the signed results it rests on
/// (the results bind the task). Two proofs with the same key prove the same thing.
pub type ProofKey = (KeyId, FaultKind, Vec<Digest>);

#[must_use]
pub fn proof_key(fault: &FaultRecord) -> ProofKey {
    let mut ev = fault.evidence.clone();
    ev.sort();
    ev.dedup();
    (fault.worker.clone(), fault.kind, ev)
}

/// Incoming proofs at the coordinator: dedupe, bounded per-reporter queues, and round-robin
/// dispatch so one verifier cannot crowd out the others' proofs.
///
/// A proof is remembered as handled only once its check decided it (confirmed or refuted). A
/// check that could not decide (the log was unavailable, say) does not stop a later proof of
/// the same fault from being checked, after [`RECHECK_AFTER`].
#[derive(Debug)]
pub struct ProofIntake<T> {
    decided: HashSet<ProofKey>,
    undecided: HashMap<ProofKey, Instant>,
    /// Queued or being checked.
    pending: HashSet<ProofKey>,
    queues: HashMap<KeyId, VecDeque<(ProofKey, T)>>,
    /// Reporters with queued proofs, in turn order.
    turn: VecDeque<KeyId>,
    in_flight: usize,
}

impl<T> Default for ProofIntake<T> {
    fn default() -> Self {
        Self {
            decided: HashSet::new(),
            undecided: HashMap::new(),
            pending: HashSet::new(),
            queues: HashMap::new(),
            turn: VecDeque::new(),
            in_flight: 0,
        }
    }
}

impl<T> ProofIntake<T> {
    /// Queues a proof by `reporter` about `fault` for checking.
    pub fn offer(&mut self, reporter: &KeyId, fault: &FaultRecord, item: T, now: Instant) -> Admit {
        let key = proof_key(fault);
        if self.decided.contains(&key)
            || self.pending.contains(&key)
            || self
                .undecided
                .get(&key)
                .is_some_and(|at| now.saturating_duration_since(*at) < RECHECK_AFTER)
        {
            return Admit::Seen;
        }
        let q = self.queues.entry(reporter.clone()).or_default();
        if q.len() >= MAX_QUEUED_PER_REPORTER {
            return Admit::Full;
        }
        if q.is_empty() {
            self.turn.push_back(reporter.clone());
        }
        q.push_back((key.clone(), item));
        self.pending.insert(key);
        Admit::Queued
    }

    /// The next proof to check, taking reporters in turn, if a check slot is free.
    pub fn next_check(&mut self) -> Option<(KeyId, ProofKey, T)> {
        if self.in_flight >= MAX_CHECKS_IN_FLIGHT {
            return None;
        }
        let reporter = self.turn.pop_front()?;
        let q = self.queues.get_mut(&reporter)?;
        let (key, item) = q.pop_front()?;
        if q.is_empty() {
            self.queues.remove(&reporter);
        } else {
            self.turn.push_back(reporter.clone());
        }
        self.in_flight += 1;
        Some((reporter, key, item))
    }

    /// A check finished; `decided` if it confirmed or refuted the fault.
    pub fn done(&mut self, key: &ProofKey, decided: bool, now: Instant) {
        self.in_flight = self.in_flight.saturating_sub(1);
        self.pending.remove(key);
        if decided {
            if self.decided.len() >= MAX_SEEN {
                self.decided.clear();
            }
            self.undecided.remove(key);
            self.decided.insert(key.clone());
        } else {
            if self.undecided.len() >= MAX_SEEN {
                self.undecided
                    .retain(|_, at| now.saturating_duration_since(*at) < RECHECK_AFTER);
                if self.undecided.len() >= MAX_SEEN {
                    self.undecided.clear();
                }
            }
            self.undecided.insert(key.clone(), now);
        }
    }

    /// Nothing queued or being checked.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.in_flight == 0 && self.queues.is_empty()
    }
}

/// What happened to an incoming proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Queued for checking.
    Queued,
    /// Already decided, queued, or recently undecided (also when another verifier proved the
    /// same fault).
    Seen,
    /// This reporter already has [`MAX_QUEUED_PER_REPORTER`] proofs queued: dropped. A later
    /// proof of the same fault is still checked.
    Full,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use cybermesh_protocol::OperatorId;

    use super::*;

    fn fault(worker: u8, evidence: &[&[u8]]) -> FaultRecord {
        FaultRecord {
            worker: SecretKey::from_seed(&[worker; 32]).key_id(),
            operator: OperatorId::new("org-m").unwrap(),
            kind: FaultKind::IncorrectResult,
            evidence: evidence.iter().map(|b| Digest::of(b)).collect(),
        }
    }

    #[test]
    fn evidence_is_bounded_and_proofs_need_every_named_result() {
        let mut ev = Evidence::new(b"{}".to_vec());
        ev.keep(Digest::of(b"r1"), b"result one");
        ev.keep(Digest::of(b"r1"), b"result one again");
        let big = vec![b'x'; MAX_EVIDENCE_BYTES];
        ev.keep(Digest::of(b"big"), &big);
        assert_eq!(ev.results.len(), 1, "duplicates and overflow are not kept");
        let key = SecretKey::from_seed(&[9; 32]);
        let (proofs, skipped) = ev.proofs(
            &[fault(1, &[b"r1"]), fault(2, &[b"not kept"])],
            "net",
            &key,
            1,
            256 * 1024,
        );
        assert_eq!((proofs.len(), skipped), (1, 1));
        // Too large for one network message: skipped, not sent truncated.
        let (proofs, skipped) = ev.proofs(&[fault(1, &[b"r1"])], "net", &key, 1, 10);
        assert_eq!((proofs.len(), skipped), (0, 1));
    }

    #[test]
    fn intake_dedupes_queues_per_reporter_and_takes_turns() {
        let t0 = Instant::now();
        let mut intake = ProofIntake::<u32>::default();
        let a = SecretKey::from_seed(&[1; 32]).key_id();
        let b = SecretKey::from_seed(&[2; 32]).key_id();
        let f1 = fault(5, &[b"r1"]);
        assert_eq!(intake.offer(&a, &f1, 1, t0), Admit::Queued);
        // The same fault again, also from another verifier, is not checked twice.
        assert_eq!(intake.offer(&b, &f1, 2, t0), Admit::Seen);
        // One reporter cannot queue more than MAX_QUEUED_PER_REPORTER.
        for i in 1..MAX_QUEUED_PER_REPORTER {
            let ev = format!("a{i}");
            assert_eq!(
                intake.offer(&a, &fault(6, &[ev.as_bytes()]), 10, t0),
                Admit::Queued
            );
        }
        assert_eq!(
            intake.offer(&a, &fault(6, &[b"one more"]), 10, t0),
            Admit::Full
        );
        // ...and does not crowd out another verifier: reporters take turns.
        assert_eq!(intake.offer(&b, &fault(7, &[b"b1"]), 20, t0), Admit::Queued);
        let (r1, _, _) = intake.next_check().unwrap();
        let (r2, k2, item2) = intake.next_check().unwrap();
        assert_eq!((r1, r2.clone(), item2), (a.clone(), b.clone(), 20));
        // At most MAX_CHECKS_IN_FLIGHT run at once.
        assert!(intake.next_check().is_none());
        intake.done(&k2, true, t0);
        assert_eq!(intake.next_check().map(|(r, _, _)| r), Some(a.clone()));
        assert!(!intake.is_idle());
    }

    #[test]
    fn an_undecided_check_does_not_hide_the_fault_for_good() {
        let t0 = Instant::now();
        let mut intake = ProofIntake::<()>::default();
        let a = SecretKey::from_seed(&[1; 32]).key_id();
        let b = SecretKey::from_seed(&[2; 32]).key_id();
        let f = fault(5, &[b"r1"]);
        // A wrong kind over the same results is a different claim, so it cannot pre-empt the
        // real one.
        let mut wrong = f.clone();
        wrong.kind = FaultKind::Equivocation;
        assert_eq!(intake.offer(&a, &wrong, (), t0), Admit::Queued);
        assert_eq!(intake.offer(&b, &f, (), t0), Admit::Queued);
        let (_, kw, ()) = intake.next_check().unwrap();
        intake.done(&kw, true, t0);
        let (_, k, ()) = intake.next_check().unwrap();
        // The log was unavailable: not decided.
        intake.done(&k, false, t0);
        assert!(intake.is_idle());
        assert_eq!(
            intake.offer(&a, &f, (), t0),
            Admit::Seen,
            "not re-checked at once"
        );
        assert_eq!(
            intake.offer(&a, &f, (), t0 + RECHECK_AFTER),
            Admit::Queued,
            "checked again later"
        );
        let (_, k, ()) = intake.next_check().unwrap();
        intake.done(&k, true, t0 + RECHECK_AFTER);
        assert_eq!(
            intake.offer(&b, &f, (), t0 + RECHECK_AFTER * 10),
            Admit::Seen,
            "a decided fault is not checked again"
        );
    }

    #[test]
    fn a_late_result_is_equivocation_only_if_it_asserts_something_else() {
        let w = SecretKey::from_seed(&[1; 32]).key_id();
        let other = SecretKey::from_seed(&[2; 32]).key_id();
        let (r1, c1) = (Digest::of(b"result 1"), Digest::of(b"claims 1"));
        let mut store = SettledEvidence::<u8>::default();
        let mut ev = Evidence::new(b"{}".to_vec());
        ev.keep(r1, b"result one");
        store.keep(
            1,
            Arc::new(ev),
            BTreeMap::from([(w.clone(), (r1, c1))]),
            100,
        );
        // The same answer signed again (new nonce, same claims) proves nothing.
        assert!(
            store
                .contradiction(&1, &w, Digest::of(b"result 2"), c1)
                .is_none()
        );
        // The very same result proves nothing either.
        assert!(store.contradiction(&1, &w, r1, Digest::of(b"c2")).is_none());
        // A worker with no accepted result, or an unkept task, proves nothing.
        assert!(
            store
                .contradiction(&1, &other, Digest::of(b"x"), Digest::of(b"y"))
                .is_none()
        );
        assert!(
            store
                .contradiction(&2, &w, Digest::of(b"x"), Digest::of(b"y"))
                .is_none()
        );
        // A different claim does, once.
        let c2 = Digest::of(b"claims 2");
        let (prior, evidence) = store
            .contradiction(&1, &w, Digest::of(b"result 3"), c2)
            .unwrap();
        assert_eq!(prior, r1);
        assert!(evidence.size() > 0);
        assert!(
            store
                .contradiction(&1, &w, Digest::of(b"result 4"), c2)
                .is_none(),
            "proven once per worker and task"
        );
    }

    #[test]
    fn settled_evidence_is_bounded_and_expires() {
        let w = SecretKey::from_seed(&[1; 32]).key_id();
        let acc = || BTreeMap::from([(w.clone(), (Digest::of(b"r"), Digest::of(b"c")))]);
        let mut store = SettledEvidence::<u32>::default();
        // Nothing to contradict, or more than the whole budget: not kept.
        store.keep(
            0,
            Arc::new(Evidence::new(vec![0; 10])),
            BTreeMap::new(),
            100,
        );
        store.keep(
            1,
            Arc::new(Evidence::new(vec![0; MAX_LATE_BYTES + 1])),
            acc(),
            100,
        );
        assert_eq!(store.size(), 0);
        // The oldest go first when the budget is full.
        let each = MAX_LATE_BYTES / 4 + 1;
        for k in 10..16 {
            store.keep(k, Arc::new(Evidence::new(vec![0; each])), acc(), 100);
        }
        assert!(store.size() <= MAX_LATE_BYTES);
        let (r, c) = (Digest::of(b"other"), Digest::of(b"other claims"));
        assert!(
            store.contradiction(&10, &w, r, c).is_none(),
            "oldest dropped"
        );
        assert!(store.contradiction(&15, &w, r, c).is_some(), "newest kept");
        store.expire(100);
        assert_eq!(store.size(), 0);
    }
}
