//! Distribution of verification records between verifiers over the network.
//!
//! Release signers need the signed records of `min_verifiers` verifier organisations. Rather
//! than collecting files from every organisation by hand, each verifier (the coordinator and
//! every independent verifier) publishes the records it signs on the `records` gossip topic,
//! and stores the records of the others in `received-records/`. An organisation's release
//! signer then builds from its own node's `records/` and `received-records/`.
//!
//! Received records are authenticated exactly as `cybermesh release build` does
//! ([`verify_record_envelope`]): enrolled verifier signature, canonical record for this
//! network, and a named verifier that is the signer with the manifest's operator. The store:
//! - keeps only the record verifier's own signature (a peer re-wrapping a record with junk
//!   signatures cannot inflate what is stored);
//! - is bounded in records and bytes, overall and per verifier operator, with at most
//!   [`MAX_PER_OPERATOR_TASK`] records per operator and task;
//! - refuses records from the future or older than [`MAX_RECORD_AGE_SECS`], prunes records as
//!   they age out, and re-checks everything when a newer trust manifest is loaded (records of
//!   revoked verifiers are removed).
//!
//! Records are re-published for a while (also after a restart) so a peer that was briefly
//! disconnected still receives them. Workers do not subscribe to the topic.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cybermesh_crypto::{CryptoError, Digest, Envelope, KeyId, canonical};
use cybermesh_network::{NetError, NetworkHandle};
use cybermesh_protocol::{OperatorId, ProtocolError, Role, TrustManifest, payload_type};
use cybermesh_verifier::{VerificationRecord, verify_record_envelope};
use tracing::{debug, info, warn};

use crate::NodeError;
use crate::files;

/// Records kept in `received-records/`.
pub const MAX_STORED_RECORDS: usize = 100_000;
/// Bytes kept in `received-records/`.
pub const MAX_STORED_BYTES: usize = 1 << 30;
/// Records and bytes per verifier operator (one operator cannot crowd out the others).
pub const MAX_PER_OPERATOR: usize = 25_000;
pub const MAX_BYTES_PER_OPERATOR: usize = 256 << 20;
/// Records per operator and task id (an honest verifier signs one record per task attempt).
pub const MAX_PER_OPERATOR_TASK: usize = 2;
/// Records older than this are refused and pruned (releases use 30 days at most).
pub const MAX_RECORD_AGE_SECS: u64 = 30 * 86_400;
/// Accepted clock skew for a record's `verified_at`.
const MAX_SKEW_SECS: u64 = 300;
/// Parsed records kept in memory for reports and tests (the rest stay on disk).
const MAX_IN_MEMORY: usize = 4096;
/// Own records remembered for re-publication.
const MAX_RECENT: usize = 256;
/// Queued publications; further records wait for the next re-publication round.
const MAX_OUTBOX: usize = 1024;
/// Publications per call of [`RecordPublisher::flush`] (keeps the event loop responsive).
const MAX_FLUSH_PER_TICK: usize = 32;
/// A record that could not be published (no peers) is retried for this long.
const PUBLISH_RETRY_FOR: Duration = Duration::from_secs(120);
/// Own records are re-published this often (longer than the gossip duplicate cache of 10
/// minutes, so peers that missed them receive them) ...
pub const REPUBLISH_EVERY: Duration = Duration::from_secs(900);
/// ... if they were verified within this window.
pub const REPUBLISH_WINDOW_SECS: u64 = 3600;

/// What happened to a record received from the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// New, valid record from another verifier; stored.
    Stored { operator: OperatorId },
    /// Already stored.
    Duplicate,
    /// Signed by this node's own key (gossip echo); ignored.
    Own,
    /// Not stored for a reason that does not prove misbehaviour by the sender: a quota is
    /// full, the record is too old or dated ahead (clocks), its signer is unknown to this
    /// node's manifest (which may lag), or it could not be written.
    Ignored(String),
    /// Provably invalid: malformed, wrong network, or misattributed to another verifier.
    Rejected(String),
}

fn hex(d: &Digest) -> String {
    use std::fmt::Write as _;
    d.as_bytes().iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Re-encodes a verified record envelope with only the record verifier's own (valid)
/// signature, so the stored bytes cannot be inflated with junk signature entries.
fn normalized(
    bytes: &[u8],
    rec: &VerificationRecord,
    manifest: &TrustManifest,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    let env = Envelope::parse(bytes, max_bytes).ok()?;
    let pk = manifest.key_with_role(&rec.verifier.key, Role::Verifier)?;
    env.signatures
        .iter()
        .filter(|s| KeyId::parse(&s.keyid).is_ok_and(|k| k == rec.verifier.key))
        .find_map(|s| {
            let one = Envelope {
                payload_type: env.payload_type.clone(),
                payload: env.payload.clone(),
                signatures: vec![s.clone()],
            };
            one.verify(payload_type::VERIFICATION, 1, |id| {
                (*id == rec.verifier.key).then_some(pk)
            })
            .ok()?;
            one.to_vec().ok()
        })
}

#[derive(Debug, Clone)]
struct Entry {
    operator: OperatorId,
    task_id: String,
    task_digest: Digest,
    verified_at: u64,
    size: usize,
}

/// Records received from other verifiers, persisted in a directory.
#[derive(Debug)]
pub struct RecordStore {
    dir: PathBuf,
    me: KeyId,
    max_bytes: usize,
    entries: HashMap<Digest, Entry>,
    /// Digests of raw envelopes already processed (cheap duplicate filter before verifying).
    raw_seen: HashSet<Digest>,
    per_operator: HashMap<OperatorId, (usize, usize)>,
    per_operator_task: HashMap<(OperatorId, String), usize>,
    /// (task id, task digest) -> operators whose records for it are stored.
    by_task: HashMap<(String, Digest), BTreeSet<OperatorId>>,
    total_bytes: usize,
    /// Up to `MAX_IN_MEMORY` stored records, parsed, for reports and tests.
    pub received: Vec<(Digest, VerificationRecord)>,
}

impl RecordStore {
    /// Opens (creating) `dir`, re-reading the records in it; records that no longer verify
    /// or have aged out are removed.
    pub fn open(
        dir: &Path,
        me: KeyId,
        manifest: &TrustManifest,
        max_bytes: usize,
        now: u64,
    ) -> Result<Self, NodeError> {
        std::fs::create_dir_all(dir).map_err(|e| NodeError::Io(e.to_string()))?;
        let mut store = Self {
            dir: dir.to_path_buf(),
            me,
            max_bytes,
            entries: HashMap::new(),
            raw_seen: HashSet::new(),
            per_operator: HashMap::new(),
            per_operator_task: HashMap::new(),
            by_task: HashMap::new(),
            total_bytes: 0,
            received: Vec::new(),
        };
        store.rescan(manifest, now)?;
        Ok(store)
    }

    /// Rebuilds the index from disk against `manifest` (call after loading a newer manifest).
    /// Files that do not verify, have aged out or exceed the quotas are deleted.
    pub fn rescan(&mut self, manifest: &TrustManifest, now: u64) -> Result<(), NodeError> {
        self.entries.clear();
        self.raw_seen.clear();
        self.per_operator.clear();
        self.per_operator_task.clear();
        self.by_task.clear();
        self.total_bytes = 0;
        self.received.clear();
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&self.dir)
            .map_err(|e| NodeError::Io(e.to_string()))?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json") && p.is_file())
            .collect();
        paths.sort();
        let mut removed = 0usize;
        for p in paths {
            let keep = files::read_bytes(&p).ok().and_then(|bytes| {
                let (d, rec) = verify_record_envelope(&bytes, manifest, self.max_bytes).ok()?;
                let fresh = rec.verified_at <= now.saturating_add(MAX_SKEW_SECS)
                    && now.saturating_sub(rec.verified_at) <= MAX_RECORD_AGE_SECS;
                (fresh && rec.verifier.key != self.me && self.has_room(&rec, bytes.len()))
                    .then_some((d, rec, bytes.len()))
            });
            match keep {
                Some((d, rec, size)) if !self.entries.contains_key(&d) => {
                    self.index(d, rec, size);
                }
                _ => {
                    removed += 1;
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
        if removed > 0 {
            info!(
                removed,
                kept = self.entries.len(),
                "received records re-checked"
            );
        }
        Ok(())
    }

    /// Deletes records that have aged out.
    pub fn prune(&mut self, now: u64) {
        let old: Vec<Digest> = self
            .entries
            .iter()
            .filter(|(_, e)| now.saturating_sub(e.verified_at) > MAX_RECORD_AGE_SECS)
            .map(|(d, _)| *d)
            .collect();
        for d in old {
            let _ = std::fs::remove_file(self.dir.join(format!("{}.json", hex(&d))));
            self.unindex(&d);
        }
    }

    fn has_room(&self, rec: &VerificationRecord, size: usize) -> bool {
        let (n, b) = self
            .per_operator
            .get(&rec.verifier.operator)
            .copied()
            .unwrap_or((0, 0));
        let per_task = self
            .per_operator_task
            .get(&(rec.verifier.operator.clone(), rec.task_id.clone()))
            .copied()
            .unwrap_or(0);
        self.entries.len() < MAX_STORED_RECORDS
            && self.total_bytes.saturating_add(size) <= MAX_STORED_BYTES
            && n < MAX_PER_OPERATOR
            && b.saturating_add(size) <= MAX_BYTES_PER_OPERATOR
            && per_task < MAX_PER_OPERATOR_TASK
    }

    fn index(&mut self, d: Digest, rec: VerificationRecord, size: usize) {
        let op = rec.verifier.operator.clone();
        let e = self.per_operator.entry(op.clone()).or_insert((0, 0));
        e.0 += 1;
        e.1 += size;
        *self
            .per_operator_task
            .entry((op.clone(), rec.task_id.clone()))
            .or_insert(0) += 1;
        self.by_task
            .entry((rec.task_id.clone(), rec.task_digest))
            .or_default()
            .insert(op.clone());
        self.total_bytes += size;
        self.entries.insert(
            d,
            Entry {
                operator: op,
                task_id: rec.task_id.clone(),
                task_digest: rec.task_digest,
                verified_at: rec.verified_at,
                size,
            },
        );
        if self.received.len() < MAX_IN_MEMORY {
            self.received.push((d, rec));
        }
    }

    fn unindex(&mut self, d: &Digest) {
        let Some(e) = self.entries.remove(d) else {
            return;
        };
        if let Some(x) = self.per_operator.get_mut(&e.operator) {
            x.0 = x.0.saturating_sub(1);
            x.1 = x.1.saturating_sub(e.size);
        }
        if let Some(n) = self
            .per_operator_task
            .get_mut(&(e.operator.clone(), e.task_id.clone()))
        {
            *n = n.saturating_sub(1);
        }
        let key = (e.task_id.clone(), e.task_digest);
        let still = self.entries.values().any(|o| {
            o.operator == e.operator && o.task_id == e.task_id && o.task_digest == e.task_digest
        });
        if !still && let Some(ops) = self.by_task.get_mut(&key) {
            ops.remove(&e.operator);
        }
        self.total_bytes = self.total_bytes.saturating_sub(e.size);
        self.received.retain(|(x, _)| x != d);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Distinct operators other than `me_op` whose records for this exact task (id and
    /// payload digest) are stored. Any status counts: a verifier that recorded the task
    /// has finished with it.
    #[must_use]
    pub fn other_operators(
        &self,
        task_id: &str,
        task_digest: &Digest,
        me_op: &OperatorId,
    ) -> usize {
        self.by_task
            .get(&(task_id.to_owned(), *task_digest))
            .map_or(0, |ops| ops.iter().filter(|o| *o != me_op).count())
    }

    /// Authenticates and stores a record received from the network.
    pub fn accept(&mut self, bytes: &[u8], manifest: &TrustManifest, now: u64) -> Received {
        let raw = Digest::of(bytes);
        if self.raw_seen.contains(&raw) {
            return Received::Duplicate;
        }
        let (d, rec) = match verify_record_envelope(bytes, manifest, self.max_bytes) {
            Ok(x) => x,
            // No signer this node's manifest knows: possibly a newly enrolled verifier (the
            // manifest here may lag), so not proof of misbehaviour.
            Err(ProtocolError::Crypto(CryptoError::InsufficientSignatures { .. })) => {
                return Received::Ignored("no signature from a verifier known here".into());
            }
            // Only proof of misbehaviour counts against the sender (peer scoring): a version
            // this node cannot decode, or a manifest older than the sender's, does not.
            Err(e) if !e.proves_misbehaviour() => return Received::Ignored(e.to_string()),
            Err(e) => return Received::Rejected(e.to_string()),
        };
        if self.raw_seen.len() >= 4 * MAX_STORED_RECORDS {
            self.raw_seen.clear();
        }
        self.raw_seen.insert(raw);
        if rec.verifier.key == self.me {
            return Received::Own;
        }
        if rec.verified_at > now.saturating_add(MAX_SKEW_SECS) {
            return Received::Ignored("record is dated in the future".into());
        }
        if now.saturating_sub(rec.verified_at) > MAX_RECORD_AGE_SECS {
            return Received::Ignored("record is too old".into());
        }
        if self.entries.contains_key(&d) {
            return Received::Duplicate;
        }
        let Some(stored) = normalized(bytes, &rec, manifest, self.max_bytes) else {
            return Received::Ignored("record verifier's signature not found".into());
        };
        if !self.has_room(&rec, stored.len()) {
            return Received::Ignored("record store quota reached".into());
        }
        let path = self.dir.join(format!("{}.json", hex(&d)));
        if let Err(e) = files::write_atomic(&path, &stored) {
            return Received::Ignored(format!("could not store: {e}"));
        }
        let operator = rec.verifier.operator.clone();
        self.index(d, rec, stored.len());
        Received::Stored { operator }
    }
}

struct Pending {
    bytes: Vec<u8>,
    first_try: Instant,
}

/// Publishes this node's own signed records, and re-publishes recent ones.
#[derive(Default)]
pub struct RecordPublisher {
    outbox: VecDeque<Pending>,
    /// (verified_at, envelope bytes) of recent own records.
    recent: VecDeque<(u64, Vec<u8>)>,
    max_bytes: usize,
    last_round: Option<Instant>,
    pub published: u64,
    /// Records larger than the network's message limit (kept only as files).
    pub too_large: u64,
    /// Records given up on after `PUBLISH_RETRY_FOR` without peers.
    pub dropped: u64,
}

impl std::fmt::Debug for RecordPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordPublisher")
            .field("outbox", &self.outbox.len())
            .field("recent", &self.recent.len())
            .field("published", &self.published)
            .finish_non_exhaustive()
    }
}

impl RecordPublisher {
    #[must_use]
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            ..Self::default()
        }
    }

    /// Re-reads this node's own recent records (after a restart) so they are re-published.
    pub fn load_recent(&mut self, own_dir: &Path, now: u64) {
        let Ok(rd) = std::fs::read_dir(own_dir) else {
            return;
        };
        let mut found: Vec<(u64, Vec<u8>)> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .filter_map(|p| {
                let bytes = files::read_bytes(&p).ok()?;
                let env = Envelope::parse(&bytes, self.max_bytes).ok()?;
                let rec: VerificationRecord =
                    canonical::from_slice(&env.payload_bytes().ok()?).ok()?;
                (now.saturating_sub(rec.verified_at) <= REPUBLISH_WINDOW_SECS)
                    .then_some((rec.verified_at, bytes))
            })
            .collect();
        found.sort_by_key(|(at, _)| *at);
        for (at, b) in found.into_iter().rev().take(MAX_RECENT).rev() {
            self.recent.push_back((at, b));
        }
    }

    /// Queues a freshly signed record envelope for publication.
    pub fn queue(&mut self, envelope: Vec<u8>, verified_at: u64) {
        if envelope.len() > self.max_bytes {
            self.too_large += 1;
            warn!(
                bytes = envelope.len(),
                "verification record exceeds the network message limit; not distributed (the file is still written)"
            );
            return;
        }
        if self.recent.len() >= MAX_RECENT {
            self.recent.pop_front();
        }
        self.recent.push_back((verified_at, envelope.clone()));
        self.push(envelope);
    }

    fn push(&mut self, bytes: Vec<u8>) {
        if self.outbox.len() < MAX_OUTBOX {
            self.outbox.push_back(Pending {
                bytes,
                first_try: Instant::now(),
            });
        }
    }

    /// Re-queues recent own records every `every`, for those verified within `window`.
    pub fn republish_due(&mut self, now: u64, every: Duration, window: u64) {
        let due = self.last_round.is_none_or(|t| t.elapsed() >= every);
        if !due {
            return;
        }
        self.last_round = Some(Instant::now());
        let again: Vec<Vec<u8>> = self
            .recent
            .iter()
            .filter(|(at, _)| now.saturating_sub(*at) <= window)
            .map(|(_, b)| b.clone())
            .collect();
        for b in again {
            self.push(b);
        }
    }

    /// Publishes up to `MAX_FLUSH_PER_TICK` queued records. Stops at the first record that
    /// cannot be sent yet (no peers subscribed) and retries it later; a duplicate (peers
    /// already have it) counts as delivered.
    pub async fn flush(&mut self, net: &NetworkHandle, topic: &str) {
        for _ in 0..MAX_FLUSH_PER_TICK {
            let Some(p) = self.outbox.front() else {
                break;
            };
            match net.publish(topic, p.bytes.clone()).await {
                Ok(()) => {
                    self.published += 1;
                    self.outbox.pop_front();
                }
                Err(NetError::Duplicate) => {
                    self.outbox.pop_front();
                }
                Err(e) => {
                    if p.first_try.elapsed() >= PUBLISH_RETRY_FOR {
                        self.dropped += 1;
                        self.outbox.pop_front();
                        continue;
                    }
                    debug!(error = %e, "record publish deferred");
                    break;
                }
            }
        }
    }

    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.outbox.is_empty()
    }
}

/// True when every task in `own_tasks` (task id, task digest) has records from at least
/// `need` other verifier operators in `store`.
#[must_use]
pub fn quorum_records_present(
    store: &RecordStore,
    own_tasks: &[(String, Digest)],
    me_op: &OperatorId,
    need: usize,
) -> bool {
    need == 0
        || own_tasks
            .iter()
            .all(|(t, d)| store.other_operators(t, d, me_op) >= need)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::collections::BTreeMap;

    use cybermesh_crypto::{EnvSignature, SecretKey};
    use cybermesh_protocol::testkit::{TestNetwork, test_key};
    use cybermesh_protocol::{EngineSpec, Limits, Revocation};
    use cybermesh_verifier::{Policy, TaskVerifier, VerifierId};

    use super::*;

    const NOW: u64 = 1_800_000_000;
    const MAX: usize = 256 * 1024;

    struct Fx {
        net: TestNetwork,
        me: VerifierId,
        b: VerifierId,
        b_key: SecretKey,
    }

    fn fx() -> Fx {
        let net = TestNetwork::new(&[("org-a", 1), ("org-b", 1), ("org-c", 1)], NOW);
        let me = VerifierId {
            key: net.verifier.key_id(),
            operator: OperatorId::new("org-a").unwrap(),
        };
        let (b_key, b_op) = &net.other_verifiers[0];
        let b = VerifierId {
            key: b_key.key_id(),
            operator: b_op.clone(),
        };
        let b_key = SecretKey::from_seed(&b_key.seed());
        Fx { net, me, b, b_key }
    }

    /// A signed record for a task over `domain`, by `signer`, claiming `claimed`.
    fn record(f: &Fx, domain: &str, claimed: &VerifierId, signer: &SecretKey, at: u64) -> Vec<u8> {
        let task = f.net.task(
            &[domain],
            &[0, 1, 2],
            EngineSpec {
                name: "e".into(),
                version: "1".into(),
            },
            BTreeMap::new(),
            NOW,
        );
        let digest = Digest::of(&canonical::to_vec(&task).unwrap());
        let rec = TaskVerifier::new(
            task,
            digest,
            claimed.clone(),
            Policy::default(),
            Limits::default(),
        )
        .unwrap()
        .finalize(None, at);
        Envelope::sign(
            payload_type::VERIFICATION,
            &canonical::to_vec(&rec).unwrap(),
            signer,
        )
        .to_vec()
        .unwrap()
    }

    #[test]
    fn stores_only_valid_records_of_other_verifiers() {
        let f = fx();
        let dir = tempfile::tempdir().unwrap();
        let mut store =
            RecordStore::open(dir.path(), f.me.key.clone(), &f.net.manifest, MAX, NOW).unwrap();
        let good = record(&f, "a.example.com", &f.b, &f.b_key, NOW);
        assert_eq!(
            store.accept(&good, &f.net.manifest, NOW),
            Received::Stored {
                operator: f.b.operator.clone()
            }
        );
        assert_eq!(
            store.accept(&good, &f.net.manifest, NOW),
            Received::Duplicate
        );
        let (task, digest) = {
            let r = &store.received[0].1;
            (r.task_id.clone(), r.task_digest)
        };
        assert_eq!(store.other_operators(&task, &digest, &f.me.operator), 1);
        assert_eq!(
            store.other_operators(&task, &Digest::of(b"other"), &f.me.operator),
            0
        );

        // Own echo; misattribution is rejected (provable); bytes this version cannot decode
        // (a newer format looks the same) and clocks are ignored.
        let own = record(&f, "a.example.com", &f.me, &f.net.verifier, NOW);
        assert_eq!(store.accept(&own, &f.net.manifest, NOW), Received::Own);
        let relabelled = record(&f, "b.example.com", &f.b, &f.net.verifier, NOW);
        assert!(matches!(
            store.accept(&relabelled, &f.net.manifest, NOW),
            Received::Rejected(_)
        ));
        assert!(matches!(
            store.accept(b"not a record", &f.net.manifest, NOW),
            Received::Ignored(_)
        ));
        let future = record(&f, "c.example.com", &f.b, &f.b_key, NOW + 3600);
        assert!(matches!(
            store.accept(&future, &f.net.manifest, NOW),
            Received::Ignored(_)
        ));
        let stale = record(
            &f,
            "d.example.com",
            &f.b,
            &f.b_key,
            NOW - MAX_RECORD_AGE_SECS - 1,
        );
        assert!(matches!(
            store.accept(&stale, &f.net.manifest, NOW),
            Received::Ignored(_)
        ));
        // A key this node's manifest does not know yet (it may lag): ignored, not penalised.
        let stranger = test_key("not-yet-enrolled");
        let unknown = record(&f, "e.example.com", &f.b, &stranger, NOW);
        assert!(matches!(
            store.accept(&unknown, &f.net.manifest, NOW),
            Received::Ignored(_)
        ));
        assert_eq!(store.len(), 1);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);

        // A restart re-reads what was stored; the stored file verifies like any record.
        let again =
            RecordStore::open(dir.path(), f.me.key.clone(), &f.net.manifest, MAX, NOW).unwrap();
        assert_eq!(again.len(), 1);
        let own_tasks = vec![(task, digest)];
        assert!(quorum_records_present(
            &again,
            &own_tasks,
            &f.me.operator,
            1
        ));
        assert!(!quorum_records_present(
            &again,
            &own_tasks,
            &f.me.operator,
            2
        ));
        assert!(quorum_records_present(&again, &[], &f.me.operator, 3));
    }

    #[test]
    fn rewrapped_records_are_stored_normalized_and_quotas_hold() {
        let f = fx();
        let dir = tempfile::tempdir().unwrap();
        let mut store =
            RecordStore::open(dir.path(), f.me.key.clone(), &f.net.manifest, MAX, NOW).unwrap();
        // A relay re-wraps an honest record with junk signature entries.
        let honest = record(&f, "a.example.com", &f.b, &f.b_key, NOW);
        let mut env = Envelope::parse(&honest, MAX).unwrap();
        for i in 0..15 {
            env.signatures.insert(
                0,
                EnvSignature {
                    keyid: format!("{:0>64}", i),
                    sig: "A".repeat(4000),
                },
            );
        }
        let bloated = env.to_vec().unwrap();
        assert!(bloated.len() > 10 * honest.len());
        assert!(matches!(
            store.accept(&bloated, &f.net.manifest, NOW),
            Received::Stored { .. }
        ));
        let stored_size: u64 = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum();
        assert!(
            stored_size <= honest.len() as u64 + 16,
            "{stored_size} vs {}",
            honest.len()
        );
        assert_eq!(
            store.accept(&honest, &f.net.manifest, NOW),
            Received::Duplicate
        );

        // At most MAX_PER_OPERATOR_TASK records per operator and task id.
        let (task_id, _) = {
            let r = &store.received[0].1;
            (r.task_id.clone(), r.task_digest)
        };
        let mut extra = 0;
        for at in 1..=5u64 {
            let b = record(&f, "a.example.com", &f.b, &f.b_key, NOW - at);
            let parsed = verify_record_envelope(&b, &f.net.manifest, MAX).unwrap().1;
            assert_eq!(parsed.task_id, task_id);
            if matches!(
                store.accept(&b, &f.net.manifest, NOW),
                Received::Stored { .. }
            ) {
                extra += 1;
            }
        }
        assert_eq!(extra, MAX_PER_OPERATOR_TASK - 1);
    }

    #[test]
    fn revoked_verifiers_records_are_removed_and_old_ones_pruned() {
        let mut f = fx();
        let dir = tempfile::tempdir().unwrap();
        let mut store =
            RecordStore::open(dir.path(), f.me.key.clone(), &f.net.manifest, MAX, NOW).unwrap();
        let old = record(
            &f,
            "a.example.com",
            &f.b,
            &f.b_key,
            NOW - MAX_RECORD_AGE_SECS + 10,
        );
        let fresh = record(&f, "b.example.com", &f.b, &f.b_key, NOW);
        assert!(matches!(
            store.accept(&old, &f.net.manifest, NOW),
            Received::Stored { .. }
        ));
        assert!(matches!(
            store.accept(&fresh, &f.net.manifest, NOW),
            Received::Stored { .. }
        ));
        store.prune(NOW + 20);
        assert_eq!(store.len(), 1);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        // Governance revokes org-b's verifier: a re-check removes its records.
        f.net.manifest.revocations.push(Revocation {
            key_id: f.b.key.clone(),
            revoked_at: NOW,
            reason: "compromised".into(),
        });
        store.rescan(&f.net.manifest, NOW).unwrap();
        assert!(store.is_empty());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn publisher_skips_oversized_records_and_bounds_republication() {
        let mut p = RecordPublisher::new(1000);
        p.queue(vec![0u8; 1001], NOW);
        assert_eq!(p.too_large, 1);
        assert!(p.is_idle());
        p.queue(vec![1u8; 10], NOW);
        p.queue(vec![2u8; 10], NOW - 7200);
        assert_eq!(p.outbox.len(), 2);
        p.outbox.clear();
        // Re-publication re-queues only records within the window.
        p.republish_due(NOW, Duration::ZERO, 3600);
        assert_eq!(p.outbox.len(), 1);
    }

    #[test]
    fn own_records_are_republished_after_a_restart() {
        let f = fx();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("t-0.json"),
            record(&f, "a.example.com", &f.me, &f.net.verifier, NOW - 60),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("t-1.json"),
            record(&f, "b.example.com", &f.me, &f.net.verifier, NOW - 7200),
        )
        .unwrap();
        let mut p = RecordPublisher::new(MAX);
        p.load_recent(dir.path(), NOW);
        assert_eq!(p.recent.len(), 1, "only records within the window");
        p.republish_due(NOW, REPUBLISH_EVERY, REPUBLISH_WINDOW_SECS);
        assert_eq!(p.outbox.len(), 1);
    }
}
