//! Witnessing log checkpoints, and portable proofs that a log showed a split view.
//!
//! **Cosignatures** follow C2SP `tlog-cosignature` (`cosignature/v1`, signature type 0x04,
//! Ed25519). A witness signs
//!
//! ```text
//! cosignature/v1
//! time <seconds since the epoch>
//! <checkpoint body: origin, size and root lines>
//! ```
//!
//! and appends `— <name> base64(key ID || timestamp (8 bytes, big-endian) || signature)` to
//! the note, with key ID `SHA-256(name || 0x0A || 0x04 || public key)[:4]` (C2SP
//! `signed-note`). A cosigned checkpoint is still a valid log checkpoint: verifiers ignore
//! signature lines under names they do not know.
//!
//! A **split view** is a log signing two trees that cannot both belong to one append-only
//! log: two roots for one size, or a smaller tree that is not a prefix of a larger one. A
//! [`SplitViewProof`] holds both signed checkpoints and, for different sizes, the root of the
//! larger tree's first entries with an RFC 6962 consistency proof to the larger root. Anyone
//! holding the log's public key can check it offline, without contacting the log.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use cybermesh_anchor::merkle;
use cybermesh_crypto::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::CtError;
use crate::checkpoint::{Checkpoint, LogKey, verify_checkpoint};
use crate::proof::Consistency;

/// Signed-note signature type of `cosignature/v1` (Ed25519) cosignatures.
pub const SIG_TYPE_COSIGNATURE_V1: u8 = 0x04;
/// Largest note accepted (as for checkpoints).
const MAX_NOTE_BYTES: usize = 64 * 1024;

type Hash = [u8; 32];

fn bad(m: &str) -> CtError {
    CtError::Unauthenticated(m.to_owned())
}

/// A signed-note key name: non-empty, without spaces or `+` (C2SP `signed-note`).
pub fn check_key_name(name: &str) -> Result<(), CtError> {
    if name.is_empty() || name.chars().any(|c| c.is_whitespace() || c == '+') {
        return Err(CtError::Malformed(format!(
            "invalid note key name {name:?}"
        )));
    }
    Ok(())
}

/// The note key ID of a `cosignature/v1` key.
#[must_use]
pub fn cosignature_key_id(name: &str, key: &PublicKey) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update([0x0A, SIG_TYPE_COSIGNATURE_V1]);
    h.update(key.as_bytes());
    let d: [u8; 32] = h.finalize().into();
    [d[0], d[1], d[2], d[3]]
}

/// The note text (origin, size and root lines, each ending in a newline) of a signed note.
fn note_body(note: &str) -> Result<&str, CtError> {
    let split = note.find("\n\n").ok_or_else(|| bad("no signature block"))?;
    Ok(&note[..=split])
}

fn cosigned_message(body: &str, time: u64) -> Vec<u8> {
    format!("cosignature/v1\ntime {time}\n{body}").into_bytes()
}

/// Appends a `cosignature/v1` cosignature by `key` under `name`, at `time` (seconds), to a
/// signed checkpoint note. The caller must have verified the note and checked that it is
/// consistent with every checkpoint of the log it cosigned before.
pub fn cosign(note: &str, name: &str, key: &SecretKey, time: u64) -> Result<String, CtError> {
    check_key_name(name)?;
    if !note.ends_with('\n') {
        return Err(bad("unterminated note"));
    }
    let body = note_body(note)?;
    let sig = key.sign(&cosigned_message(body, time));
    let mut blob = cosignature_key_id(name, &key.public_key()).to_vec();
    blob.extend_from_slice(&time.to_be_bytes());
    blob.extend_from_slice(&sig);
    Ok(format!("{note}\u{2014} {name} {}\n", B64.encode(blob)))
}

/// Verifies the `cosignature/v1` cosignature by `key` under `name` on a checkpoint note and
/// returns its time (seconds). Lines under other names or key IDs are ignored; a line under
/// this name and key ID that does not verify rejects the note, and so does no such line.
pub fn verify_cosignature(note: &str, name: &str, key: &PublicKey) -> Result<u64, CtError> {
    if note.len() > MAX_NOTE_BYTES {
        return Err(CtError::TooLarge);
    }
    if note.chars().any(|c| c.is_control() && c != '\n') {
        return Err(bad("control characters in note"));
    }
    let body = note_body(note)?;
    let sigs = note[body.len() + 1..]
        .strip_suffix('\n')
        .ok_or_else(|| bad("unterminated signature line"))?;
    let id = cosignature_key_id(name, key);
    let mut found = None;
    for line in sigs.split('\n') {
        let Some((n, b64)) = line
            .strip_prefix("\u{2014} ")
            .and_then(|r| r.split_once(' '))
        else {
            return Err(bad("malformed signature line"));
        };
        if n != name {
            continue;
        }
        let blob = B64
            .decode(b64)
            .map_err(|_| bad("malformed cosignature line"))?;
        if blob.len() < 4 || blob[..4] != id {
            continue;
        }
        if blob.len() != 4 + 8 + 64 {
            return Err(bad("malformed cosignature"));
        }
        let time = u64::from_be_bytes(blob[4..12].try_into().map_err(|_| bad("time"))?);
        key.verify(&cosigned_message(body, time), &blob[12..])
            .map_err(|_| bad("invalid cosignature"))?;
        found = Some(time);
    }
    found.ok_or_else(|| bad("no cosignature by this witness"))
}

/// Proof that a log signed two checkpoints that cannot both belong to one append-only log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitViewProof {
    pub v: u16,
    /// The log's origin (checkpoint origin line).
    pub origin: String,
    /// The larger (or equal-size) checkpoint, as a signed note.
    pub larger: String,
    /// The other checkpoint, as a signed note.
    pub smaller: String,
    /// Root of the larger tree's first `smaller` size entries (base64).
    pub prefix_root: String,
    /// RFC 6962 consistency proof from that root to the larger root (base64 hashes); empty
    /// for equal sizes.
    pub proof: Vec<String>,
}

impl SplitViewProof {
    /// Builds a proof from an [`Consistency::Inconsistent`] comparison of `smaller` against
    /// `larger` (both verified notes). `None` for a consistent comparison.
    #[must_use]
    pub fn new(origin: &str, larger: &str, smaller: &str, c: &Consistency) -> Option<Self> {
        let Consistency::Inconsistent { prefix_root, proof } = c else {
            return None;
        };
        Some(Self {
            v: 1,
            origin: origin.to_owned(),
            larger: larger.to_owned(),
            smaller: smaller.to_owned(),
            prefix_root: B64.encode(prefix_root),
            proof: proof.iter().map(|h| B64.encode(h)).collect(),
        })
    }

    /// Checks the proof offline against the log's pinned key: both checkpoints are validly
    /// signed by the log, and they cannot both belong to one append-only log. Returns
    /// (larger, smaller).
    pub fn verify(&self, key: &LogKey) -> Result<(Checkpoint, Checkpoint), CtError> {
        if self.v != 1 {
            return Err(CtError::Malformed("unsupported proof version".into()));
        }
        if self.origin != key.origin() {
            return Err(bad("proof is for another log"));
        }
        let larger = verify_checkpoint(&self.larger, key)?;
        let smaller = verify_checkpoint(&self.smaller, key)?;
        let (m, n) = (smaller.size, larger.size);
        let hash = |s: &str| -> Result<Hash, CtError> {
            B64.decode(s)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| CtError::Malformed("hash".into()))
        };
        let prefix = hash(&self.prefix_root)?;
        let proof = self
            .proof
            .iter()
            .map(|h| hash(h))
            .collect::<Result<Vec<Hash>, CtError>>()?;
        let proven = if m > n {
            false
        } else if m == n {
            proof.is_empty() && prefix == larger.root && smaller.root != larger.root
        } else if m == 0 {
            proof.is_empty() && prefix == merkle::empty_root() && smaller.root != prefix
        } else {
            merkle::verify_consistency(m, n, &prefix, &larger.root, &proof)
                && smaller.root != prefix
        };
        if proven {
            Ok((larger, smaller))
        } else {
            Err(bad("the checkpoints are not shown to be inconsistent"))
        }
    }
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::TileSource;
    use crate::mock::{MockLog, demo_entries};
    use crate::proof::TileAuthenticator;

    fn key_of(log: &MockLog) -> LogKey {
        LogKey::from_info(&log.log_info("mock", "http://127.0.0.1/")).unwrap()
    }

    #[test]
    fn cosignatures_follow_c2sp_and_keep_the_log_signature_valid() {
        let log = MockLog::build("mock.example/log", &demo_entries(1)).unwrap();
        let note = log.checkpoint().unwrap();
        let w = SecretKey::from_seed(&[7; 32]);
        let name = "cybermesh/test/w1";
        let cosigned = cosign(&note, name, &w, 1_800_000_000).unwrap();
        // The log's own signature still verifies (the witness line is an unknown key).
        assert_eq!(
            verify_checkpoint(&cosigned, &key_of(&log)).unwrap().size,
            256
        );
        assert_eq!(
            verify_cosignature(&cosigned, name, &w.public_key()).unwrap(),
            1_800_000_000
        );
        // The signed message is exactly the C2SP one.
        let blob = B64
            .decode(cosigned.lines().last().unwrap().rsplit(' ').next().unwrap())
            .unwrap();
        assert_eq!(blob[..4], cosignature_key_id(name, &w.public_key()));
        let body = note_body(&note).unwrap();
        let msg = format!("cosignature/v1\ntime 1800000000\n{body}");
        assert!(msg.ends_with('\n') && msg.lines().count() == 5);
        w.public_key().verify(msg.as_bytes(), &blob[12..]).unwrap();
        // Another witness, another name, a changed time or tree: refused.
        let other = SecretKey::from_seed(&[8; 32]);
        assert!(verify_cosignature(&cosigned, name, &other.public_key()).is_err());
        assert!(verify_cosignature(&cosigned, "cybermesh/test/w2", &w.public_key()).is_err());
        let mut b = blob.clone();
        b[11] ^= 1;
        let line = format!("\u{2014} {name} {}\n", B64.encode(&b));
        let forged = format!("{note}{line}");
        assert!(verify_cosignature(&forged, name, &w.public_key()).is_err());
        let moved = cosigned.replacen("\n256\n", "\n512\n", 1);
        assert!(verify_cosignature(&moved, name, &w.public_key()).is_err());
        assert!(cosign(&note, "has space", &w, 1).is_err());
        assert!(cosign(&note, "a+b", &w, 1).is_err());
    }

    #[test]
    fn a_split_view_proof_is_checkable_offline_and_cannot_be_forged() {
        // One log key, two views: both share the first tile, then diverge.
        let base = MockLog::build("mock.example/log", &demo_entries(1)).unwrap();
        let mut a = base.clone();
        a.extend(&demo_entries(2)).unwrap();
        let mut b = base.clone();
        b.extend(&demo_entries(1)).unwrap();
        let key = key_of(&base);
        let (na, nb) = (a.checkpoint().unwrap(), b.checkpoint().unwrap());
        let (ca, cb) = (
            verify_checkpoint(&na, &key).unwrap(),
            verify_checkpoint(&nb, &key).unwrap(),
        );
        assert!(ca.size > cb.size);
        let auth = TileAuthenticator::new(&a, ca.clone());
        let c = auth.consistency_with(&cb).unwrap();
        let proof = SplitViewProof::new(key.origin(), &na, &nb, &c).unwrap();
        let (l, s) = proof.verify(&key).unwrap();
        assert_eq!((l.size, s.size), (768, 512));
        // It survives a round trip through JSON, and the witnesses' cosignatures.
        let w = SecretKey::from_seed(&[1; 32]);
        let mut cosigned = proof.clone();
        cosigned.smaller = cosign(&nb, "cybermesh/t/w", &w, 5).unwrap();
        let back: SplitViewProof =
            serde_json::from_str(&serde_json::to_string(&cosigned).unwrap()).unwrap();
        back.verify(&key).unwrap();

        // The earlier checkpoint of the same view is consistent: no proof.
        let ok = auth
            .consistency_with(&verify_checkpoint(&base.checkpoint().unwrap(), &key).unwrap())
            .unwrap();
        assert!(SplitViewProof::new(key.origin(), &na, &base.checkpoint().unwrap(), &ok).is_none());

        // Forgeries: a proof claiming the consistent pair, a tampered proof hash, a
        // checkpoint not signed by the log, swapped roles, another log's key.
        let mut fake = proof.clone();
        fake.smaller = base.checkpoint().unwrap();
        assert!(fake.verify(&key).is_err());
        let mut fake = proof.clone();
        let mut h = B64.decode(&fake.proof[0]).unwrap();
        h[0] ^= 1;
        fake.proof[0] = B64.encode(h);
        assert!(fake.verify(&key).is_err());
        let mut fake = proof.clone();
        fake.smaller = fake.smaller.replacen("\n512\n", "\n513\n", 1);
        assert!(fake.verify(&key).is_err());
        let mut fake = proof.clone();
        std::mem::swap(&mut fake.larger, &mut fake.smaller);
        assert!(fake.verify(&key).is_err());
        let other = LogKey::from_info(
            &MockLog::build("other.example/log", &demo_entries(1))
                .unwrap()
                .log_info("x", "http://127.0.0.1/"),
        )
        .unwrap();
        assert!(proof.verify(&other).is_err());

        // Equal sizes, different roots: proven by the two signatures alone.
        let mut c2 = base.clone();
        c2.extend(&demo_entries(1)).unwrap();
        let nc = c2.checkpoint().unwrap();
        let cc = verify_checkpoint(&nc, &key).unwrap();
        assert_eq!(cc.size, cb.size);
        let auth = TileAuthenticator::new(&b, cb);
        let c = auth.consistency_with(&cc).unwrap();
        let p = SplitViewProof::new(key.origin(), &nb, &nc, &c).unwrap();
        assert!(p.proof.is_empty());
        p.verify(&key).unwrap();
    }
}
