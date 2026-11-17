//! Checkpoints (C2SP `tlog-checkpoint` signed notes, C2SP `static-ct-api`).
//!
//! [`verify_checkpoint`] accepts a checkpoint only if it carries a valid RFC 6962
//! `TreeHeadSignature` (ECDSA P-256, SHA-256) by the log's pinned key, as a note signature
//! whose key name is the pinned origin and whose key ID is
//! `SHA-256(origin || 0x0A || 0x05 || LogID)[:4]`. Following C2SP `signed-note`:
//! signatures with unknown key names or IDs are ignored, a known key's invalid signature
//! rejects the note, and a note with no valid known signature is rejected. Extension lines
//! are not allowed with this signature type, and the origin line (which the RFC 6962
//! signature does not cover) must equal the pinned origin.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use cybermesh_analysis::CtLogInfo;
use sha2::{Digest as _, Sha256};

use crate::{CtError, TileSource};

/// Largest checkpoint accepted.
const MAX_CHECKPOINT_BYTES: usize = 64 * 1024;
/// Signature lines examined at most.
const MAX_SIGNATURE_LINES: usize = 64;
/// Signed-note signature type of RFC 6962 `TreeHeadSignature`s.
const SIG_TYPE_RFC6962: u8 = 0x05;
/// TLS `HashAlgorithm.sha256` and `SignatureAlgorithm.ecdsa`.
const HASH_SHA256: u8 = 4;
const SIG_ECDSA: u8 = 3;

/// A checkpoint body (origin, tree size, root hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: [u8; 32],
    /// `TreeHeadSignature.timestamp` (ms since the epoch) once verified; 0 if only parsed.
    pub signed_at_ms: u64,
}

impl Checkpoint {
    /// Parses the note text without verifying it. Requires the three mandatory lines.
    pub fn parse(text: &str) -> Result<Self, CtError> {
        if text.len() > MAX_CHECKPOINT_BYTES {
            return Err(CtError::TooLarge);
        }
        let mut lines = text.split('\n');
        let origin = lines
            .next()
            .filter(|l| !l.is_empty())
            .ok_or_else(|| CtError::Malformed("origin".into()))?;
        let size_line = lines
            .next()
            .ok_or_else(|| CtError::Malformed("size".into()))?;
        if size_line.is_empty()
            || !size_line.bytes().all(|b| b.is_ascii_digit())
            || (size_line.len() > 1 && size_line.starts_with('0'))
        {
            return Err(CtError::Malformed("tree size".into()));
        }
        let size: u64 = size_line
            .parse()
            .map_err(|_| CtError::Malformed("tree size".into()))?;
        let root_line = lines
            .next()
            .ok_or_else(|| CtError::Malformed("root".into()))?;
        let root_bytes = B64
            .decode(root_line)
            .map_err(|_| CtError::Malformed("root hash".into()))?;
        let root: [u8; 32] = root_bytes
            .try_into()
            .map_err(|_| CtError::Malformed("root hash length".into()))?;
        Ok(Self {
            origin: origin.to_owned(),
            size,
            root,
            signed_at_ms: 0,
        })
    }

    /// Number of full data tiles.
    #[must_use]
    pub fn full_tiles(&self) -> u64 {
        self.size / 256
    }
}

/// A log's pinned verification key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogKey {
    origin: String,
    /// Uncompressed P-256 point (65 bytes).
    point: Vec<u8>,
    /// RFC 6962 `LogID`: SHA-256 of the DER `SubjectPublicKeyInfo`.
    pub log_id: [u8; 32],
    key_id: [u8; 4],
}

impl LogKey {
    /// The key pinned for `log` (validated `CtLogInfo`).
    pub fn from_info(log: &CtLogInfo) -> Result<Self, CtError> {
        let der = log.public_key_der().ok_or_else(|| {
            CtError::Malformed(format!("{}: invalid pinned public key", log.log_id))
        })?;
        let log_id: [u8; 32] = Sha256::digest(&der).into();
        let mut h = Sha256::new();
        h.update(log.origin.as_bytes());
        h.update([0x0A, SIG_TYPE_RFC6962]);
        h.update(log_id);
        let id: [u8; 32] = h.finalize().into();
        let point = der[cybermesh_analysis::P256_SPKI_PREFIX.len()..].to_vec();
        Ok(Self {
            origin: log.origin.clone(),
            point,
            log_id,
            key_id: [id[0], id[1], id[2], id[3]],
        })
    }

    /// The note signature key ID.
    #[must_use]
    pub fn key_id(&self) -> [u8; 4] {
        self.key_id
    }

    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

/// The RFC 6962 `TreeHeadSignature` input: version v1, signature type `tree_hash`,
/// timestamp, tree size, root hash.
#[must_use]
pub fn tree_head_input(timestamp_ms: u64, size: u64, root: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(50);
    m.extend_from_slice(&[0, 1]);
    m.extend_from_slice(&timestamp_ms.to_be_bytes());
    m.extend_from_slice(&size.to_be_bytes());
    m.extend_from_slice(root);
    m
}

/// Parses an `RFC6962NoteSignature` (after the key ID): timestamp and DER ECDSA signature.
fn parse_note_signature(b: &[u8]) -> Option<(u64, &[u8])> {
    let ts = u64::from_be_bytes(b.get(..8)?.try_into().ok()?);
    let (hash, sig) = (*b.get(8)?, *b.get(9)?);
    let len = usize::from(u16::from_be_bytes(b.get(10..12)?.try_into().ok()?));
    let der = b.get(12..12 + len)?;
    (hash == HASH_SHA256 && sig == SIG_ECDSA && b.len() == 12 + len).then_some((ts, der))
}

/// Verifies a checkpoint against the log's pinned key and origin.
pub fn verify_checkpoint(text: &str, key: &LogKey) -> Result<Checkpoint, CtError> {
    let bad = |m: &str| CtError::Unauthenticated(m.to_owned());
    if text.len() > MAX_CHECKPOINT_BYTES {
        return Err(CtError::TooLarge);
    }
    if text.chars().any(|c| c.is_control() && c != '\n') {
        return Err(bad("control characters in checkpoint"));
    }
    // The note text ends at the last blank line; signature lines follow.
    let split = text
        .rfind("\n\n")
        .ok_or_else(|| bad("no signature block"))?;
    let (note, sigs) = (&text[..=split], &text[split + 2..]);
    if note.split('\n').count() != 4 {
        return Err(bad(
            "checkpoint must have exactly origin, size and root lines",
        ));
    }
    let mut cp = Checkpoint::parse(note)?;
    if cp.origin != key.origin {
        return Err(bad("checkpoint origin is not the pinned origin"));
    }
    let lines = sigs
        .strip_suffix('\n')
        .ok_or_else(|| bad("unterminated signature line"))?;
    let mut verified = None;
    for (i, line) in lines.split('\n').enumerate() {
        if i >= MAX_SIGNATURE_LINES {
            return Err(bad("too many signature lines"));
        }
        let Some(rest) = line.strip_prefix("\u{2014} ") else {
            return Err(bad("malformed signature line"));
        };
        let Some((name, b64)) = rest.split_once(' ') else {
            return Err(bad("malformed signature line"));
        };
        // Unknown key name or ID (another key type, a witness): ignored.
        if name != key.origin {
            continue;
        }
        // A line under the pinned name must at least carry a key ID (signed-note: such a
        // line is otherwise malformed); a different key ID is another key: ignored.
        let blob = B64
            .decode(b64)
            .map_err(|_| bad("malformed signature line under the pinned key name"))?;
        if blob.len() < 4 {
            return Err(bad("malformed signature line under the pinned key name"));
        }
        if blob[..4] != key.key_id {
            continue;
        }
        // The pinned key: its signature must verify, or the whole note is rejected.
        let (ts, der) = parse_note_signature(&blob[4..])
            .ok_or_else(|| bad("malformed RFC 6962 note signature"))?;
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            &key.point,
        )
        .verify(&tree_head_input(ts, cp.size, &cp.root), der)
        .map_err(|_| bad("invalid signature by the pinned log key"))?;
        verified = Some(ts);
    }
    cp.signed_at_ms = verified.ok_or_else(|| bad("no signature by the pinned log key"))?;
    Ok(cp)
}

/// Largest accepted age of a verified checkpoint. Static CT logs publish new checkpoints every
/// few seconds, so an old one means a stale cache or a replay.
pub const MAX_CHECKPOINT_AGE_SECS: u64 = 3600;
/// Largest accepted clock skew for a checkpoint dated in the future.
pub const MAX_CHECKPOINT_SKEW_SECS: u64 = 300;

/// Refuses a verified checkpoint that is older than `max_age_secs` or dated in the future
/// (`now` in Unix seconds).
pub fn check_fresh(cp: &Checkpoint, now: u64, max_age_secs: u64) -> Result<(), CtError> {
    let signed = cp.signed_at_ms / 1000;
    if signed > now.saturating_add(MAX_CHECKPOINT_SKEW_SECS) {
        return Err(CtError::Unauthenticated(
            "checkpoint is dated in the future".into(),
        ));
    }
    if now.saturating_sub(signed) > max_age_secs {
        return Err(CtError::Unauthenticated(format!(
            "checkpoint is {} s old (stale cache or replay)",
            now.saturating_sub(signed)
        )));
    }
    Ok(())
}

/// Fetches the current checkpoint from `src` and verifies it against `log`'s pinned key.
pub fn fetch_verified_checkpoint(
    src: &dyn TileSource,
    log: &CtLogInfo,
) -> Result<Checkpoint, CtError> {
    let key = LogKey::from_info(log)?;
    verify_checkpoint(&src.checkpoint()?, &key)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    /// Let's Encrypt Willow 2027h1 as pinned in `datasets/ct-logs/public-static-ct-logs.json`.
    fn willow() -> CtLogInfo {
        let logs: Vec<CtLogInfo> = serde_json::from_str(include_str!(
            "../../../datasets/ct-logs/public-static-ct-logs.json"
        ))
        .unwrap();
        logs.into_iter()
            .find(|l| l.log_id == "letsencrypt-willow-2027h1")
            .unwrap()
    }

    /// A real checkpoint fetched from the log on 2026-11-17. Besides the RFC 6962 signature
    /// it carries a `grease.invalid` line and two other signature types under the same key
    /// name (different key IDs), which must be ignored.
    const REAL: &str = include_str!("../tests/vectors/willow-2027h1.checkpoint");

    #[test]
    fn verifies_a_real_static_ct_log_checkpoint() {
        let key = LogKey::from_info(&willow()).unwrap();
        let cp = verify_checkpoint(REAL, &key).unwrap();
        assert_eq!(cp.origin, "log.willow.ct.letsencrypt.org/2027h1");
        assert_eq!(cp.size, 1_225_734_888);
        assert!(cp.signed_at_ms > 1_700_000_000_000);
        // Any change to the signed body breaks it.
        let tampered = REAL.replacen("1225734888", "1225734889", 1);
        assert!(verify_checkpoint(&tampered, &key).is_err());
        // Another log's key does not verify it (its signature line is then unknown).
        let mut other = willow();
        other.public_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0y8YK0nyrjCBqRjl0CZkcMOIJLtRrzoSGe5r+bLxzT6T0KIkaXr8fk/QKUoM9u6EuQQ4m13PUyR6kBEFPKRYGw==".into();
        assert!(verify_checkpoint(REAL, &LogKey::from_info(&other).unwrap()).is_err());
        // The origin is pinned (the RFC 6962 signature does not cover it).
        let mut moved = willow();
        moved.origin = "log.example.org/2027h1".into();
        assert!(verify_checkpoint(REAL, &LogKey::from_info(&moved).unwrap()).is_err());
    }

    #[test]
    fn rejects_unsigned_malformed_and_extended_notes() {
        let key = LogKey::from_info(&willow()).unwrap();
        let body = "log.willow.ct.letsencrypt.org/2027h1\n1225734888\nswwUfATOTsfcOsC7vNSIhi7HU2cfvU495Hyq/Nx15Ck=\n";
        let our_line = REAL
            .lines()
            .find(|l| l.contains("gKFEjgAAAa"))
            .unwrap()
            .to_owned();
        for bad in [
            body.to_owned(),                                          // no signatures
            format!("{body}\n— grease.invalid AAAA\n"),               // only unknown keys
            format!("{body}\n{our_line}"),                            // unterminated line
            format!("{}ext\n\n{our_line}\n", body),                   // extension line
            format!("{body}\n- {}\n", &our_line[4..]),                // not an em dash
            format!("{body}\r\n{our_line}\n"),                        // control character
            format!("{body}\n{our_line}\n— {} !!!\n", key.origin()), // undecodable line, pinned name
            format!("{body}\n{our_line}\n— {} AAA=\n", key.origin()), // no key ID, pinned name
        ] {
            assert!(verify_checkpoint(&bad, &key).is_err(), "{bad:?}");
        }
        // A known key's invalid signature rejects the note even if a valid one is present.
        let mut blob = B64.decode(our_line.rsplit(' ').next().unwrap()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        let broken = format!("— {} {}", key.origin(), B64.encode(&blob));
        assert!(verify_checkpoint(&format!("{body}\n{our_line}\n{broken}\n"), &key).is_err());
        assert!(verify_checkpoint(&format!("{body}\n{our_line}\n"), &key).is_ok());
    }

    #[test]
    fn stale_or_future_checkpoints_are_refused() {
        let cp = Checkpoint {
            origin: "o".into(),
            size: 1,
            root: [0; 32],
            signed_at_ms: 1_800_000_000_000,
        };
        let at = 1_800_000_000;
        let max = MAX_CHECKPOINT_AGE_SECS;
        assert!(check_fresh(&cp, at, max).is_ok());
        assert!(check_fresh(&cp, at + max, max).is_ok());
        assert!(check_fresh(&cp, at + max + 1, max).is_err());
        assert!(check_fresh(&cp, at - MAX_CHECKPOINT_SKEW_SECS - 1, max).is_err());
    }

    #[test]
    fn parses_the_spec_example() {
        let t = "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n\n— example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=\n";
        let c = Checkpoint::parse(t).unwrap();
        assert_eq!(c.origin, "example.com/behind-the-sofa");
        assert_eq!(c.size, 20_852_163);
        assert_eq!(c.full_tiles(), 81_453);
        for bad in ["", "o\n012\nAAAA\n", "o\n12\nnot-base64\n", "o\nx\n\n"] {
            assert!(Checkpoint::parse(bad).is_err(), "{bad:?}");
        }
    }
}
