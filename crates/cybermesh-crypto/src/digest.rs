use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use crate::CryptoError;

const PREFIX: &str = "sha256:";

/// A SHA-256 digest. Serialised as `sha256:<64 lowercase hex chars>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// SHA-256 of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Domain-separated SHA-256: `SHA256(tag || 0x00 || part_0 || ... )`, where every part
    /// is prefixed by its length as a big-endian u64 so concatenations are unambiguous.
    #[must_use]
    pub fn tagged(tag: &str, parts: &[&[u8]]) -> Self {
        let mut h = Sha256::new();
        h.update(tag.as_bytes());
        h.update([0u8]);
        for p in parts {
            h.update((p.len() as u64).to_be_bytes());
            h.update(p);
        }
        Self(h.finalize().into())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Bare lowercase hex (no prefix).
    #[must_use]
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses either `sha256:<hex>` or bare hex.
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        let h = s.strip_prefix(PREFIX).unwrap_or(s);
        if h.len() != 64 || h.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(CryptoError::InvalidHex(
                "digest must be 64 lowercase hex characters".into(),
            ));
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(h, &mut out).map_err(|e| CryptoError::InvalidHex(e.to_string()))?;
        Ok(Self(out))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PREFIX}{}", self.hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({self})")
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        // On the wire the prefix is mandatory so that the encoding is canonical.
        if !s.starts_with(PREFIX) {
            return Err(serde::de::Error::custom("digest must start with sha256:"));
        }
        Digest::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        // SHA-256("abc")
        assert_eq!(
            Digest::of(b"abc").hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn tagged_is_domain_separated() {
        assert_ne!(
            Digest::tagged("a", &[b"bc"]),
            Digest::tagged("ab", &[b"c"])
        );
        assert_ne!(
            Digest::tagged("t", &[b"ab", b"c"]),
            Digest::tagged("t", &[b"a", b"bc"])
        );
    }

    #[test]
    fn serde_roundtrip_and_strictness() {
        let d = Digest::of(b"x");
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.starts_with("\"sha256:"));
        let back: Digest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
        let upper = json.to_uppercase().replace("SHA256:", "sha256:");
        assert!(serde_json::from_str::<Digest>(&upper).is_err());
        let bare = format!("\"{}\"", d.hex());
        assert!(serde_json::from_str::<Digest>(&bare).is_err());
    }
}
