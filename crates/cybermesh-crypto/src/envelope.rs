use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

use crate::{CryptoError, KeyId, PublicKey, SecretKey};

/// Upper bound on signatures processed per envelope (bounds verification work).
pub const MAX_SIGNATURES: usize = 16;

/// DSSE pre-authentication encoding:
/// `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`, LEN as ASCII decimal.
#[must_use]
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let header = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut out = Vec::with_capacity(header.len() + payload.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(payload);
    out
}

/// One signature in a DSSE envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvSignature {
    pub keyid: String,
    pub sig: String,
}

/// A DSSE envelope: `{"payloadType", "payload" (base64), "signatures": [{"keyid","sig"}]}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<EnvSignature>,
}

/// Result of a successful threshold verification.
#[derive(Debug, Clone)]
pub struct VerifiedEnvelope {
    /// Exact signed payload bytes.
    pub payload: Vec<u8>,
    /// Distinct trusted keys whose signatures verified, in envelope order.
    pub signers: Vec<KeyId>,
}

impl Envelope {
    /// Creates an envelope carrying one signature.
    #[must_use]
    pub fn sign(payload_type: &str, payload: &[u8], key: &SecretKey) -> Self {
        let sig = key.sign(&pae(payload_type, payload));
        Self {
            payload_type: payload_type.to_owned(),
            payload: B64.encode(payload),
            signatures: vec![EnvSignature {
                keyid: key.key_id().to_string(),
                sig: B64.encode(sig),
            }],
        }
    }

    /// Adds a co-signature over the same payload. Rejects a second signature by the same key.
    pub fn add_signature(&mut self, key: &SecretKey) -> Result<(), CryptoError> {
        let kid = key.key_id().to_string();
        if self.signatures.iter().any(|s| s.keyid == kid) {
            return Err(CryptoError::MalformedEnvelope(
                "key has already signed this envelope".into(),
            ));
        }
        if self.signatures.len() >= MAX_SIGNATURES {
            return Err(CryptoError::MalformedEnvelope("too many signatures".into()));
        }
        let payload = self.payload_bytes()?;
        let sig = key.sign(&pae(&self.payload_type, &payload));
        self.signatures.push(EnvSignature {
            keyid: kid,
            sig: B64.encode(sig),
        });
        Ok(())
    }

    /// Merges signatures from another envelope over byte-identical payload and type.
    pub fn merge_signatures(&mut self, other: &Envelope) -> Result<(), CryptoError> {
        if other.payload_type != self.payload_type || other.payload != self.payload {
            return Err(CryptoError::MalformedEnvelope(
                "cannot merge signatures over different payloads".into(),
            ));
        }
        for s in &other.signatures {
            if !self.signatures.iter().any(|x| x.keyid == s.keyid) {
                if self.signatures.len() >= MAX_SIGNATURES {
                    return Err(CryptoError::MalformedEnvelope("too many signatures".into()));
                }
                self.signatures.push(s.clone());
            }
        }
        Ok(())
    }

    /// Decoded payload bytes (strict, padded standard base64).
    pub fn payload_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        B64.decode(&self.payload)
            .map_err(|_| CryptoError::InvalidBase64)
    }

    /// Parses an envelope after enforcing a size limit on the raw bytes.
    pub fn parse(bytes: &[u8], max_len: usize) -> Result<Self, CryptoError> {
        if bytes.len() > max_len {
            return Err(CryptoError::TooLarge {
                size: bytes.len(),
                limit: max_len,
            });
        }
        let env: Envelope = serde_json::from_slice(bytes)
            .map_err(|e| CryptoError::MalformedEnvelope(e.to_string()))?;
        if env.signatures.is_empty() || env.signatures.len() > MAX_SIGNATURES {
            return Err(CryptoError::MalformedEnvelope(format!(
                "signature count must be 1..={MAX_SIGNATURES}"
            )));
        }
        Ok(env)
    }

    /// Compact JSON encoding of the envelope.
    pub fn to_vec(&self) -> Result<Vec<u8>, CryptoError> {
        serde_json::to_vec(self).map_err(|e| CryptoError::Json(e.to_string()))
    }

    /// Verifies the envelope against a trusted key set.
    ///
    /// * the payload type must equal `expected_type` (cross-protocol domain separation);
    /// * signatures from unknown keys are ignored, duplicates of one key count once;
    /// * at least `threshold` (>= 1) distinct trusted keys must have valid signatures.
    pub fn verify<F>(
        &self,
        expected_type: &str,
        threshold: usize,
        lookup: F,
    ) -> Result<VerifiedEnvelope, CryptoError>
    where
        F: Fn(&KeyId) -> Option<PublicKey>,
    {
        if self.payload_type != expected_type {
            return Err(CryptoError::WrongPayloadType {
                expected: expected_type.to_owned(),
                actual: self.payload_type.clone(),
            });
        }
        if threshold == 0 {
            return Err(CryptoError::InsufficientSignatures {
                valid: 0,
                required: 1,
            });
        }
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(CryptoError::MalformedEnvelope("too many signatures".into()));
        }
        let payload = self.payload_bytes()?;
        let message = pae(&self.payload_type, &payload);
        let mut seen = BTreeSet::new();
        let mut signers = Vec::new();
        for s in &self.signatures {
            let Ok(kid) = KeyId::parse(&s.keyid) else {
                continue;
            };
            if seen.contains(&kid) {
                continue;
            }
            let Some(pk) = lookup(&kid) else {
                continue;
            };
            // Guard against a lookup table whose key id does not match the key.
            if pk.key_id() != kid {
                continue;
            }
            let Ok(sig) = B64.decode(&s.sig) else {
                continue;
            };
            if pk.verify(&message, &sig).is_ok() {
                seen.insert(kid.clone());
                signers.push(kid);
            }
        }
        if signers.len() < threshold {
            return Err(CryptoError::InsufficientSignatures {
                valid: signers.len(),
                required: threshold,
            });
        }
        Ok(VerifiedEnvelope { payload, signers })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use proptest::prelude::*;

    use super::*;

    const T: &str = "application/vnd.cybermesh.test+json;v=1";

    fn table(keys: &[&SecretKey]) -> HashMap<KeyId, PublicKey> {
        keys.iter().map(|k| (k.key_id(), k.public_key())).collect()
    }

    #[test]
    fn pae_matches_dsse_spec_example() {
        // From the DSSE protocol specification.
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
        );
    }

    #[test]
    fn single_signature_roundtrip() {
        let k = SecretKey::generate().unwrap();
        let env = Envelope::sign(T, b"{\"x\":1}", &k);
        let bytes = env.to_vec().unwrap();
        let parsed = Envelope::parse(&bytes, 1024).unwrap();
        let t = table(&[&k]);
        let v = parsed.verify(T, 1, |id| t.get(id).copied()).unwrap();
        assert_eq!(v.payload, b"{\"x\":1}");
        assert_eq!(v.signers, vec![k.key_id()]);
    }

    #[test]
    fn rejects_wrong_type_unknown_key_and_tampering() {
        let k = SecretKey::generate().unwrap();
        let other = SecretKey::generate().unwrap();
        let env = Envelope::sign(T, b"payload", &k);
        let t = table(&[&k]);
        assert!(matches!(
            env.verify("other/type", 1, |id| t.get(id).copied()),
            Err(CryptoError::WrongPayloadType { .. })
        ));
        let t2 = table(&[&other]);
        assert!(env.verify(T, 1, |id| t2.get(id).copied()).is_err());

        let mut tampered = env.clone();
        tampered.payload = B64.encode(b"payloae");
        assert!(tampered.verify(T, 1, |id| t.get(id).copied()).is_err());

        // Type confusion: same bytes signed under a different payload type must not verify.
        let mut retyped = env.clone();
        retyped.payload_type = "application/vnd.cybermesh.other+json;v=1".into();
        assert!(
            retyped
                .verify(&retyped.payload_type.clone(), 1, |id| t.get(id).copied())
                .is_err()
        );
    }

    #[test]
    fn threshold_counts_distinct_trusted_keys_only() {
        let a = SecretKey::generate().unwrap();
        let b = SecretKey::generate().unwrap();
        let c = SecretKey::generate().unwrap();
        let mut env = Envelope::sign(T, b"release", &a);
        // Duplicate signature entries from the same key count once.
        env.signatures.push(env.signatures[0].clone());
        let t = table(&[&a, &b, &c]);
        assert!(matches!(
            env.verify(T, 2, |id| t.get(id).copied()),
            Err(CryptoError::InsufficientSignatures {
                valid: 1,
                required: 2
            })
        ));
        assert!(env.add_signature(&a).is_err());
        env.add_signature(&b).unwrap();
        let v = env.verify(T, 2, |id| t.get(id).copied()).unwrap();
        assert_eq!(v.signers.len(), 2);
        // Threshold 0 is never acceptable.
        assert!(env.verify(T, 0, |id| t.get(id).copied()).is_err());
    }

    #[test]
    fn merge_requires_identical_payload() {
        let a = SecretKey::generate().unwrap();
        let b = SecretKey::generate().unwrap();
        let mut ea = Envelope::sign(T, b"same", &a);
        let eb = Envelope::sign(T, b"same", &b);
        ea.merge_signatures(&eb).unwrap();
        assert_eq!(ea.signatures.len(), 2);
        let ec = Envelope::sign(T, b"different", &b);
        assert!(ea.merge_signatures(&ec).is_err());
    }

    #[test]
    fn size_limit_and_malformed_inputs() {
        let k = SecretKey::generate().unwrap();
        let bytes = Envelope::sign(T, &[0u8; 100], &k).to_vec().unwrap();
        assert!(matches!(
            Envelope::parse(&bytes, 50),
            Err(CryptoError::TooLarge { .. })
        ));
        assert!(Envelope::parse(br#"{"payloadType":"x","payload":"","signatures":[]}"#, 1000).is_err());
        assert!(Envelope::parse(b"not json", 1000).is_err());
        let mut env = Envelope::sign(T, b"p", &k);
        env.payload = "!!!".into();
        let t = table(&[&k]);
        assert_eq!(
            env.verify(T, 1, |id| t.get(id).copied()).unwrap_err(),
            CryptoError::InvalidBase64
        );
    }

    proptest! {
        #[test]
        fn parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = Envelope::parse(&bytes, 4096);
        }

        #[test]
        fn any_single_bit_flip_in_payload_is_rejected(payload in proptest::collection::vec(any::<u8>(), 1..64), idx in any::<usize>(), bit in 0u8..8) {
            let k = SecretKey::from_seed(&[3u8; 32]);
            let env = Envelope::sign(T, &payload, &k);
            let mut p = payload.clone();
            let i = idx % p.len();
            p[i] ^= 1 << bit;
            let mut tampered = env.clone();
            tampered.payload = B64.encode(&p);
            let t = table(&[&k]);
            prop_assert!(tampered.verify(T, 1, |id| t.get(id).copied()).is_err());
        }
    }
}
