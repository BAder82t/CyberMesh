use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::Path;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::{CryptoError, Digest};

/// Fills a buffer from the operating system CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| CryptoError::Randomness)?;
    Ok(buf)
}

/// 16 random bytes, lowercase hex. Used for message nonces.
pub fn generate_nonce() -> Result<String, CryptoError> {
    Ok(hex::encode(random_bytes::<16>()?))
}

/// An Ed25519 public key. Serialised as 64 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Parses and validates a raw 32-byte Ed25519 public key.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        let vk = VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        if vk.is_weak() {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(Self(bytes))
    }

    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        if s.len() != 64 || s.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(CryptoError::InvalidHex(
                "public key must be 64 lowercase hex characters".into(),
            ));
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(|e| CryptoError::InvalidHex(e.to_string()))?;
        Self::from_bytes(out)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Stable identifier: lowercase hex SHA-256 of the raw public key.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        KeyId(Digest::of(&self.0).hex())
    }

    /// Strict verification (rejects non-canonical `S`, small-order `R` and weak keys).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| CryptoError::InvalidLength {
            expected: 64,
            actual: signature.len(),
        })?;
        let vk = VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::InvalidPublicKey)?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify_strict(message, &sig)
            .map_err(|_| CryptoError::BadSignature)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        PublicKey::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Identifier of a public key: lowercase hex SHA-256 of the raw key bytes.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct KeyId(String);

impl KeyId {
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CryptoError::InvalidHex(
                "key id must be 64 lowercase hex characters".into(),
            ));
        }
        Ok(Self(s.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// First 12 hex characters, for logs and human display only.
    #[must_use]
    pub fn short(&self) -> &str {
        &self.0[..12]
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        KeyId::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", self.short())
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An Ed25519 signing key. The seed is zeroised on drop by `ed25519-dalek`.
pub struct SecretKey {
    inner: SigningKey,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    kind: String,
    algorithm: String,
    seed_hex: String,
    public_key: String,
}

const KEY_FILE_KIND: &str = "cybermesh-secret-key";

impl SecretKey {
    /// Generates a new key from the OS CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let seed = Zeroizing::new(random_bytes::<32>()?);
        Ok(Self::from_seed(&seed))
    }

    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            inner: SigningKey::from_bytes(seed),
        }
    }

    /// Raw seed bytes. Callers must zeroise copies (used to derive the libp2p identity).
    #[must_use]
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.inner.to_bytes())
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.inner.verifying_key().to_bytes())
    }

    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.public_key().key_id()
    }

    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.inner.sign(message).to_bytes()
    }

    /// Writes the key as JSON with owner-only permissions (0600 on Unix). Refuses to
    /// overwrite an existing file.
    pub fn write_to_file(&self, path: &Path) -> Result<(), CryptoError> {
        let seed = self.seed();
        let file = KeyFile {
            kind: KEY_FILE_KIND.into(),
            algorithm: "ed25519".into(),
            seed_hex: hex::encode(*seed),
            public_key: self.public_key().to_hex(),
        };
        let json = Zeroizing::new(
            serde_json::to_vec_pretty(&file).map_err(|e| CryptoError::Json(e.to_string()))?,
        );
        let mut seed_hex = file.seed_hex;
        zeroize::Zeroize::zeroize(&mut seed_hex);

        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(path)
            .map_err(|e| CryptoError::KeyFile(format!("{}: {e}", path.display())))?;
        if let Err(e) = f.write_all(&json).and_then(|()| f.sync_all()) {
            // Do not leave a truncated key file behind (it would block regeneration).
            drop(f);
            let _ = fs::remove_file(path);
            return Err(CryptoError::KeyFile(e.to_string()));
        }
        Ok(())
    }

    /// Loads a key file. On Unix the file is opened without following symlinks and its
    /// permissions are checked on the opened handle (no check/use race); files readable by
    /// group or others are refused.
    pub fn read_from_file(path: &Path) -> Result<Self, CryptoError> {
        use std::io::Read as _;
        let err = |e: std::io::Error| CryptoError::KeyFile(format!("{}: {e}", path.display()));
        let mut opts = fs::OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let f = opts.open(path).map_err(err)?;
        let meta = f.metadata().map_err(err)?;
        if !meta.is_file() || meta.len() > 4096 {
            return Err(CryptoError::KeyFile(format!(
                "{} is not a regular key file",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(CryptoError::KeyFile(format!(
                    "{} is accessible by group/others; run `chmod 600` on it",
                    path.display()
                )));
            }
        }
        let mut raw = Vec::new();
        f.take(4096).read_to_end(&mut raw).map_err(err)?;
        let bytes = Zeroizing::new(raw);
        let mut file: KeyFile =
            serde_json::from_slice(&bytes).map_err(|e| CryptoError::KeyFile(e.to_string()))?;
        if file.kind != KEY_FILE_KIND || file.algorithm != "ed25519" {
            zeroize::Zeroize::zeroize(&mut file.seed_hex);
            return Err(CryptoError::KeyFile("unsupported key file type".into()));
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        let decoded = hex::decode_to_slice(&file.seed_hex, &mut *seed);
        zeroize::Zeroize::zeroize(&mut file.seed_hex);
        decoded.map_err(|_| CryptoError::KeyFile("seed is not 32 bytes of hex".into()))?;
        let key = Self::from_seed(&seed);
        if key.public_key().to_hex() != file.public_key {
            return Err(CryptoError::KeyFile(
                "public key does not match seed (corrupted key file)".into(),
            ));
        }
        Ok(key)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey(public={})", self.public_key().to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8032_test_vector_1() {
        // RFC 8032 section 7.1, TEST 1 (empty message).
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let sk = SecretKey::from_seed(&seed);
        assert_eq!(
            sk.public_key().to_hex(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = sk.sign(b"");
        assert_eq!(
            hex::encode(sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        sk.public_key().verify(b"", &sig).unwrap();
    }

    #[test]
    fn rejects_tampered_message_and_signature() {
        let sk = SecretKey::generate().unwrap();
        let sig = sk.sign(b"hello");
        assert!(sk.public_key().verify(b"hellp", &sig).is_err());
        let mut bad = sig;
        bad[10] ^= 1;
        assert!(sk.public_key().verify(b"hello", &bad).is_err());
        assert!(sk.public_key().verify(b"hello", &sig[..63]).is_err());
    }

    #[test]
    fn rejects_small_order_public_key() {
        // The identity point (small order) encoded as y = 1.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            PublicKey::from_bytes(identity),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn key_file_roundtrip_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.json");
        let sk = SecretKey::generate().unwrap();
        sk.write_to_file(&path).unwrap();
        // create_new: refuses to overwrite.
        assert!(sk.write_to_file(&path).is_err());
        let loaded = SecretKey::read_from_file(&path).unwrap();
        assert_eq!(loaded.public_key(), sk.public_key());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(SecretKey::read_from_file(&path).is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let link = dir.path().join("link.json");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(SecretKey::read_from_file(&link).is_err(), "symlinks are not followed");
        }
    }

    #[test]
    fn key_id_is_sha256_of_public_key() {
        let sk = SecretKey::from_seed(&[7u8; 32]);
        assert_eq!(
            sk.key_id().as_str(),
            Digest::of(sk.public_key().as_bytes()).hex()
        );
        assert!(KeyId::parse("ABC").is_err());
        assert!(KeyId::parse(&"A".repeat(64)).is_err());
    }
}
