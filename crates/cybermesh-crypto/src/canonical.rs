//! Strict, canonical JSON encoding.
//!
//! CyberMesh payloads are plain structs (fixed field order), `BTreeMap`s (sorted keys),
//! strings, booleans and integers. Floating point numbers are never used. Encoding is
//! `serde_json`'s compact form. Decoding re-encodes the parsed value and requires the bytes
//! to match exactly, so there is exactly one accepted byte string per value.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::CryptoError;

/// Encodes a value in canonical form.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, CryptoError> {
    serde_json::to_vec(value).map_err(|e| CryptoError::Json(e.to_string()))
}

/// Decodes a value and rejects any non-canonical encoding of it.
pub fn from_slice<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<T, CryptoError> {
    let value: T = serde_json::from_slice(bytes).map_err(|e| CryptoError::Json(e.to_string()))?;
    let reencoded = to_vec(&value)?;
    if reencoded != bytes {
        return Err(CryptoError::NonCanonical);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
    #[serde(deny_unknown_fields)]
    struct Sample {
        a: u64,
        b: String,
        c: BTreeMap<String, u32>,
    }

    #[test]
    fn rejects_whitespace_reordering_duplicates_and_escapes() {
        let s = Sample {
            a: 1,
            b: "é".into(),
            c: BTreeMap::from([("x".into(), 1), ("y".into(), 2)]),
        };
        let canon = to_vec(&s).unwrap();
        assert_eq!(from_slice::<Sample>(&canon).unwrap(), s);

        let escaped = format!(r#"{{"a":1,"b":"{}u00e9","c":{{"x":1,"y":2}}}}"#, '\\');
        assert!(escaped.contains("\\u00e9"));
        for bad in [
            r#"{"a":1, "b":"é","c":{"x":1,"y":2}}"#,
            r#"{"b":"é","a":1,"c":{"x":1,"y":2}}"#,
            r#"{"a":1,"b":"é","c":{"y":2,"x":1}}"#,
            // "é" written as a JSON unicode escape (backslash built at runtime below).
            &escaped,
            r#"{"a":1,"a":1,"b":"é","c":{"x":1,"y":2}}"#,
            r#"{"a":1,"b":"é","c":{"x":1,"y":2},"d":0}"#,
            r#"{"a":1.0,"b":"é","c":{"x":1,"y":2}}"#,
        ] {
            assert!(from_slice::<Sample>(bad.as_bytes()).is_err(), "accepted {bad:?}");
        }
    }

    proptest! {
        #[test]
        fn roundtrip_is_identity(a in any::<u64>(), b in ".{0,40}", keys in proptest::collection::btree_map("[a-z]{1,8}", any::<u32>(), 0..8)) {
            let s = Sample { a, b, c: keys };
            let bytes = to_vec(&s).unwrap();
            prop_assert_eq!(from_slice::<Sample>(&bytes).unwrap(), s);
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = from_slice::<Sample>(&bytes);
        }
    }
}
