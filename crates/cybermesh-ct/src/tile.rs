//! Static CT API data tiles.
//!
//! ```text
//! struct {
//!     TimestampedEntry timestamped_entry;          // RFC 6962 3.4
//!     select (entry_type) {
//!         case x509_entry: Empty;
//!         case precert_entry: ASN.1Cert pre_certificate;   // opaque<1..2^24-1>
//!     };
//!     Fingerprint certificate_chain<0..2^16-1>;    // 32-byte SHA-256 fingerprints
//! } TileLeaf;
//!
//! struct {
//!     uint64 timestamp;
//!     LogEntryType entry_type;                     // uint16: x509_entry(0), precert_entry(1)
//!     select (entry_type) {
//!         case x509_entry: ASN.1Cert;              // opaque<1..2^24-1>
//!         case precert_entry: PreCert;             // issuer_key_hash[32] || TBSCertificate<1..2^24-1>
//!     } signed_entry;
//!     CtExtensions extensions;                     // opaque<0..2^16-1>, contains leaf_index
//! } TimestampedEntry;
//! ```
//!
//! The Merkle leaf is `MerkleTreeLeaf = 0x00 (v1) || 0x00 (timestamped_entry) ||
//! TimestampedEntry`, hashed as `SHA-256(0x00 || MerkleTreeLeaf)` (RFC 6962).

use cybermesh_anchor::merkle;
use sha2::{Digest as _, Sha256};

use crate::CtError;

/// Entries in a full tile.
pub const WIDTH: usize = 256;
/// Largest certificate or TBSCertificate accepted (real ones are a few KiB).
pub const MAX_CERT_BYTES: usize = 1 << 20;

/// Encodes a tile index as static CT path elements: 1234067 -> `x001/x234/067`.
#[must_use]
pub fn tile_path(n: u64) -> String {
    let mut groups = Vec::new();
    let mut v = n;
    loop {
        groups.push(v % 1000);
        v /= 1000;
        if v == 0 {
            break;
        }
    }
    groups.reverse();
    let last = groups.len() - 1;
    groups
        .iter()
        .enumerate()
        .map(|(i, g)| {
            if i == last {
                format!("{g:03}")
            } else {
                format!("x{g:03}")
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Path of a full data tile.
#[must_use]
pub fn data_tile_path(n: u64) -> String {
    format!("tile/data/{}", tile_path(n))
}

/// Path of a hash tile (`width` for partial tiles).
#[must_use]
pub fn hash_tile_path(level: u8, n: u64, width: Option<u8>) -> String {
    match width {
        Some(w) => format!("tile/{level}/{}.p/{w}", tile_path(n)),
        None => format!("tile/{level}/{}", tile_path(n)),
    }
}

/// Kind of logged object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// `der` is a full X.509 certificate.
    X509,
    /// `der` is the TBSCertificate from the PreCert (poison extension removed).
    Precert,
}

/// One parsed log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub index: u64,
    pub timestamp: u64,
    pub kind: EntryKind,
    pub der: Vec<u8>,
    pub leaf_hash: [u8; 32],
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CtError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.buf.len())
            .ok_or_else(|| CtError::Malformed("truncated tile".into()))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn uint(&mut self, bytes: usize) -> Result<u64, CtError> {
        Ok(self
            .take(bytes)?
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
    }

    fn vec(&mut self, len_bytes: usize, min: usize, max: usize) -> Result<&'a [u8], CtError> {
        let n = usize::try_from(self.uint(len_bytes)?)
            .map_err(|_| CtError::Malformed("length".into()))?;
        if n < min || n > max {
            return Err(CtError::Malformed(format!("field length {n} out of range")));
        }
        self.take(n)
    }
}

/// Reads the `leaf_index` extension, if present, rejecting malformed extension lists.
fn leaf_index_extension(ext: &[u8]) -> Result<Option<u64>, CtError> {
    let mut r = Reader { buf: ext, pos: 0 };
    let mut found = None;
    while r.pos < ext.len() {
        let ty = r.uint(1)?;
        let data = r.vec(2, 0, 0xffff)?;
        if ty == 0 {
            if found.is_some() || data.len() != 5 {
                return Err(CtError::Malformed("bad leaf_index extension".into()));
            }
            found = Some(data.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b)));
        }
    }
    Ok(found)
}

/// Parses a full data tile (exactly 256 entries, no trailing bytes). Every entry must carry
/// a `leaf_index` extension equal to its position.
pub fn parse_data_tile(bytes: &[u8], tile_index: u64) -> Result<Vec<Entry>, CtError> {
    let mut r = Reader { buf: bytes, pos: 0 };
    let first = tile_index
        .checked_mul(WIDTH as u64)
        .ok_or_else(|| CtError::Malformed("tile index overflow".into()))?;
    let mut out = Vec::with_capacity(WIDTH);
    for i in 0..WIDTH as u64 {
        let index = first + i;
        let start = r.pos;
        let timestamp = r.uint(8)?;
        let entry_type = r.uint(2)?;
        let (kind, der) = match entry_type {
            0 => (EntryKind::X509, r.vec(3, 1, MAX_CERT_BYTES)?),
            1 => {
                r.take(32)?; // issuer_key_hash
                (EntryKind::Precert, r.vec(3, 1, MAX_CERT_BYTES)?)
            }
            other => return Err(CtError::Malformed(format!("unknown entry type {other}"))),
        };
        let ext = r.vec(2, 0, 0xffff)?;
        let timestamped_entry = &bytes[start..r.pos];
        // static-ct-api requires the extension: without it, entries are not bound to their
        // position and a tile could be served at the wrong index.
        match leaf_index_extension(ext)? {
            Some(li) if li == index => {}
            Some(li) => {
                return Err(CtError::Malformed(format!(
                    "entry at index {index} claims leaf_index {li}"
                )));
            }
            None => {
                return Err(CtError::Malformed(format!(
                    "entry at index {index} has no leaf_index extension"
                )));
            }
        }
        if kind == EntryKind::Precert {
            r.vec(3, 1, MAX_CERT_BYTES)?; // pre_certificate (not needed: TBS is in the entry)
        }
        let chain = r.vec(2, 0, 0xffff)?;
        if chain.len() % 32 != 0 {
            return Err(CtError::Malformed(
                "certificate_chain not a list of fingerprints".into(),
            ));
        }
        let mut h = Sha256::new();
        h.update([0u8, 0u8, 0u8]); // RFC 6962 leaf prefix, then MerkleTreeLeaf version + type
        h.update(timestamped_entry);
        out.push(Entry {
            index,
            timestamp,
            kind,
            der: der.to_vec(),
            leaf_hash: h.finalize().into(),
        });
    }
    if r.pos != bytes.len() {
        return Err(CtError::Malformed(
            "trailing bytes after 256 entries".into(),
        ));
    }
    Ok(out)
}

/// RFC 6962 Merkle tree hash over the entries' leaf hashes.
#[must_use]
pub fn tile_root(entries: &[Entry]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = entries.iter().map(|e| e.leaf_hash).collect();
    merkle::root(&leaves)
}

/// Serialises one TileLeaf (used by the mock log and by tests).
#[must_use]
pub fn encode_tile_leaf(
    timestamp: u64,
    kind: EntryKind,
    der: &[u8],
    leaf_index: u64,
    precert_full: Option<&[u8]>,
) -> (Vec<u8>, [u8; 32]) {
    let mut te = Vec::new();
    te.extend_from_slice(&timestamp.to_be_bytes());
    match kind {
        EntryKind::X509 => {
            te.extend_from_slice(&0u16.to_be_bytes());
        }
        EntryKind::Precert => {
            te.extend_from_slice(&1u16.to_be_bytes());
            te.extend_from_slice(&[0x11u8; 32]);
        }
    }
    let len = der.len() as u32;
    te.extend_from_slice(&len.to_be_bytes()[1..]);
    te.extend_from_slice(der);
    // extensions: one leaf_index extension (type 0, length 5, uint40)
    te.extend_from_slice(&8u16.to_be_bytes());
    te.push(0);
    te.extend_from_slice(&5u16.to_be_bytes());
    te.extend_from_slice(&leaf_index.to_be_bytes()[3..]);
    let mut leaf = te.clone();
    if kind == EntryKind::Precert {
        let p = precert_full.unwrap_or(der);
        let plen = p.len() as u32;
        leaf.extend_from_slice(&plen.to_be_bytes()[1..]);
        leaf.extend_from_slice(p);
    }
    leaf.extend_from_slice(&32u16.to_be_bytes());
    leaf.extend_from_slice(&[0x22u8; 32]);
    let mut h = Sha256::new();
    h.update([0u8, 0u8, 0u8]);
    h.update(&te);
    (leaf, h.finalize().into())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn tile_paths_match_the_spec() {
        assert_eq!(tile_path(1_234_067), "x001/x234/067");
        assert_eq!(tile_path(0), "000");
        assert_eq!(tile_path(5), "005");
        assert_eq!(tile_path(1000), "x001/000");
        assert_eq!(data_tile_path(1_234_067), "tile/data/x001/x234/067");
        assert_eq!(hash_tile_path(1, 3, Some(17)), "tile/1/003.p/17");
        assert_eq!(hash_tile_path(0, 273, None), "tile/0/273");
    }

    fn synthetic_tile(tile: u64) -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0..WIDTH as u64 {
            let kind = if i % 3 == 0 {
                EntryKind::Precert
            } else {
                EntryKind::X509
            };
            let (leaf, _) = encode_tile_leaf(
                1_700_000_000_000 + i,
                kind,
                &[0x30, 0x00],
                tile * 256 + i,
                None,
            );
            out.extend_from_slice(&leaf);
        }
        out
    }

    #[test]
    fn parses_full_tile_and_checks_leaf_indices() {
        let bytes = synthetic_tile(7);
        let entries = parse_data_tile(&bytes, 7).unwrap();
        assert_eq!(entries.len(), 256);
        assert_eq!(entries[0].index, 7 * 256);
        assert_eq!(entries[3].kind, EntryKind::Precert);
        // Same bytes presented as a different tile: leaf_index mismatch.
        assert!(parse_data_tile(&bytes, 8).is_err());
        // Truncated and trailing data.
        assert!(parse_data_tile(&bytes[..bytes.len() - 1], 7).is_err());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(parse_data_tile(&extra, 7).is_err());
    }

    #[test]
    fn leaf_hash_matches_encoder() {
        let (leaf, hash) = encode_tile_leaf(42, EntryKind::X509, &[1, 2, 3], 0, None);
        let mut tile = Vec::new();
        for _ in 0..256 {
            tile.extend_from_slice(&leaf);
        }
        // leaf_index 0 for every entry fails the index check after the first entry.
        assert!(parse_data_tile(&tile, 0).is_err());
        let e = parse_data_tile(&synthetic_tile(0), 0).unwrap();
        let (_, h0) = encode_tile_leaf(
            1_700_000_000_000,
            EntryKind::Precert,
            &[0x30, 0x00],
            0,
            None,
        );
        assert_eq!(e[0].leaf_hash, h0);
        assert_ne!(hash, h0);
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096), tile in 0u64..1_000_000) {
            let _ = parse_data_tile(&bytes, tile);
        }
    }
}
