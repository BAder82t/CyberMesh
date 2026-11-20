//! Authenticating hash tiles against a verified checkpoint.
//!
//! A data tile's Merkle root is entry `n % 256` of level-1 hash tile `n / 256`. Hash tiles are
//! just files served by the log or a CDN, so a tile root is trusted only once it is proven to
//! be part of the tree whose root the log signed: [`TileAuthenticator::tile_root`] recomputes
//! the RFC 6962 root of the signed tree size *through* that entry, using the other hashes the
//! path needs from the log's hash tiles (C2SP `tlog-tiles`, levels 0 and up), and compares it
//! with the checkpoint's signed root. By collision resistance, a match proves the entry; the
//! helper hashes need no separate trust.
//!
//! Tiles are read with their exact expected width and cached per authenticator, so verifying
//! several tiles of one task costs a few small hash tiles in total.

use std::collections::HashMap;
use std::sync::Mutex;

use cybermesh_anchor::merkle;

use crate::checkpoint::Checkpoint;
use crate::{CtError, TileSource};

type Hash = [u8; 32];

/// How another checkpoint of a log relates to a verified, larger (or equal) one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Consistency {
    /// The other checkpoint's tree is this tree, or a prefix of it.
    Consistent,
    /// The log signed two trees that cannot both belong to one append-only log: the other
    /// checkpoint's root is not the root of this tree's first `size` entries.
    Inconsistent {
        /// The root of this tree's first `other.size` entries (this root for equal sizes).
        prefix_root: Hash,
        /// RFC 6962 consistency proof from `(other.size, prefix_root)` to this checkpoint.
        /// Empty for equal sizes: two roots for one size need no proof.
        proof: Vec<Hash>,
    },
}

/// Proves data tile roots against one verified checkpoint.
pub struct TileAuthenticator<'a> {
    src: &'a dyn TileSource,
    checkpoint: Checkpoint,
    cache: Mutex<HashMap<(u8, u64), Vec<Hash>>>,
}

impl std::fmt::Debug for TileAuthenticator<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TileAuthenticator")
            .field("size", &self.checkpoint.size)
            .finish_non_exhaustive()
    }
}

impl<'a> TileAuthenticator<'a> {
    /// `checkpoint` must have been verified ([`crate::verify_checkpoint`]).
    #[must_use]
    pub fn new(src: &'a dyn TileSource, checkpoint: Checkpoint) -> Self {
        Self {
            src,
            checkpoint,
            cache: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// The tile source (for data tiles, which are proven through their roots).
    #[must_use]
    pub fn source(&self) -> &dyn TileSource {
        self.src
    }

    /// Hash tile `idx` at `level` with the width implied by the signed tree size.
    fn tile(&self, level: u8, idx: u64) -> Result<Vec<Hash>, CtError> {
        if let Some(t) = self
            .cache
            .lock()
            .ok()
            .and_then(|c| c.get(&(level, idx)).cloned())
        {
            return Ok(t);
        }
        // Complete subtrees of 256^level leaves in the tree.
        let count = self.checkpoint.size >> (8 * u32::from(level));
        let first = idx.checked_mul(256).filter(|f| *f < count).ok_or_else(|| {
            CtError::NotFound(format!("hash tile {level}/{idx} is beyond the tree"))
        })?;
        let width = (count - first).min(256);
        let w = (width < 256).then(|| u8::try_from(width).unwrap_or(255));
        // A log may stop serving a partial tile once the full tile exists (static-ct-api):
        // fall back to the full tile and keep the hashes covered by the signed tree.
        let bytes = match self.src.hash_tile(level, idx, w) {
            Err(CtError::NotFound(_)) if w.is_some() => {
                let mut full = self.src.hash_tile(level, idx, None)?;
                if full.len() != 256 * 32 {
                    return Err(CtError::Malformed(format!(
                        "full hash tile {level}/{idx} has {} bytes",
                        full.len()
                    )));
                }
                full.truncate(usize::try_from(width).unwrap_or(0) * 32);
                full
            }
            other => other?,
        };
        let expected = usize::try_from(width).unwrap_or(0) * 32;
        if bytes.len() != expected {
            return Err(CtError::Malformed(format!(
                "hash tile {level}/{idx} has {} bytes, expected {expected}",
                bytes.len()
            )));
        }
        let hashes: Vec<Hash> = bytes.as_chunks::<32>().0.to_vec();
        if let Ok(mut c) = self.cache.lock() {
            c.insert((level, idx), hashes.clone());
        }
        Ok(hashes)
    }

    /// Hash of the complete subtree of height `h` at index `i` (leaves `[i·2^h, (i+1)·2^h)`).
    fn node(&self, h: u32, i: u64) -> Result<Hash, CtError> {
        let (level, r) = (h / 8, h % 8);
        let level = u8::try_from(level).map_err(|_| CtError::Malformed("tree height".into()))?;
        let start = i << r;
        let n = 1usize << r;
        let tile = self.tile(level, start / 256)?;
        let off = usize::try_from(start % 256).unwrap_or(0);
        let mut layer: Vec<Hash> = tile
            .get(off..off + n)
            .ok_or_else(|| CtError::Malformed("hash tile too short".into()))?
            .to_vec();
        while layer.len() > 1 {
            layer = layer
                .as_chunks::<2>()
                .0
                .iter()
                .map(|[l, r]| merkle::node_hash(l, r))
                .collect();
        }
        Ok(layer[0])
    }

    /// RFC 6962 Merkle tree hash of leaves `[a, b)`, for ranges arising in the RFC's split.
    fn mth(&self, a: u64, b: u64) -> Result<Hash, CtError> {
        let n = b - a;
        if n.is_power_of_two() && a.is_multiple_of(n) {
            return self.node(n.trailing_zeros(), a / n);
        }
        let k = largest_power_of_two_below(n);
        Ok(merkle::node_hash(
            &self.mth(a, a + k)?,
            &self.mth(a + k, b)?,
        ))
    }

    /// The tree hash of `[a, b)` computed through the 256-leaf subtree at `t0` with hash
    /// `target` (never reading that subtree's hash from a tile).
    fn mth_through(&self, a: u64, b: u64, t0: u64, target: &Hash) -> Result<Hash, CtError> {
        if a == t0 && b == t0 + 256 {
            return Ok(*target);
        }
        let k = largest_power_of_two_below(b - a);
        if t0 + 256 <= a + k {
            Ok(merkle::node_hash(
                &self.mth_through(a, a + k, t0, target)?,
                &self.mth(a + k, b)?,
            ))
        } else {
            Ok(merkle::node_hash(
                &self.mth(a, a + k)?,
                &self.mth_through(a + k, b, t0, target)?,
            ))
        }
    }

    /// The Merkle root of full data tile `tile`, proven to be in the signed tree.
    pub fn tile_root(&self, tile: u64) -> Result<Hash, CtError> {
        if tile >= self.checkpoint.full_tiles() {
            return Err(CtError::NotFound(format!(
                "data tile {tile} is not full yet"
            )));
        }
        let claimed = self.node(8, tile)?;
        let root = self.mth_through(0, self.checkpoint.size, tile * 256, &claimed)?;
        if root != self.checkpoint.root {
            return Err(CtError::Unauthenticated(format!(
                "hash tiles for data tile {tile} do not match the signed checkpoint"
            )));
        }
        Ok(claimed)
    }

    /// Proves that this (verified) checkpoint's tree extends `older`, an earlier verified
    /// checkpoint of the same log: an RFC 6962 consistency proof is assembled from the log's
    /// hash tiles and both signed roots are recomputed from it (RFC 9162 §2.1.4.2). A log that
    /// rewrote or forked its history cannot pass. Equal sizes need equal roots.
    pub fn prove_extends(&self, older: &Checkpoint) -> Result<(), CtError> {
        let (m, n) = (older.size, self.checkpoint.size);
        if m > n {
            return Err(CtError::Unauthenticated(format!(
                "checkpoint size {n} is smaller than an earlier verified size {m}"
            )));
        }
        let mut ranges = Vec::new();
        if m > 0 && m < n {
            subproof_ranges(m, 0, n, true, &mut ranges);
        }
        let proof = ranges
            .iter()
            .map(|(a, b)| self.mth(*a, *b))
            .collect::<Result<Vec<Hash>, CtError>>()?;
        if merkle::verify_consistency(m, n, &older.root, &self.checkpoint.root, &proof) {
            Ok(())
        } else {
            Err(CtError::Unauthenticated(format!(
                "checkpoint of size {n} is not consistent with the earlier checkpoint of size {m}"
            )))
        }
    }

    /// Compares `other`, a verified checkpoint of the same log no larger than this one, with
    /// this tree, using hash tiles authenticated against this checkpoint's signed root.
    ///
    /// The root of this tree's first `other.size` entries and the RFC 6962 consistency proof
    /// from it to this checkpoint's root are both computed from the tiles, and the proof must
    /// verify. Then the comparison is decided by the signed roots alone. An error means the
    /// tiles could not be read or do not match this checkpoint: nothing is proven either way.
    pub fn consistency_with(&self, other: &Checkpoint) -> Result<Consistency, CtError> {
        let (m, n) = (other.size, self.checkpoint.size);
        if m > n {
            return Err(CtError::Unauthenticated(format!(
                "compare against the larger checkpoint ({m} > {n})"
            )));
        }
        if m == n {
            return Ok(if other.root == self.checkpoint.root {
                Consistency::Consistent
            } else {
                Consistency::Inconsistent {
                    prefix_root: self.checkpoint.root,
                    proof: Vec::new(),
                }
            });
        }
        let (prefix_root, proof) = if m == 0 {
            (merkle::empty_root(), Vec::new())
        } else {
            let mut ranges = Vec::new();
            subproof_ranges(m, 0, n, true, &mut ranges);
            let proof = ranges
                .iter()
                .map(|(a, b)| self.mth(*a, *b))
                .collect::<Result<Vec<Hash>, CtError>>()?;
            let prefix = self.mth(0, m)?;
            if !merkle::verify_consistency(m, n, &prefix, &self.checkpoint.root, &proof) {
                return Err(CtError::Unauthenticated(format!(
                    "hash tiles do not match the signed checkpoint of size {n}"
                )));
            }
            (prefix, proof)
        };
        Ok(if prefix_root == other.root {
            Consistency::Consistent
        } else {
            Consistency::Inconsistent { prefix_root, proof }
        })
    }

    /// The root of the whole tree recomputed from the hash tiles (equals the signed root for
    /// a consistent log).
    pub fn tree_root(&self) -> Result<Hash, CtError> {
        if self.checkpoint.size == 0 {
            return Ok(merkle::empty_root());
        }
        self.mth(0, self.checkpoint.size)
    }
}

/// The ranges whose tree hashes form the RFC 6962 consistency proof `SUBPROOF(m, D[a:b], complete)`.
fn subproof_ranges(m: u64, a: u64, b: u64, complete: bool, out: &mut Vec<(u64, u64)>) {
    let n = b - a;
    if m == n {
        if !complete {
            out.push((a, b));
        }
        return;
    }
    let k = largest_power_of_two_below(n);
    if m <= k {
        subproof_ranges(m, a, a + k, complete, out);
        out.push((a + k, b));
    } else {
        subproof_ranges(m - k, a + k, b, false, out);
        out.push((a, a + k));
    }
}

/// The largest power of two strictly below `n` (`n >= 2`).
fn largest_power_of_two_below(n: u64) -> u64 {
    1u64 << (63 - (n - 1).leading_zeros())
}

/// Convenience: proves one data tile's root against a verified checkpoint.
pub fn authenticated_tile_root(
    src: &dyn TileSource,
    checkpoint: &Checkpoint,
    tile: u64,
) -> Result<Hash, CtError> {
    TileAuthenticator::new(src, checkpoint.clone()).tile_root(tile)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::collections::BTreeMap;

    use super::*;
    use crate::tile::hash_tile_path;

    /// A log of `n` synthetic leaves exposing only hash tiles (all levels) and its root.
    struct HashLog {
        files: BTreeMap<String, Vec<u8>>,
        root: Hash,
        n: u64,
    }

    impl HashLog {
        fn new(n: u64) -> Self {
            let leaves: Vec<Hash> = (0..n)
                .map(|i| merkle::leaf_hash(&i.to_be_bytes()))
                .collect();
            Self::from_leaves(&leaves)
        }

        fn from_leaves(leaves: &[Hash]) -> Self {
            let n = leaves.len() as u64;
            let mut files = BTreeMap::new();
            let mut nodes = leaves.to_vec();
            let mut level = 0u8;
            while !nodes.is_empty() {
                let mut next = Vec::new();
                for (i, chunk) in nodes.chunks(256).enumerate() {
                    let w = (chunk.len() < 256).then(|| u8::try_from(chunk.len()).unwrap());
                    files.insert(hash_tile_path(level, i as u64, w), chunk.concat());
                    if chunk.len() == 256 {
                        next.push(merkle::root(chunk));
                    }
                }
                nodes = next;
                level += 1;
            }
            Self {
                files,
                root: merkle::root(leaves),
                n,
            }
        }

        fn checkpoint(&self) -> Checkpoint {
            Checkpoint {
                origin: "test".into(),
                size: self.n,
                root: self.root,
                signed_at_ms: 1,
            }
        }
    }

    impl TileSource for HashLog {
        fn data_tile(&self, _: u64) -> Result<Vec<u8>, CtError> {
            Err(CtError::NotFound("no data tiles".into()))
        }
        fn hash_tile(&self, level: u8, n: u64, width: Option<u8>) -> Result<Vec<u8>, CtError> {
            let p = hash_tile_path(level, n, width);
            self.files.get(&p).cloned().ok_or(CtError::NotFound(p))
        }
        fn checkpoint(&self) -> Result<String, CtError> {
            Err(CtError::NotFound("checkpoint".into()))
        }
    }

    #[test]
    fn proves_tile_roots_for_trees_with_partial_tiles_at_every_level() {
        // 70,000 is the tlog-tiles example: partial tiles at levels 0, 1 and 2.
        for n in [256u64, 512, 1000, 65_536, 65_792, 70_000] {
            let log = HashLog::new(n);
            let auth = TileAuthenticator::new(&log, log.checkpoint());
            assert_eq!(auth.tree_root().unwrap(), log.root, "n = {n}");
            let full = n / 256;
            for t in [0, full / 2, full - 1] {
                let leaves: Vec<Hash> = (t * 256..t * 256 + 256)
                    .map(|i| merkle::leaf_hash(&i.to_be_bytes()))
                    .collect();
                assert_eq!(
                    auth.tile_root(t).unwrap(),
                    merkle::root(&leaves),
                    "n = {n}, t = {t}"
                );
            }
            assert!(auth.tile_root(full).is_err(), "only full data tiles");
        }
    }

    #[test]
    fn missing_partial_tiles_fall_back_to_the_full_tile() {
        // The log grew from 70,000 to 140,000 entries and, as static-ct-api allows, deleted
        // the older tree's partial tiles whose full tile now exists; the verifier holds a
        // checkpoint for 70,000.
        let old = HashLog::new(70_000);
        let mut grown = HashLog::new(140_000);
        // The log served the old tree's partial tiles when that checkpoint was current.
        for (k, v) in old.files.iter().filter(|(k, _)| k.contains(".p/")) {
            grown.files.insert(k.clone(), v.clone());
        }
        let partials: Vec<String> = old
            .files
            .keys()
            .filter(|k| {
                k.split_once(".p/")
                    .is_some_and(|(full, _)| grown.files.contains_key(full))
            })
            .cloned()
            .collect();
        assert_eq!(partials.len(), 2, "levels 0 and 1 have full replacements");
        for p in &partials {
            grown.files.remove(p);
        }
        let auth = TileAuthenticator::new(&grown, old.checkpoint());
        for t in [0u64, 136, 272] {
            let leaves: Vec<Hash> = (t * 256..t * 256 + 256)
                .map(|i| merkle::leaf_hash(&i.to_be_bytes()))
                .collect();
            assert_eq!(auth.tile_root(t).unwrap(), merkle::root(&leaves), "t = {t}");
        }
    }

    /// A tree of `n` leaves sharing only its first `fork_at` leaves with [`HashLog::new`].
    fn forked(n: u64, fork_at: u64) -> HashLog {
        let leaves: Vec<Hash> = (0..n)
            .map(|i| {
                let v = if i >= fork_at { i + 1_000_000 } else { i };
                merkle::leaf_hash(&v.to_be_bytes())
            })
            .collect();
        HashLog::from_leaves(&leaves)
    }

    #[test]
    fn consistency_between_checkpoints_is_proven_from_tiles() {
        for (m, n) in [
            (1u64, 2u64),
            (256, 257),
            (300, 70_000),
            (65_536, 70_000),
            (69_999, 70_000),
            (70_000, 70_000),
        ] {
            let old = HashLog::new(m);
            let new = HashLog::new(n);
            let auth = TileAuthenticator::new(&new, new.checkpoint());
            auth.prove_extends(&old.checkpoint())
                .unwrap_or_else(|e| panic!("{m} -> {n}: {e}"));
        }
        // A log that rewrote history (entries from 50,000 on differ) cannot prove it extends
        // the earlier tree, even with all of its own tiles served correctly.
        let old = HashLog::new(60_000);
        let rewritten = forked(70_000, 50_000);
        let auth = TileAuthenticator::new(&rewritten, rewritten.checkpoint());
        assert!(
            auth.tile_root(1).is_ok(),
            "the new tree itself is consistent"
        );
        assert!(matches!(
            auth.prove_extends(&old.checkpoint()),
            Err(CtError::Unauthenticated(_))
        ));
        // Shrinking, or the same size with a different root, is refused.
        let small = HashLog::new(1000);
        let auth = TileAuthenticator::new(&small, small.checkpoint());
        assert!(
            auth.prove_extends(&HashLog::new(2000).checkpoint())
                .is_err()
        );
        assert!(auth.prove_extends(&forked(1000, 10).checkpoint()).is_err());
    }

    #[test]
    fn a_tampered_hash_tile_is_detected() {
        let n = 70_000;
        let mut log = HashLog::new(n);
        let cp = log.checkpoint();
        // The level-1 entry for data tile 7 is replaced: proving tile 7 fails ...
        let p = hash_tile_path(1, 0, None);
        log.files.get_mut(&p).unwrap()[7 * 32] ^= 1;
        let auth = TileAuthenticator::new(&log, cp.clone());
        assert!(matches!(
            auth.tile_root(7),
            Err(CtError::Unauthenticated(_))
        ));
        // ... and so does any other tile whose proof uses that level-1 tile.
        assert!(auth.tile_root(8).is_err());
        // A wrong signed root (a checkpoint for another tree) fails too.
        let log = HashLog::new(n);
        let mut other = cp;
        other.root[0] ^= 1;
        assert!(TileAuthenticator::new(&log, other).tile_root(3).is_err());
        // A hash tile of the wrong length is refused before hashing.
        let mut log = HashLog::new(n);
        log.files
            .get_mut(&hash_tile_path(1, 0, None))
            .unwrap()
            .pop();
        let auth = TileAuthenticator::new(&log, log.checkpoint());
        assert!(matches!(auth.tile_root(1), Err(CtError::Malformed(_))));
    }

    #[test]
    fn a_forked_view_is_proven_with_a_checkable_consistency_proof() {
        // Consistent: every earlier size of the same log, and the same tree.
        let big = HashLog::new(70_000);
        let auth = TileAuthenticator::new(&big, big.checkpoint());
        for m in [0u64, 1, 256, 300, 65_536, 69_999, 70_000] {
            assert_eq!(
                auth.consistency_with(&HashLog::new(m).checkpoint())
                    .unwrap(),
                Consistency::Consistent,
                "m = {m}"
            );
        }
        // Another view: a tree that shares only its first 50,000 entries with this one.
        for m in [60_000u64, 65_536, 69_999] {
            let other = forked(m, 50_000).checkpoint();
            let Consistency::Inconsistent { prefix_root, proof } =
                auth.consistency_with(&other).unwrap()
            else {
                panic!("m = {m}: a forked view must be proven");
            };
            // The proof alone (no tiles) shows the log committed to another root at size m.
            assert_ne!(prefix_root, other.root);
            assert_eq!(prefix_root, HashLog::new(m).root);
            assert!(merkle::verify_consistency(
                m,
                70_000,
                &prefix_root,
                &big.root,
                &proof
            ));
            assert!(!merkle::verify_consistency(
                m,
                70_000,
                &other.root,
                &big.root,
                &proof
            ));
        }
        // Equal sizes with different roots need no proof.
        let other = forked(70_000, 50_000).checkpoint();
        assert_eq!(
            auth.consistency_with(&other).unwrap(),
            Consistency::Inconsistent {
                prefix_root: big.root,
                proof: Vec::new()
            }
        );
        // Comparing against a larger checkpoint is the caller's mistake, not evidence.
        assert!(
            auth.consistency_with(&HashLog::new(70_001).checkpoint())
                .is_err()
        );
        // Tiles that do not match the signed root prove nothing: an error, never a verdict.
        let mut bad = HashLog::new(70_000);
        let cp = bad.checkpoint();
        bad.files.get_mut(&hash_tile_path(1, 0, None)).unwrap()[3 * 32] ^= 1;
        let auth = TileAuthenticator::new(&bad, cp);
        assert!(matches!(
            auth.consistency_with(&HashLog::new(60_000).checkpoint()),
            Err(CtError::Unauthenticated(_))
        ));
    }
}
