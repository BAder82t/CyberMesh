//! Classic RFC 6962 logs behave like static logs for everything CyberMesh needs: a verified
//! checkpoint, scanned tiles whose roots are proven against it, and consistency.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use cybermesh_analysis::{CtLogInfo, Engine, EvidenceBundle};
use cybermesh_anchor::merkle;
use cybermesh_ct::checkpoint::fetch_verified_checkpoint;
use cybermesh_ct::mock::{MockEntry, MockRfc6962Log, demo_entries};
use cybermesh_ct::rfc6962::{Rfc6962Source, parse_leaf_input, sth_note};
use cybermesh_ct::{
    Checkpoint, Consistency, CtError, LogKey, TileSource, authenticator, scan_tiles,
    verify_checkpoint,
};

const ORIGIN: &str = "ct.example/classic-2026";

fn engine() -> Engine {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../datasets/demo/evidence");
    Engine::new(EvidenceBundle::load(&dir).unwrap())
}

fn entries(n: usize) -> Vec<MockEntry> {
    let mut out = demo_entries(n.div_ceil(256));
    out.truncate(n);
    out
}

fn info(log: &MockRfc6962Log) -> CtLogInfo {
    log.log_info("classic", "http://127.0.0.1:9/")
}

fn source(log: &MockRfc6962Log) -> Rfc6962Source {
    Rfc6962Source::new(Box::new(log.clone()), &info(log)).unwrap()
}

/// A verified checkpoint of the first `n` entries.
fn checkpoint(log: &MockRfc6962Log, n: u64) -> Checkpoint {
    let key = LogKey::from_info(&info(log)).unwrap();
    verify_checkpoint(&sth_note(&log.sth_at(n).unwrap(), &key), &key).unwrap()
}

#[test]
fn a_signed_tree_head_is_a_verified_checkpoint() {
    let log = MockRfc6962Log::build(ORIGIN, &entries(800)).unwrap();
    let src = source(&log);
    let cp = fetch_verified_checkpoint(&src, &info(&log)).unwrap();
    assert_eq!((cp.size, cp.full_tiles()), (800, 3));
    assert_eq!(cp.root, log.root_at(800));
    // A tampered root, or another origin, is refused like for any checkpoint.
    let key = LogKey::from_info(&info(&log)).unwrap();
    let mut sth = log.sth_at(800).unwrap();
    sth.root[0] ^= 1;
    assert!(verify_checkpoint(&sth_note(&sth, &key), &key).is_err());
    let other = LogKey::from_info(&log.log_info("classic", "http://127.0.0.1:9/")).unwrap();
    let cp_text = sth_note(&log.sth_at(800).unwrap(), &other);
    let wrong_origin = cp_text.replace(ORIGIN, "ct.example/other");
    assert!(verify_checkpoint(&wrong_origin, &key).is_err());
}

#[test]
fn tiles_are_scanned_and_their_roots_proven_whatever_the_page_size() {
    let log = MockRfc6962Log::build(ORIGIN, &entries(800)).unwrap();
    let e = engine();
    let mut results = Vec::new();
    // Logs return at most a handful of entries per call: even one at a time works.
    for per_call in [1, 7, 64, 1000] {
        let mut l = log.clone();
        l.max_entries_per_call = per_call;
        let src = source(&l);
        let cp = fetch_verified_checkpoint(&src, &info(&l)).unwrap();
        let auth = authenticator(&src, cp);
        let (tiles, bytes) = scan_tiles(&src, 0, 3, &e).unwrap();
        assert!(bytes > 0);
        for t in &tiles {
            assert_eq!(t.unparsed, 0);
            assert_eq!(t.root.0, auth.tile_root(t.tile_index).unwrap());
        }
        results.push(tiles);
    }
    // The result does not depend on how the log pages its answers.
    assert!(results.windows(2).all(|w| w[0] == w[1]));
    let names: Vec<&str> = results[0]
        .iter()
        .flat_map(|t| t.matches.iter().map(|m| m.name.as_str()))
        .collect();
    assert!(names.contains(&"paypa1-account-verify.com"), "{names:?}");
    // The tile root is the Merkle root of the leaf hashes, as for a static log.
    let (first, _) = source(&log).entries(0).unwrap();
    let leaves: Vec<[u8; 32]> = first.iter().map(|x| x.leaf_hash).collect();
    assert_eq!(results[0][0].root.0, merkle::root(&leaves));
}

#[test]
fn only_full_tiles_are_available() {
    let log = MockRfc6962Log::build(ORIGIN, &entries(800)).unwrap();
    let src = source(&log);
    let auth = authenticator(&src, checkpoint(&log, 800));
    assert!(auth.tile_root(2).is_ok());
    assert!(matches!(auth.tile_root(3), Err(CtError::NotFound(_))));
    // Entries beyond the log do not exist either.
    assert!(src.entries(3).is_err());
}

#[test]
fn a_log_serving_other_entries_than_it_hashed_is_caught() {
    let mut log = MockRfc6962Log::build(ORIGIN, &entries(512)).unwrap();
    // Entry 300 is replaced by a different valid entry: its leaf hash no longer matches.
    let other = MockRfc6962Log::build(ORIGIN, &entries(256)).unwrap();
    log.replace_leaf_input(300, other.leaf_input(5).to_vec());
    let src = source(&log);
    let auth = authenticator(&src, checkpoint(&log, 512));
    assert!(
        auth.tile_root(0).is_ok(),
        "an untouched tile still verifies"
    );
    let err = auth.tile_root(1).unwrap_err();
    assert!(matches!(err, CtError::Unauthenticated(_)), "{err:?}");
}

#[test]
fn a_log_that_pages_wrongly_is_refused() {
    let log = MockRfc6962Log::build(ORIGIN, &entries(256)).unwrap();
    struct Greedy(MockRfc6962Log);
    impl cybermesh_ct::rfc6962::LogApi for Greedy {
        fn get_sth(&self) -> Result<cybermesh_ct::rfc6962::Sth, CtError> {
            self.0.get_sth()
        }
        fn get_entries(&self, start: u64, end: u64) -> Result<Vec<Vec<u8>>, CtError> {
            // More than asked: entries beyond `end`.
            let mut v = self.0.get_entries(start, end)?;
            v.push(v[0].clone());
            Ok(v)
        }
        fn get_proof_by_hash(&self, h: &[u8; 32], n: u64) -> Result<(u64, Vec<[u8; 32]>), CtError> {
            self.0.get_proof_by_hash(h, n)
        }
        fn get_sth_consistency(&self, a: u64, b: u64) -> Result<Vec<[u8; 32]>, CtError> {
            self.0.get_sth_consistency(a, b)
        }
    }
    let mut l = log.clone();
    l.max_entries_per_call = 10;
    let src = Rfc6962Source::new(Box::new(Greedy(l)), &info(&log)).unwrap();
    assert!(matches!(src.entries(0), Err(CtError::Malformed(_))));
    // A log that returns nothing is refused too, not retried forever: unavailable, as for a
    // log that has not yet served its newest entries.
    let mut empty = log.clone();
    empty.max_entries_per_call = 0;
    assert!(matches!(
        source(&empty).entries(0),
        Err(CtError::NotFound(_))
    ));
}

#[test]
fn a_log_that_extends_its_history_is_consistent_for_every_size() {
    let log = MockRfc6962Log::build(ORIGIN, &entries(600)).unwrap();
    let src = source(&log);
    // Sizes with and without a power of two among them, and the full tree.
    let sizes = [
        1u64, 2, 3, 7, 8, 100, 255, 256, 257, 300, 512, 513, 599, 600,
    ];
    for &n in &sizes {
        let newer = authenticator(&src, checkpoint(&log, n));
        for &m in sizes.iter().filter(|m| **m <= n) {
            let older = checkpoint(&log, m);
            newer
                .prove_extends(&older)
                .unwrap_or_else(|e| panic!("{m} -> {n}: {e}"));
            assert_eq!(
                newer.consistency_with(&older).unwrap(),
                Consistency::Consistent,
                "{m} -> {n}"
            );
        }
        // The empty tree is consistent with everything.
        let empty = Checkpoint {
            origin: ORIGIN.into(),
            size: 0,
            root: merkle::empty_root(),
            signed_at_ms: 0,
        };
        assert_eq!(
            newer.consistency_with(&empty).unwrap(),
            Consistency::Consistent
        );
    }
    // A tree cannot extend a larger one.
    let small = authenticator(&src, checkpoint(&log, 100));
    assert!(small.prove_extends(&checkpoint(&log, 200)).is_err());
    assert!(small.consistency_with(&checkpoint(&log, 200)).is_err());
}

#[test]
fn a_forked_log_is_proven_inconsistent_with_a_proof_anyone_can_check() {
    let honest = MockRfc6962Log::build(ORIGIN, &entries(600)).unwrap();
    // The same log key signs a different history: same size, or a different prefix.
    let mut fork = MockRfc6962Log::build(ORIGIN, &entries(600)).unwrap();
    fork.extend(&entries(10)).unwrap();
    let src = source(&fork);
    let newest = fork.size();
    let tree = authenticator(&src, checkpoint(&fork, newest));
    // Prefix sizes that are (128, 256, 512) and are not (100, 300) a power of two.
    for m in [100u64, 128, 256, 300, 512] {
        // `honest` and `fork` hold different certificates, so their prefixes differ.
        let other = checkpoint(&honest, m);
        match tree.consistency_with(&other).unwrap() {
            Consistency::Inconsistent { prefix_root, proof } => {
                assert_eq!(prefix_root, fork.root_at(m), "m = {m}");
                assert_ne!(prefix_root, other.root);
                // The proof anyone can check: from the fork's own prefix to its signed root.
                assert!(
                    merkle::verify_consistency(
                        m,
                        newest,
                        &prefix_root,
                        &checkpoint(&fork, newest).root,
                        &proof
                    ),
                    "m = {m}"
                );
            }
            Consistency::Consistent => panic!("m = {m}: a fork was called consistent"),
        }
    }
    // Two roots for one size need no proof.
    let same_size = checkpoint(&honest, 600);
    let t600 = authenticator(&src, checkpoint(&fork, 600));
    assert!(matches!(
        t600.consistency_with(&same_size).unwrap(),
        Consistency::Inconsistent { ref proof, .. } if proof.is_empty()
    ));
}

#[test]
fn leaf_inputs_are_parsed_strictly() {
    let log = MockRfc6962Log::build(ORIGIN, &entries(256)).unwrap();
    let good = log.leaf_input(0).to_vec();
    let e = parse_leaf_input(7, &good).unwrap();
    assert_eq!(e.index, 7);
    assert_eq!(e.leaf_hash, merkle::leaf_hash(&good));
    // Truncated, padded, and of another version or type: refused.
    assert!(parse_leaf_input(0, &good[..good.len() - 1]).is_err());
    let mut padded = good.clone();
    padded.push(0);
    assert!(parse_leaf_input(0, &padded).is_err());
    let mut v1 = good.clone();
    v1[0] = 1;
    assert!(parse_leaf_input(0, &v1).is_err());
    let mut other_type = good.clone();
    other_type[1] = 1;
    assert!(parse_leaf_input(0, &other_type).is_err());
    let mut unknown_entry = good;
    unknown_entry[10] = 0xff;
    assert!(parse_leaf_input(0, &unknown_entry).is_err());
    assert!(parse_leaf_input(0, &[]).is_err());
}

#[test]
fn downloaded_bytes_count_what_the_log_sent_chains_included() {
    // A classic log's get-entries answer also carries each entry's certificate chain. The
    // bytes reported (and so any bandwidth cap) must count it, not only the leaves.
    struct Chains(MockRfc6962Log);
    impl cybermesh_ct::rfc6962::LogApi for Chains {
        fn get_sth(&self) -> Result<cybermesh_ct::rfc6962::Sth, CtError> {
            self.0.get_sth()
        }
        fn get_entries(&self, start: u64, end: u64) -> Result<Vec<Vec<u8>>, CtError> {
            self.0.get_entries(start, end)
        }
        fn get_entries_sized(
            &self,
            start: u64,
            end: u64,
        ) -> Result<(Vec<Vec<u8>>, usize), CtError> {
            let leaves = self.0.get_entries(start, end)?;
            let size = leaves.iter().map(|l| l.len() + 4000).sum();
            Ok((leaves, size))
        }
        fn get_proof_by_hash(&self, h: &[u8; 32], n: u64) -> Result<(u64, Vec<[u8; 32]>), CtError> {
            self.0.get_proof_by_hash(h, n)
        }
        fn get_sth_consistency(&self, a: u64, b: u64) -> Result<Vec<[u8; 32]>, CtError> {
            self.0.get_sth_consistency(a, b)
        }
    }
    let log = MockRfc6962Log::build(ORIGIN, &entries(256)).unwrap();
    let leaf_bytes: usize = (0..256).map(|i| log.leaf_input(i).len()).sum();
    // The default counts leaves only.
    let (_, plain) = source(&log).entries(0).unwrap();
    assert_eq!(plain, leaf_bytes);
    let src = Rfc6962Source::new(Box::new(Chains(log.clone())), &info(&log)).unwrap();
    let (e, counted) = src.entries(0).unwrap();
    assert_eq!(e.len(), 256);
    assert_eq!(counted, leaf_bytes + 256 * 4000);
    // A cached tile reports the same size, so a second read is not undercounted.
    assert_eq!(src.entries(0).unwrap().1, counted);
}
