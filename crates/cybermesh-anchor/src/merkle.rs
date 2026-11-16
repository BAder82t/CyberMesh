//! RFC 9162 (Certificate Transparency v2) Merkle tree hashing and proofs.

use sha2::{Digest as _, Sha256};

pub type Hash = [u8; 32];

/// Hash of the empty tree.
#[must_use]
pub fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

/// `SHA-256(0x00 || data)`.
#[must_use]
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

/// `SHA-256(0x01 || left || right)`.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Largest power of two strictly less than `n` (n >= 2).
fn split(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Merkle tree hash over leaf hashes.
#[must_use]
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// Audit path for leaf `m` in the tree over `leaves` (RFC 6962 PATH).
#[must_use]
pub fn inclusion_proof(m: usize, leaves: &[Hash]) -> Vec<Hash> {
    let n = leaves.len();
    if n <= 1 || m >= n {
        return Vec::new();
    }
    let k = split(n);
    if m < k {
        let mut p = inclusion_proof(m, &leaves[..k]);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = inclusion_proof(m - k, &leaves[k..]);
        p.push(root(&leaves[..k]));
        p
    }
}

fn subproof(m: usize, leaves: &[Hash], complete: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        return if complete { Vec::new() } else { vec![root(leaves)] };
    }
    let k = split(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], complete);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(root(&leaves[..k]));
        p
    }
}

/// Consistency proof between the first `m` leaves and all of `leaves` (RFC 6962 PROOF).
#[must_use]
pub fn consistency_proof(m: usize, leaves: &[Hash]) -> Vec<Hash> {
    if m == 0 || m >= leaves.len() {
        return Vec::new();
    }
    subproof(m, leaves, true)
}

/// RFC 9162 section 2.1.3.2.
#[must_use]
pub fn verify_inclusion(
    leaf_index: u64,
    tree_size: u64,
    leaf: &Hash,
    proof: &[Hash],
    root_hash: &Hash,
) -> bool {
    if leaf_index >= tree_size {
        return false;
    }
    let (mut fn_, mut sn) = (leaf_index, tree_size - 1);
    let mut r = *leaf;
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root_hash
}

/// RFC 9162 section 2.1.4.2.
#[must_use]
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_hash: &Hash,
    second_hash: &Hash,
    proof: &[Hash],
) -> bool {
    if first > second {
        return false;
    }
    if first == second {
        return proof.is_empty() && first_hash == second_hash;
    }
    if first == 0 {
        // Every tree is consistent with the empty tree.
        return proof.is_empty();
    }
    if proof.is_empty() {
        return false;
    }
    let mut path: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        path.push(*first_hash);
    }
    path.extend_from_slice(proof);
    let (mut fn_, mut sn) = (first - 1, second - 1);
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let mut fr = path[0];
    let mut sr = path[0];
    for c in &path[1..] {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    fr == *first_hash && sr == *second_hash && sn == 0
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(&(i as u64).to_be_bytes())).collect()
    }

    #[test]
    fn empty_tree_is_sha256_of_nothing() {
        assert_eq!(
            hex::encode(empty_root()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn exhaustive_small_trees() {
        for n in 1..=33usize {
            let l = leaves(n);
            let r = root(&l);
            for m in 0..n {
                let p = inclusion_proof(m, &l);
                assert!(verify_inclusion(m as u64, n as u64, &l[m], &p, &r), "n={n} m={m}");
                // Wrong index, wrong leaf, wrong size, truncated proof must all fail.
                if n > 1 {
                    assert!(!verify_inclusion(((m + 1) % n) as u64, n as u64, &l[m], &p, &r));
                    // Note: a claimed size of n+1 against the size-n root can verify for
                    // some (m, n) (e.g. n=3, m=0). Size and root are bound together by the
                    // checkpoint, so the check that matters is against the size-(n+1) root.
                    let l2 = leaves(n + 1);
                    assert!(!verify_inclusion(m as u64, n as u64 + 1, &l[m], &p, &root(&l2)));
                    if !p.is_empty() {
                        assert!(!verify_inclusion(m as u64, n as u64, &l[m], &p[..p.len() - 1], &r));
                    }
                }
                assert!(!verify_inclusion(m as u64, n as u64, &leaf_hash(b"x"), &p, &r));
            }
            for m in 1..=n {
                let p = consistency_proof(m, &l);
                let r1 = root(&l[..m]);
                assert!(verify_consistency(m as u64, n as u64, &r1, &r, &p), "n={n} m={m}");
                if m < n {
                    assert!(!verify_consistency(m as u64, n as u64, &leaf_hash(b"x"), &r, &p));
                    assert!(!verify_consistency(m as u64, n as u64, &r1, &leaf_hash(b"x"), &p));
                }
            }
        }
    }

    #[test]
    fn rewritten_history_fails_consistency() {
        let l = leaves(10);
        let mut forged = l.clone();
        forged[3] = leaf_hash(b"rewritten");
        let p = consistency_proof(5, &forged);
        assert!(!verify_consistency(5, 10, &root(&l[..5]), &root(&forged), &p));
    }

    proptest! {
        #[test]
        fn random_inclusion_and_consistency(n in 1usize..200, m_seed in any::<usize>(), k_seed in any::<usize>()) {
            let l = leaves(n);
            let m = m_seed % n;
            let r = root(&l);
            prop_assert!(verify_inclusion(m as u64, n as u64, &l[m], &inclusion_proof(m, &l), &r));
            let k = 1 + k_seed % n;
            prop_assert!(verify_consistency(k as u64, n as u64, &root(&l[..k]), &r, &consistency_proof(k, &l)));
        }

        #[test]
        fn garbage_proofs_never_panic(n in 1u64..1000, idx in any::<u64>(), proof in proptest::collection::vec(any::<[u8;32]>(), 0..20)) {
            let _ = verify_inclusion(idx, n, &[0u8;32], &proof, &[1u8;32]);
            let _ = verify_consistency(idx % (n + 1), n, &[0u8;32], &[1u8;32], &proof);
        }
    }
}
