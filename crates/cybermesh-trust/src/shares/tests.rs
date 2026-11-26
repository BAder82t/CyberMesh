#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use cybermesh_entropy::{Pool, Provenance, Purpose};
use cybermesh_sharing::{RandomSource, split};

const SET: [u8; 16] = [3; 16];

/// xorshift for tests only. NOT secret randomness.
struct TestRng(u64);
impl RandomSource for TestRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), SharingError> {
        for b in buf {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *b = (self.0 >> 24) as u8;
        }
        Ok(())
    }
}

fn fixture(n: usize) -> Vec<u8> {
    let mut s = 0x9e37_79b9_7f4a_7c15u64;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8 | 1
        })
        .collect()
}

fn pool(dir: &std::path::Path, purpose: Purpose, n: usize) -> Pool {
    Pool::create(
        dir,
        PoolId([4; 16]),
        purpose,
        Provenance::ProvisionedShared,
        &fixture(n),
    )
    .unwrap()
}

const N: usize = 5;
const BLOCK: usize = 16 * (1 + N);

/// A dealing of `secret` as 3-of-5, tagged from the dealer's pool; and a function that makes a
/// fresh verifier with the matching block (the verifier's pool holds identical material).
struct Dealing {
    shares: Vec<AuthShare>,
    secret: Vec<u8>,
    _dealer: tempfile::TempDir,
}

fn deal(secret: &[u8]) -> Dealing {
    let d = tempfile::tempdir().unwrap();
    let dealer = pool(d.path(), Purpose::Authentication, BLOCK * 3);
    let shares = split(secret, 3, N, SET, 1, &mut TestRng(77)).unwrap();
    let shares = authenticate_shares(shares, dealer.reserve(BLOCK).unwrap()).unwrap();
    Dealing {
        shares,
        secret: secret.to_vec(),
        _dealer: d,
    }
}

fn checker(max_failures: u32) -> (tempfile::TempDir, ShareChecker) {
    let d = tempfile::tempdir().unwrap();
    let v = pool(d.path(), Purpose::Authentication, BLOCK * 3);
    let c = ShareChecker::new(v.reserve(BLOCK).unwrap(), max_failures).unwrap();
    (d, c)
}

fn copy(a: &AuthShare) -> AuthShare {
    AuthShare::from_bytes(&a.to_bytes()).unwrap()
}

/// Flip a bit of the share's data, keeping its tag.
fn tamper(a: &AuthShare) -> AuthShare {
    let mut b = a.to_bytes();
    let last = b.len() - 1;
    b[last] ^= 0x01;
    AuthShare::from_bytes(&b).unwrap()
}

#[test]
fn honest_shares_authenticate_and_reconstruct() {
    let dl = deal(b"the dealer's secret");
    let (_d, mut c) = checker(10);
    for s in &dl.shares {
        c.check(s).unwrap();
        c.check(s).unwrap(); // verifying again is not tagging again
    }
    let r = c.reconstruct(dl.shares.iter().map(copy).collect()).unwrap();
    assert_eq!(r.secret, dl.secret);
    assert!(r.rejected.is_empty());
    assert_eq!(c.failures(), 0);
    // Exactly k shares suffice.
    let (_d2, mut c2) = checker(10);
    let r = c2
        .reconstruct(dl.shares.iter().take(3).map(copy).collect())
        .unwrap();
    assert_eq!(r.secret, dl.secret);
}

#[test]
fn every_pair_of_altered_shares_is_rejected_and_the_secret_is_still_right() {
    // The case where Reed-Solomon decoding alone returned a wrong secret in 6 of 10 pairs
    // (3-of-5, two bad shares): here all 10 recover the real secret and name the bad shares.
    let dl = deal(b"never wrong");
    for a in 0..N {
        for b in a + 1..N {
            let presented: Vec<AuthShare> = dl
                .shares
                .iter()
                .enumerate()
                .map(|(i, s)| if i == a || i == b { tamper(s) } else { copy(s) })
                .collect();
            let (_d, mut c) = checker(10);
            let r = c.reconstruct(presented).unwrap();
            assert_eq!(r.secret, dl.secret, "bad {a},{b}");
            let want: Vec<u8> = [a, b]
                .iter()
                .map(|&i| dl.shares[i].share().index())
                .collect();
            assert_eq!(r.rejected, want);
            assert_eq!(c.failures(), 2);
        }
    }
}

#[test]
fn too_many_altered_shares_is_an_error_never_a_wrong_secret() {
    let dl = deal(b"fail closed");
    for bad in [[0, 1, 2], [0, 2, 4], [1, 3, 4]] {
        let presented: Vec<AuthShare> = dl
            .shares
            .iter()
            .enumerate()
            .map(|(i, s)| if bad.contains(&i) { tamper(s) } else { copy(s) })
            .collect();
        let (_d, mut c) = checker(10);
        match c.reconstruct(presented) {
            Err(SharesError::TooFewAuthentic { needed: 3, got: 2 }) => {}
            other => panic!("{other:?}"),
        }
    }
    // All shares altered: nothing authentic at all.
    let (_d, mut c) = checker(10);
    let all: Vec<AuthShare> = dl.shares.iter().map(tamper).collect();
    assert!(matches!(
        c.reconstruct(all),
        Err(SharesError::TooFewAuthentic { got: 0, .. })
    ));
}

#[test]
fn a_holder_cannot_move_its_tag_to_another_share_set_or_epoch() {
    let dl = deal(b"bound to the share");
    let (_d, mut c) = checker(10);
    // Share 2's data under share 1's tag.
    let mut b = dl.shares[0].to_bytes();
    let other = dl.shares[1].to_bytes();
    b.truncate(BLOCK_HEADER);
    b.extend_from_slice(&other[BLOCK_HEADER..]);
    let swapped = AuthShare::from_bytes(&b).unwrap();
    assert_eq!(c.check(&swapped), Err(SharesError::Invalid(2)));
    // The same share relabelled to another epoch or set.
    for patch in [
        |v: &mut Vec<u8>| v[BLOCK_HEADER + 17 + 3] ^= 1,
        |v: &mut Vec<u8>| v[BLOCK_HEADER + 1] ^= 1,
    ] {
        let mut b = dl.shares[0].to_bytes();
        patch(&mut b);
        let relabelled = AuthShare::from_bytes(&b).unwrap();
        assert_eq!(c.check(&relabelled), Err(SharesError::Invalid(1)));
    }
    // Index relabelled: share 1's data claiming to be index 3.
    let mut b = dl.shares[0].to_bytes();
    b[BLOCK_HEADER + 1 + 16 + 4 + 1] = 3;
    assert_eq!(
        c.check(&AuthShare::from_bytes(&b).unwrap()),
        Err(SharesError::Invalid(3))
    );
}

#[test]
fn a_tag_from_another_dealing_is_refused() {
    let dl = deal(b"first dealing");
    // A second dealing from the same pools: the verifier's second block is at offset BLOCK.
    let (_d, mut c) = {
        let d = tempfile::tempdir().unwrap();
        let v = pool(d.path(), Purpose::Authentication, BLOCK * 3);
        v.reserve(BLOCK).unwrap(); // skip the first block
        let c = ShareChecker::new(v.reserve(BLOCK).unwrap(), 10).unwrap();
        (d, c)
    };
    assert!(
        matches!(c.check(&dl.shares[0]), Err(SharesError::OutOfStep { have, got: 0 }) if have == BLOCK as u64)
    );
    // Forging the public offset field does not help: the key differs.
    let mut b = dl.shares[0].to_bytes();
    b[..8].copy_from_slice(&(BLOCK as u64).to_be_bytes());
    assert_eq!(
        c.check(&AuthShare::from_bytes(&b).unwrap()),
        Err(SharesError::Invalid(1))
    );
    assert_eq!(
        c.failures(),
        1,
        "out-of-step is not counted, a forged offset is"
    );
}

#[test]
fn the_failure_budget_retires_the_dealing() {
    let dl = deal(b"budget");
    let (_d, mut c) = checker(2);
    assert_eq!(
        c.check(&tamper(&dl.shares[0])),
        Err(SharesError::Invalid(1))
    );
    assert_eq!(
        c.check(&tamper(&dl.shares[1])),
        Err(SharesError::Invalid(2))
    );
    assert_eq!(c.check(&dl.shares[2]), Err(SharesError::KeyRetired));
    assert_eq!(c.failures(), 2);
    let (_d, mut c) = checker(2);
    let presented: Vec<AuthShare> = vec![
        tamper(&dl.shares[0]),
        tamper(&dl.shares[1]),
        copy(&dl.shares[2]),
        copy(&dl.shares[3]),
        copy(&dl.shares[4]),
    ];
    assert_eq!(
        c.reconstruct(presented).unwrap_err(),
        SharesError::KeyRetired
    );
}

#[test]
fn a_dishonest_dealer_is_caught_only_by_the_consistency_check() {
    // The dealer tags shares of two different polynomials: every tag is valid.
    let d = tempfile::tempdir().unwrap();
    let dealer = pool(d.path(), Purpose::Authentication, BLOCK * 3);
    let a = split(b"secret A", 3, N, SET, 1, &mut TestRng(1)).unwrap();
    let b = split(b"secret B", 3, N, SET, 1, &mut TestRng(2)).unwrap();
    let mixed: Vec<Share> = a.into_iter().take(2).chain(b.into_iter().skip(2)).collect();
    let tagged = authenticate_shares(mixed, dealer.reserve(BLOCK).unwrap()).unwrap();
    // More than k shares: the cross-check notices.
    let (_d1, mut c) = checker(10);
    let err = c
        .reconstruct(tagged.iter().map(copy).collect())
        .unwrap_err();
    assert_eq!(err, SharesError::Sharing(SharingError::Inconsistent));
    // Exactly k shares: it returns a value that is neither secret. Documented limit: a valid tag
    // only says the dealer issued this share.
    let (_d2, mut c) = checker(10);
    let r = c
        .reconstruct(tagged.iter().take(3).map(copy).collect())
        .unwrap();
    assert_ne!(r.secret, b"secret A");
    assert_ne!(r.secret, b"secret B");
}

#[test]
fn material_must_be_authentication_material_of_the_right_shape() {
    let d = tempfile::tempdir().unwrap();
    let enc = pool(d.path(), Purpose::Encryption, BLOCK * 2);
    let shares = |n| split(b"x-secret!", 2, n, SET, 1, &mut TestRng(5)).unwrap();
    assert!(matches!(
        authenticate_shares(shares(3), enc.reserve(BLOCK).unwrap()),
        Err(SharesError::BadMaterial)
    ));
    let d2 = tempfile::tempdir().unwrap();
    let auth = pool(d2.path(), Purpose::Authentication, 1024);
    // 16 bytes is a key with no holder slots; 40 is not a multiple of 16.
    for bad in [16, 40] {
        assert!(matches!(
            authenticate_shares(shares(3), auth.reserve(bad).unwrap()),
            Err(SharesError::BadMaterial)
        ));
    }
    // A block for 3 holders cannot tag share index 4 or 5.
    let d3 = tempfile::tempdir().unwrap();
    let p = pool(d3.path(), Purpose::Authentication, 1024);
    assert_eq!(
        authenticate_shares(shares(5), p.reserve(16 * 4).unwrap()).unwrap_err(),
        SharesError::NoSlot(4)
    );
    // A checker refuses a presented share whose slot it does not have.
    let dl = deal(b"slots!!!");
    let d4 = tempfile::tempdir().unwrap();
    let v = pool(d4.path(), Purpose::Authentication, 1024);
    let mut small = ShareChecker::new(v.reserve(16 * 3).unwrap(), 10).unwrap();
    assert_eq!(small.check(&dl.shares[4]), Err(SharesError::NoSlot(5)));
}

#[test]
fn wire_format_is_strict_and_secrets_are_redacted() {
    let dl = deal(b"wire");
    let s = &dl.shares[0];
    assert_eq!(&AuthShare::from_bytes(&s.to_bytes()).unwrap(), s);
    let b = s.to_bytes();
    assert!(AuthShare::from_bytes(&[]).is_err());
    assert!(AuthShare::from_bytes(&b[..BLOCK_HEADER]).is_err());
    assert!(AuthShare::from_bytes(&b[..b.len() - 1]).is_err());
    let mut long = b.clone();
    long.push(0);
    assert!(AuthShare::from_bytes(&long).is_err());
    let (_d, c) = checker(1);
    assert!(!format!("{c:?}").contains("pads"));
    assert!(!format!("{s:?}").contains("secret"));
}
