#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use cybermesh_entropy::{Pool, PoolId, Provenance};
use proptest::prelude::*;
use std::path::Path;

/// xorshift fixture bytes (never all zero). Test fixture only; NOT secret randomness.
fn fixture(seed: u64, n: usize) -> Vec<u8> {
    let mut s = seed | 1;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8 | 1
        })
        .collect()
}

fn pool(dir: &Path, tag: u8, purpose: Purpose, n: usize) -> Pool {
    Pool::create(
        dir,
        PoolId([tag; 16]),
        purpose,
        Provenance::ProvisionedShared,
        &fixture(42, n),
    )
    .unwrap()
}

/// Sender and receiver pools with identical material, as two provisioned parties would hold.
fn pair(n: usize) -> (tempfile::TempDir, tempfile::TempDir, Pool, Pool) {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a = pool(da.path(), 1, Purpose::Authentication, n);
    let b = pool(db.path(), 1, Purpose::Authentication, n);
    (da, db, a, b)
}

fn gf8_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

#[test]
fn field_multiplication_is_a_field_and_matches_a_reference() {
    // x * x^127 = x^128 = x^7 + x^2 + x + 1.
    assert_eq!(gf_mul(2, 1 << 127), 0x87);
    // A structurally different reference: most significant bit first.
    let reference = |a: u128, b: u128| {
        (0..128).rev().fold(0u128, |acc, i| {
            let acc = (acc << 1) ^ (0x87 * (acc >> 127));
            if (b >> i) & 1 == 1 { acc ^ a } else { acc }
        })
    };
    let v: Vec<u128> = fixture(7, 16 * 12)
        .chunks(16)
        .map(|c| u128::from_be_bytes(c.try_into().unwrap()))
        .collect();
    for &a in &v {
        assert_eq!(gf_mul(a, 1), a);
        assert_eq!(gf_mul(a, 0), 0);
        for &b in &v {
            assert_eq!(gf_mul(a, b), gf_mul(b, a));
            assert_eq!(gf_mul(a, b), reference(a, b));
            for &c in &v[..4] {
                assert_eq!(gf_mul(gf_mul(a, b), c), gf_mul(a, gf_mul(b, c)));
                assert_eq!(gf_mul(a, b ^ c), gf_mul(a, b) ^ gf_mul(a, c));
            }
        }
    }
}

#[test]
fn tag_and_verify_roundtrip_between_two_parties() {
    let (_da, _db, a, b) = pair(16 * 10);
    let ka = MacKey::from_reservation(a.reserve(16).unwrap()).unwrap();
    let mut vb = Verifier::new(
        MacKey::from_reservation(b.reserve(16).unwrap()).unwrap(),
        DEFAULT_MAX_FAILURES,
    );
    for msg in [
        &b""[..],
        b"x",
        b"hello trust fabric",
        &[7u8; 16],
        &[7u8; 17],
        &[0u8; 100],
    ] {
        // Same offset on both sides: the n-th message uses the n-th pad.
        let t = ka.tag(msg, a.reserve(16).unwrap()).unwrap();
        vb.verify(msg, &t, b.reserve(16).unwrap()).unwrap();
    }
    assert_eq!(vb.failures(), 0);
}

#[test]
fn modified_message_tag_or_out_of_step_pad_is_rejected_and_counted() {
    let (_da, _db, a, b) = pair(16 * 12);
    let ka = MacKey::from_reservation(a.reserve(16).unwrap()).unwrap();
    let mut vb = Verifier::new(
        MacKey::from_reservation(b.reserve(16).unwrap()).unwrap(),
        100,
    );
    let msg = b"pay 10 to alice";
    let t = ka.tag(msg, a.reserve(16).unwrap()).unwrap();

    assert_eq!(
        vb.verify(b"pay 99 to alice", &t, b.reserve(16).unwrap()),
        Err(MacError::Invalid)
    );
    let mut bytes = t.to_bytes();
    bytes[5] ^= 1;
    // The receiver's pad for the first message was spent by the failed attempt above, so a
    // retry must use the next pad: a failed check burns it, as the docs say.
    assert_eq!(
        vb.verify(msg, &Tag::from_bytes(bytes), b.reserve(16).unwrap()),
        Err(MacError::Invalid)
    );
    assert_eq!(vb.failures(), 2);
    // Pad desynchronisation: the genuine tag against the wrong (next) pad fails too.
    assert_eq!(
        vb.verify(msg, &t, b.reserve(16).unwrap()),
        Err(MacError::Invalid)
    );
    assert_eq!(vb.failures(), 3);
}

#[test]
fn a_pad_is_spent_even_when_the_tag_is_wrong() {
    let (_da, _db, a, b) = pair(16 * 4);
    let ka = MacKey::from_reservation(a.reserve(16).unwrap()).unwrap();
    let mut vb = Verifier::new(
        MacKey::from_reservation(b.reserve(16).unwrap()).unwrap(),
        10,
    );
    let before = b.stats().unwrap().remaining;
    let t = ka.tag(b"m", a.reserve(16).unwrap()).unwrap();
    let _ = vb.verify(b"other", &t, b.reserve(16).unwrap());
    assert_eq!(b.stats().unwrap().remaining, before - 16);
}

#[test]
fn different_pads_give_different_tags_for_the_same_message() {
    let (_da, _db, a, _b) = pair(16 * 4);
    let k = MacKey::from_reservation(a.reserve(16).unwrap()).unwrap();
    let t1 = k.tag(b"same", a.reserve(16).unwrap()).unwrap();
    let t2 = k.tag(b"same", a.reserve(16).unwrap()).unwrap();
    assert_ne!(t1, t2);
}

#[test]
fn padding_and_length_ambiguities_do_not_collide() {
    let msgs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0; 2],
        vec![0; 15],
        vec![0; 16],
        vec![0; 17],
        vec![0; 32],
        b"a".to_vec(),
        b"a\0".to_vec(),
        b"\0a".to_vec(),
    ];
    for key in fixture(5, 16 * 6)
        .chunks(16)
        .map(|c| u128::from_be_bytes(c.try_into().unwrap()))
    {
        let hashes: Vec<u128> = msgs.iter().map(|m| poly_hash(key, m)).collect();
        for i in 0..hashes.len() {
            for j in i + 1..hashes.len() {
                assert_ne!(hashes[i], hashes[j], "{:?} vs {:?}", msgs[i], msgs[j]);
            }
        }
    }
}

#[test]
fn only_authentication_material_of_the_right_size_is_accepted() {
    let d = tempfile::tempdir().unwrap();
    let enc = pool(d.path(), 1, Purpose::Encryption, 64);
    let auth = pool(d.path(), 2, Purpose::Authentication, 128);
    // A pad-purpose reservation cannot become a key or a MAC pad.
    assert!(matches!(
        MacKey::from_reservation(enc.reserve(16).unwrap()),
        Err(MacError::BadMaterial)
    ));
    assert!(matches!(
        MacKey::from_reservation(auth.reserve(32).unwrap()),
        Err(MacError::BadMaterial)
    ));
    assert!(matches!(
        MacKey::from_reservation(auth.reserve(8).unwrap()),
        Err(MacError::BadMaterial)
    ));
    let k = MacKey::from_reservation(auth.reserve(16).unwrap()).unwrap();
    assert_eq!(
        k.tag(b"m", enc.reserve(16).unwrap()).unwrap_err(),
        MacError::BadMaterial
    );
    assert_eq!(
        k.tag(b"m", auth.reserve(24).unwrap()).unwrap_err(),
        MacError::BadMaterial
    );
    assert!(k.tag(b"m", auth.reserve(16).unwrap()).is_ok());
}

#[test]
fn a_key_is_retired_after_its_failure_budget() {
    let (_da, _db, a, b) = pair(16 * 12);
    let ka = MacKey::from_reservation(a.reserve(16).unwrap()).unwrap();
    let mut vb = Verifier::new(MacKey::from_reservation(b.reserve(16).unwrap()).unwrap(), 3);
    let forged = Tag::from_bytes([1; 16]);
    for _ in 0..3 {
        assert_eq!(
            vb.verify(b"m", &forged, b.reserve(16).unwrap()),
            Err(MacError::Invalid)
        );
    }
    // Even a genuine tag is refused now: the key must be replaced.
    for _ in 0..3 {
        a.reserve(16).unwrap(); // keep the sender in step
    }
    let t = ka.tag(b"m", a.reserve(16).unwrap()).unwrap();
    assert_eq!(
        vb.verify(b"m", &t, b.reserve(16).unwrap()),
        Err(MacError::KeyRetired)
    );
    assert_eq!(vb.failures(), 3, "retirement is not another failure");
    // A bad pad is not a forgery attempt and does not count.
    let (_dc, _dd, c, d2) = pair(16 * 6);
    let mut v = Verifier::new(
        MacKey::from_reservation(d2.reserve(16).unwrap()).unwrap(),
        5,
    );
    let _ = c;
    let junk = pool(_dc.path(), 9, Purpose::Encryption, 32);
    assert_eq!(
        v.verify(b"m", &forged, junk.reserve(16).unwrap()),
        Err(MacError::BadMaterial)
    );
    assert_eq!(v.failures(), 0);
}

#[test]
fn overlong_messages_are_refused_and_the_boundary_works() {
    let (_da, _db, a, _b) = pair(16 * 6);
    let k = MacKey::from_reservation(a.reserve(16).unwrap()).unwrap();
    assert_eq!(
        k.tag(&vec![1u8; MAX_MESSAGE_LEN + 1], a.reserve(16).unwrap())
            .unwrap_err(),
        MacError::MessageTooLong
    );
    assert!(
        k.tag(&vec![1u8; MAX_MESSAGE_LEN], a.reserve(16).unwrap())
            .is_ok()
    );
}

#[test]
fn forgery_bound_is_what_the_docs_say() {
    let b = forgery_bound(MAX_MESSAGE_LEN, u64::from(DEFAULT_MAX_FAILURES));
    assert!(b > 0.0 && b < 2f64.powi(-90), "{b}");
    assert!(forgery_bound(32, 1) < forgery_bound(32, 2));
    assert!(forgery_bound(32, 1) < forgery_bound(1 << 20, 1));
    // 32 bytes: 2 blocks + length block = degree 3.
    assert!((forgery_bound(32, 1) - 3.0 * 2f64.powi(-128)).abs() < 1e-45);
}

/// The polynomial claim, checked exhaustively over GF(2^8) with the same construction: for any
/// two different messages of up to 3 blocks, at most `3 + 1` of the 256 keys make the hashes
/// equal.
#[test]
fn almost_universal_bound_holds_exhaustively_over_a_small_field() {
    const SYMS: [u8; 5] = [0, 1, 2, 0x80, 0xff];
    let mut msgs: Vec<Vec<u8>> = vec![vec![]];
    for len in 1..=3 {
        let mut next: Vec<Vec<u8>> = vec![vec![]];
        for _ in 0..len {
            next = next
                .iter()
                .flat_map(|m| {
                    SYMS.iter().map(move |&s| {
                        let mut m = m.clone();
                        m.push(s);
                        m
                    })
                })
                .collect();
        }
        msgs.extend(next);
    }
    assert_eq!(msgs.len(), 1 + 5 + 25 + 125);
    let h = |m: &[u8], r: u8| {
        hash_with(
            m.iter().copied(),
            m.len() as u8,
            r,
            0,
            |a, b| a ^ b,
            gf8_mul,
        )
    };
    let mut worst = 0;
    for (i, x) in msgs.iter().enumerate() {
        for y in &msgs[i + 1..] {
            let equal = (0..=255u8).filter(|&r| h(x, r) == h(y, r)).count();
            worst = worst.max(equal);
            assert!(equal <= 4, "{x:?} vs {y:?}: {equal} colliding keys");
        }
    }
    assert!(worst >= 2, "the bound is not vacuous here (worst {worst})");
}

#[test]
fn secrets_are_redacted_and_tags_compare_by_value() {
    let (_da, _db, a, _b) = pair(16 * 3);
    let k = MacKey::from_reservation(a.reserve(16).unwrap()).unwrap();
    assert_eq!(format!("{k:?}"), "MacKey(..)");
    let t = k.tag(b"m", a.reserve(16).unwrap()).unwrap();
    assert_eq!(format!("{t:?}"), "Tag(..)");
    assert_eq!(t, Tag::from_bytes(t.to_bytes()));
    assert!(format!("{:?}", Verifier::new(k, 1)).contains("MacKey(..)"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn any_single_bit_flip_is_detected(msg in proptest::collection::vec(any::<u8>(), 1..80),
                                        bit in any::<usize>(), flip_tag in any::<bool>()) {
        let (_da, _db, a, b) = pair(16 * 6);
        let ka = MacKey::from_reservation(a.reserve(16).unwrap()).unwrap();
        let mut vb = Verifier::new(MacKey::from_reservation(b.reserve(16).unwrap()).unwrap(), 10);
        let t = ka.tag(&msg, a.reserve(16).unwrap()).unwrap();
        let (mut m2, mut t2) = (msg.clone(), t.to_bytes());
        if flip_tag { t2[(bit / 8) % 16] ^= 1 << (bit % 8); } else { m2[(bit / 8) % msg.len()] ^= 1 << (bit % 8); }
        prop_assert_eq!(vb.verify(&m2, &Tag::from_bytes(t2), b.reserve(16).unwrap()), Err(MacError::Invalid));
    }
}
