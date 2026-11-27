#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use cybermesh_entropy::{PoolId, Provenance};
use proptest::prelude::*;
use std::path::Path;

pub(crate) const IT: SecurityProfile = SecurityProfile::InformationTheoretic;

/// xorshift fixture bytes (never zero). Test fixture only; NOT secret randomness.
pub(crate) fn fixture(tag: u8, n: usize) -> Vec<u8> {
    let mut s = 0x9e37_79b9_7f4a_7c15u64 ^ (u64::from(tag) << 32);
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8 | 1
        })
        .collect()
}

// Pool tags: initiator->responder encryption/authentication, responder->initiator ditto.
pub(crate) const IR_ENC: u8 = 1;
pub(crate) const IR_AUTH: u8 = 2;
pub(crate) const RI_ENC: u8 = 3;
pub(crate) const RI_AUTH: u8 = 4;

fn make(dir: &Path, tag: u8, enc: usize, auth: usize, prov: Provenance) -> Pool {
    let (purpose, n) = if tag == IR_ENC || tag == RI_ENC {
        (Purpose::Encryption, enc)
    } else {
        (Purpose::Authentication, auth)
    };
    Pool::create(dir, PoolId([tag; 16]), purpose, prov, &fixture(tag, n)).unwrap()
}

pub(crate) fn open(dir: &Path, tag: u8) -> Pool {
    Pool::open(dir, PoolId([tag; 16])).unwrap()
}

/// Two parties, each with its own directory holding identical copies of the four pools.
pub(crate) struct Rig {
    pub(crate) di: tempfile::TempDir,
    pub(crate) dr: tempfile::TempDir,
}

impl Rig {
    pub(crate) fn new(enc: usize, auth: usize) -> Self {
        let (di, dr) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        for d in [&di, &dr] {
            for t in [IR_ENC, IR_AUTH, RI_ENC, RI_AUTH] {
                make(d.path(), t, enc, auth, Provenance::ProvisionedShared);
            }
        }
        Self { di, dr }
    }
    /// An endpoint as if its owner had already applied a fresh sync response: the gate on
    /// handshakes is open. Most tests are about what happens after that.
    pub(crate) fn ep(&self, role: Role) -> Endpoint {
        let ep = self.cold(role);
        ep.mark_synced();
        ep
    }
    /// An endpoint exactly as opening the pools gives it: unsynced.
    pub(crate) fn cold(&self, role: Role) -> Endpoint {
        let (d, se, sa, re, ra) = match role {
            Role::Initiator => (&self.di, IR_ENC, IR_AUTH, RI_ENC, RI_AUTH),
            Role::Responder => (&self.dr, RI_ENC, RI_AUTH, IR_ENC, IR_AUTH),
        };
        Endpoint::new(
            IT,
            role,
            open(d.path(), se),
            open(d.path(), sa),
            open(d.path(), re),
            open(d.path(), ra),
        )
        .unwrap()
    }
    pub(crate) fn connect(&self) -> (Session, Session) {
        let (ini, hello) = Initiator::start(self.ep(Role::Initiator)).unwrap();
        let (res, reply) = Responder::accept(self.ep(Role::Responder), &hello).unwrap();
        let (si, fin) = ini.finish(&reply).unwrap();
        (si, res.finish(&fin).unwrap())
    }
}

pub(crate) fn big() -> Rig {
    Rig::new(1 << 18, 1 << 12)
}

#[test]
fn handshake_and_bidirectional_records() {
    let rig = big();
    let (mut a, mut b) = rig.connect();
    assert_eq!(a.id(), b.id());
    for i in 0..5u8 {
        let m = vec![i; usize::from(i) * 7];
        assert_eq!(
            b.open(&a.seal(&m).unwrap()).unwrap(),
            Opened::Data(m.clone())
        );
        let r = vec![0xA0 | i; 3 + usize::from(i)];
        assert_eq!(a.open(&b.seal(&r).unwrap()).unwrap(), Opened::Data(r));
    }
    // Empty and one-byte payloads, and the largest allowed.
    for m in [vec![], vec![9], vec![0x55; MAX_RECORD_DATA]] {
        assert_eq!(b.open(&a.seal(&m).unwrap()).unwrap(), Opened::Data(m));
    }
    assert_eq!(
        a.seal(&vec![0; MAX_RECORD_DATA + 1])
            .unwrap_err()
            .to_string(),
        TransportError::TooLarge.to_string()
    );
    assert!(format!("{a:?}").contains("Session") && !format!("{a:?}").contains("pad"));
}

#[test]
fn ciphertext_is_the_plaintext_xor_the_pool_bytes_and_each_byte_is_spent_once() {
    let rig = big();
    let (mut a, mut b) = rig.connect();
    let rec = a.seal(b"hi").unwrap();
    // Frame: type 0, len 2, "hi", zero padding to 8 bytes; pad = the first 8 bytes of the pool.
    let pad = &fixture(IR_ENC, 1 << 18)[..8];
    let frame = [0u8, 0, 0, 0, 2, b'h', b'i', 0];
    let ct = &rec[REC_HEADER..REC_HEADER + 8];
    for i in 0..8 {
        assert_eq!(ct[i] ^ pad[i], frame[i]);
    }
    let rec2 = a.seal(b"hi").unwrap();
    assert_ne!(
        &rec2[REC_HEADER..REC_HEADER + 8],
        ct,
        "same plaintext, fresh pad, different ciphertext"
    );
    let pad2 = &fixture(IR_ENC, 1 << 18)[8..16];
    for i in 0..8 {
        assert_eq!(rec2[REC_HEADER + i] ^ pad2[i], frame[i]);
    }
    b.open(&rec).unwrap();
    b.open(&rec2).unwrap();
    // Sender and receiver consumed the same: 16 encryption bytes; handshake took 48 / 32 of the
    // authentication streams, plus 16 per record.
    let s = |ep: &Session| ep.remaining_to_send().unwrap();
    let (enc, auth) = s(&a);
    assert_eq!((1 << 18) - enc, 16);
    assert_eq!((1 << 12) - auth, 48 + 2 * 16);
    let (_, rauth) = s(&b);
    assert_eq!((1 << 12) - rauth, 32, "responder has sent no record yet");
}

#[test]
fn any_change_to_a_record_ends_the_session() {
    type Tamper = Box<dyn Fn(&mut Vec<u8>)>;
    let cases: Vec<(&str, Tamper)> = vec![
        ("ciphertext", Box::new(|r| r[REC_HEADER + 2] ^= 1)),
        (
            "tag",
            Box::new(|r| {
                let n = r.len();
                r[n - 1] ^= 1;
            }),
        ),
        ("session id", Box::new(|r| r[3] ^= 1)),
        ("direction", Box::new(|r| r[17] ^= 1)),
        ("sequence", Box::new(|r| r[25] ^= 1)),
        ("length field", Box::new(|r| r[29] ^= 1)),
        ("version", Box::new(|r| r[0] = 2)),
        (
            "truncated",
            Box::new(|r| {
                r.pop();
            }),
        ),
        ("extended", Box::new(|r| r.push(0))),
    ];
    for (name, f) in cases {
        let rig = big();
        let (mut a, mut b) = rig.connect();
        let good = a.seal(b"attack at dawn").unwrap();
        let mut bad = good.clone();
        f(&mut bad);
        assert!(b.open(&bad).is_err(), "{name} accepted");
        // Even the untouched record is refused now: the session is over.
        assert!(
            matches!(b.open(&good), Err(TransportError::Terminated)),
            "{name}"
        );
    }
}

#[test]
fn replay_reorder_reflection_and_cross_session_replay_are_refused() {
    let rig = big();
    // Replay.
    let (mut a, mut b) = rig.connect();
    let r0 = a.seal(b"one").unwrap();
    b.open(&r0).unwrap();
    assert!(matches!(
        b.open(&r0),
        Err(TransportError::Order {
            expected: 1,
            got: 0
        })
    ));
    // Reorder (fresh rig: the previous pools are mid-stream).
    let rig = big();
    let (mut a, mut b) = rig.connect();
    let (r0, r1) = (a.seal(b"one").unwrap(), a.seal(b"two").unwrap());
    assert!(matches!(
        b.open(&r1),
        Err(TransportError::Order {
            expected: 0,
            got: 1
        })
    ));
    let _ = r0;
    // Reflection: the initiator's own record fed back to the initiator.
    let rig = big();
    let (mut a, _b) = rig.connect();
    let own = a.seal(b"echo").unwrap();
    assert!(matches!(a.open(&own), Err(TransportError::WrongSession)));
    // Cross-session: a record of session 1 fed to session 2 on the same pools.
    let rig = big();
    let (mut a1, mut b1) = rig.connect();
    let old = a1.seal(b"session one").unwrap();
    b1.open(&old).unwrap();
    let c = a1.close().unwrap();
    assert_eq!(b1.open(&c).unwrap(), Opened::Closed);
    let cb = b1.close().unwrap();
    assert_eq!(a1.open(&cb).unwrap(), Opened::Closed);
    drop((a1, b1));
    let (_a2, mut b2) = rig.connect();
    assert!(matches!(b2.open(&old), Err(TransportError::WrongSession)));
}

#[test]
fn close_is_authenticated_and_final() {
    let rig = big();
    let (mut a, mut b) = rig.connect();
    let c = a.close().unwrap();
    assert!(matches!(a.seal(b"more"), Err(TransportError::Closed)));
    assert!(matches!(a.close(), Err(TransportError::Closed)));
    assert_eq!(b.open(&c).unwrap(), Opened::Closed);
    assert!(matches!(b.open(&c), Err(TransportError::Closed)));
    // Half close: b saw a's close, but b's own direction is still open.
    let late = b.seal(b"late").unwrap();
    assert_eq!(a.open(&late).unwrap(), Opened::Data(b"late".to_vec()));
    let bc = b.close().unwrap();
    assert_eq!(a.open(&bc).unwrap(), Opened::Closed);
    assert!(matches!(a.open(&bc), Err(TransportError::Closed)));
    assert!(matches!(b.seal(b"x"), Err(TransportError::Closed)));
}

#[test]
fn exhaustion_leaves_everything_untouched_and_replenishing_resumes() {
    let rig = Rig::new(64, 1 << 12);
    let (mut a, mut b) = rig.connect();
    let m = [7u8; 20]; // frame 25
    b.open(&a.seal(&m).unwrap()).unwrap();
    b.open(&a.seal(&m).unwrap()).unwrap(); // 50 of 64 spent
    let before = a.remaining_to_send().unwrap();
    assert!(matches!(a.seal(&m), Err(TransportError::KeyExhausted)));
    assert_eq!(a.remaining_to_send().unwrap(), before, "nothing was spent");
    b.open(&a.seal(b"tiny").unwrap()).unwrap(); // frame 9, still fits
    assert!(matches!(a.seal(b"tiny"), Err(TransportError::KeyExhausted)));
    // Both parties provision the same new material; the session continues.
    let extra: Vec<u8> = fixture(99, 100);
    open(rig.di.path(), IR_ENC).replenish(&extra).unwrap();
    open(rig.dr.path(), IR_ENC).replenish(&extra).unwrap();
    // The Session owns its own handles on the same files, so it sees the new bytes.
    assert_eq!(
        b.open(&a.seal(&m).unwrap()).unwrap(),
        Opened::Data(m.to_vec())
    );
}

#[test]
fn the_handshake_refuses_downgrades_forgeries_and_out_of_step_pools() {
    // Another profile announced by the peer.
    let rig = big();
    let (_ini, mut hello) = Initiator::start(rig.ep(Role::Initiator)).unwrap();
    hello[2] = SecurityProfile::Standard as u8;
    assert!(matches!(
        Responder::accept(rig.ep(Role::Responder), &hello),
        Err(TransportError::Downgrade(1))
    ));
    // Tampered hello (session id).
    let rig = big();
    let (_ini, mut hello) = Initiator::start(rig.ep(Role::Initiator)).unwrap();
    hello[5] ^= 1;
    assert!(matches!(
        Responder::accept(rig.ep(Role::Responder), &hello),
        Err(TransportError::Authentication)
    ));
    // Tampered responder hello: a flipped tag, a flipped session id, a flipped cursor.
    for (at, name) in [(HELLO_LEN - 1, "tag"), (5, "session id"), (30, "cursor")] {
        let rig = big();
        let (ini, hello) = Initiator::start(rig.ep(Role::Initiator)).unwrap();
        let (_res, mut reply) = Responder::accept(rig.ep(Role::Responder), &hello).unwrap();
        reply[at] ^= 1;
        let e = ini.finish(&reply).map(|_| ()).unwrap_err();
        match (name, e) {
            ("tag", TransportError::Authentication)
            | ("session id", TransportError::WrongSession)
            | ("cursor", TransportError::OutOfStep { .. }) => {}
            (n, e) => panic!("{n}: {e}"),
        }
    }
    // A tampered finished message.
    let rig = big();
    let (ini, hello) = Initiator::start(rig.ep(Role::Initiator)).unwrap();
    let (res, reply) = Responder::accept(rig.ep(Role::Responder), &hello).unwrap();
    let (_si, mut fin) = ini.finish(&reply).unwrap();
    fin[FINISHED_BODY] ^= 1;
    assert!(matches!(
        res.finish(&fin),
        Err(TransportError::Authentication)
    ));
    // Wrong session id in the finished message.
    let rig = big();
    let (ini, hello) = Initiator::start(rig.ep(Role::Initiator)).unwrap();
    let (res, reply) = Responder::accept(rig.ep(Role::Responder), &hello).unwrap();
    let (_si, mut fin) = ini.finish(&reply).unwrap();
    fin[3] ^= 1;
    assert!(matches!(
        res.finish(&fin),
        Err(TransportError::WrongSession)
    ));
    // A recorded hello replayed against a responder whose pools have moved on.
    let rig = big();
    let (ini, hello) = Initiator::start(rig.ep(Role::Initiator)).unwrap();
    let (res, reply) = Responder::accept(rig.ep(Role::Responder), &hello).unwrap();
    let (_si, fin) = ini.finish(&reply).unwrap();
    res.finish(&fin).unwrap();
    assert!(matches!(
        Responder::accept(rig.ep(Role::Responder), &hello),
        Err(TransportError::OutOfStep { .. })
    ));
}

#[test]
fn out_of_step_pools_are_detected_before_anything_is_consumed() {
    let rig = big();
    let (_ini, hello) = Initiator::start(rig.ep(Role::Initiator)).unwrap();
    // The responder's copy of the encryption pool has drifted by 8 bytes.
    open(rig.dr.path(), IR_ENC).reserve(8).unwrap();
    let auth_before = open(rig.dr.path(), IR_AUTH).stats().unwrap().consumed;
    match Responder::accept(rig.ep(Role::Responder), &hello) {
        Err(TransportError::OutOfStep {
            what: "encryption pool",
            ours: 8,
            theirs: 0,
        }) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(
        open(rig.dr.path(), IR_AUTH).stats().unwrap().consumed,
        auth_before
    );
}

#[test]
fn only_the_information_theoretic_profile_and_suitable_pools_are_accepted() {
    let rig = big();
    let pools = |role: Role| {
        let (d, se, sa, re, ra) = match role {
            Role::Initiator => (&rig.di, IR_ENC, IR_AUTH, RI_ENC, RI_AUTH),
            Role::Responder => (&rig.dr, RI_ENC, RI_AUTH, IR_ENC, IR_AUTH),
        };
        (
            open(d.path(), se),
            open(d.path(), sa),
            open(d.path(), re),
            open(d.path(), ra),
        )
    };
    for p in [SecurityProfile::Standard, SecurityProfile::PostQuantum] {
        let (a, b, c, d) = pools(Role::Initiator);
        assert!(
            matches!(Endpoint::new(p, Role::Initiator, a, b, c, d), Err(TransportError::ProfileUnsupported(q)) if q == p)
        );
    }
    // Swapped purposes.
    let (se, sa, re, ra) = pools(Role::Initiator);
    assert!(matches!(
        Endpoint::new(IT, Role::Initiator, sa, se, re, ra),
        Err(TransportError::BadEndpoint(_))
    ));
    // The same pool twice.
    let (se, sa, _re, ra) = pools(Role::Initiator);
    let dup = open(rig.di.path(), IR_ENC);
    assert!(matches!(
        Endpoint::new(IT, Role::Initiator, se, sa, dup, ra),
        Err(TransportError::BadEndpoint(_))
    ));
    // Local randomness is not shared secret material.
    let d = tempfile::tempdir().unwrap();
    let local: Vec<Pool> = [IR_ENC, IR_AUTH, RI_ENC, RI_AUTH]
        .iter()
        .map(|&t| make(d.path(), t, 64, 64, Provenance::LocalSecret))
        .collect();
    let mut it = local.into_iter();
    let (a, b, c, e) = (
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
    );
    assert!(matches!(
        Endpoint::new(IT, Role::Initiator, a, b, c, e),
        Err(TransportError::BadEndpoint(_))
    ));
    // Roles are checked.
    assert!(matches!(
        Initiator::start(rig.ep(Role::Responder)),
        Err(TransportError::BadEndpoint(_))
    ));
    assert!(matches!(
        Responder::accept(rig.ep(Role::Initiator), &[0; HELLO_LEN]),
        Err(TransportError::BadEndpoint(_))
    ));
    // Garbage hello.
    assert!(matches!(
        Responder::accept(rig.ep(Role::Responder), b"nope"),
        Err(TransportError::Malformed)
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    fn random_conversations_roundtrip(msgs in proptest::collection::vec((any::<bool>(), proptest::collection::vec(any::<u8>(), 0..300)), 1..12)) {
        let rig = Rig::new(1 << 14, 1 << 11);
        let (mut a, mut b) = rig.connect();
        for (from_a, m) in msgs {
            let got = if from_a { b.open(&a.seal(&m).unwrap()).unwrap() } else { a.open(&b.seal(&m).unwrap()).unwrap() };
            prop_assert_eq!(got, Opened::Data(m));
        }
    }
}
