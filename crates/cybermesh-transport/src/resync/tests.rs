#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::session::tests::{IR_AUTH, IR_ENC, RI_AUTH, RI_ENC, Rig, big, open};
use crate::{Initiator, Opened, Responder, Role, Session};
use proptest::prelude::*;

const POLICY: u64 = 1 << 20;

fn connect_fresh(rig: &Rig) -> Result<(Session, Session), TransportError> {
    let (ini, hello) = Initiator::start(rig.ep(Role::Initiator))?;
    let (res, reply) = Responder::accept(rig.ep(Role::Responder), &hello)?;
    let (a, fin) = ini.finish(&reply)?;
    Ok((a, res.finish(&fin)?))
}

/// `a` asks, `b` answers, `a` applies the answer.
fn ask(a: &Endpoint, b: &Endpoint) -> ResyncReport {
    let mut rq = a.sync_request().unwrap();
    let resp = b.sync_response(&rq.to_bytes()).unwrap();
    a.resync(&resp, &mut rq, POLICY).unwrap()
}

/// Each party asks the other in turn. Right when neither party has been restored from a backup
/// (a lost record, a crash).
fn exchange(a: &Endpoint, b: &Endpoint) -> (ResyncReport, ResyncReport) {
    let first = ask(a, b);
    let second = ask(b, a);
    (first, second)
}

fn all_cursors(rig: &Rig) -> (Cursors, Cursors) {
    (
        rig.ep(Role::Initiator).cursors().unwrap(),
        rig.ep(Role::Responder).cursors().unwrap(),
    )
}

/// Initiator and responder cursors describe the same four pools when the pair is in step.
fn in_step(i: Cursors, r: Cursors) -> bool {
    i.send_enc == r.recv_enc
        && i.send_auth == r.recv_auth
        && i.recv_enc == r.send_enc
        && i.recv_auth == r.send_auth
}

/// A response with the right shape that echoes `nonce` (which is public) and whatever tag the forger
/// chose.
fn forged(role: Role, nonce: &[u8; NONCE_LEN], cursors: [u64; 4], tag: [u8; 16]) -> Vec<u8> {
    let mut m = vec![b'S', 3, role as u8];
    m.extend_from_slice(nonce);
    for c in cursors {
        m.extend_from_slice(&c.to_be_bytes());
    }
    m.extend_from_slice(&tag);
    m
}

#[test]
fn a_lost_record_is_healed_by_burning_the_receiver_forward() {
    let rig = big();
    let (mut a, mut b) = connect_fresh(&rig).unwrap();
    let r0 = a.seal(b"delivered").unwrap();
    let _lost1 = a.seal(b"lost one").unwrap();
    let r2 = a.seal(b"after the gap").unwrap();
    assert_eq!(b.open(&r0).unwrap(), Opened::Data(b"delivered".to_vec()));
    assert!(matches!(
        b.open(&r2),
        Err(TransportError::Order {
            expected: 1,
            got: 2
        })
    ));
    drop((a, b));
    let (ci, cr) = all_cursors(&rig);
    assert!(!in_step(ci, cr));
    assert!(matches!(
        Responder::accept(
            rig.ep(Role::Responder),
            &Initiator::start(rig.ep(Role::Initiator)).unwrap().1
        ),
        Err(TransportError::OutOfStep { .. })
    ));
    // Resync: the leader burns nothing in its send pool, the lagging receiver burns what it never read.
    let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
    let (before_i, before_r) = (ei.cursors().unwrap(), er.cursors().unwrap());
    let (ri, rr) = exchange(&ei, &er);
    let (after_i, after_r) = (ei.cursors().unwrap(), er.cursors().unwrap());
    assert!(in_step(after_i, after_r));
    for (b, a) in [(before_i, after_i), (before_r, after_r)] {
        assert!(a.send_enc >= b.send_enc && a.send_auth >= b.send_auth);
        assert!(a.recv_enc >= b.recv_enc && a.recv_auth >= b.recv_auth);
    }
    assert_eq!(rr.burned[2], before_i.send_enc - before_r.recv_enc);
    assert_eq!(
        ri.burned[0], 0,
        "the sender is the leader and burns nothing"
    );
    drop((ei, er));
    let (mut a, mut b) = connect_fresh(&rig).unwrap();
    assert_eq!(
        b.open(&a.seal(b"healed").unwrap()).unwrap(),
        Opened::Data(b"healed".to_vec())
    );
    assert_eq!(
        a.open(&b.seal(b"both ways").unwrap()).unwrap(),
        Opened::Data(b"both ways".to_vec())
    );
}

#[test]
fn losses_in_both_directions_and_a_crash_with_records_in_flight() {
    let rig = big();
    let (mut a, mut b) = connect_fresh(&rig).unwrap();
    let _ = a.seal(b"a to b, never delivered").unwrap();
    let _ = a.seal(b"a to b again").unwrap();
    let _ = b.seal(b"b to a, never delivered").unwrap();
    drop((a, b));
    let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
    assert!(!in_step(ei.cursors().unwrap(), er.cursors().unwrap()));
    exchange(&ei, &er);
    assert!(in_step(ei.cursors().unwrap(), er.cursors().unwrap()));
    drop((ei, er));
    let (mut a, mut b) = connect_fresh(&rig).unwrap();
    assert_eq!(
        a.open(&b.seal(b"recovered").unwrap()).unwrap(),
        Opened::Data(b"recovered".to_vec())
    );
}

#[test]
fn resync_of_an_endpoint_taken_back_from_a_dead_session() {
    let rig = big();
    let (mut a, mut b) = connect_fresh(&rig).unwrap();
    let r = a.seal(b"x").unwrap();
    let mut bad = r.clone();
    bad[32] ^= 1;
    assert!(b.open(&bad).is_err());
    let (ea, eb) = (a.into_endpoint(), b.into_endpoint());
    exchange(&ea, &eb);
    assert!(in_step(ea.cursors().unwrap(), eb.cursors().unwrap()));
}

#[test]
fn an_exchange_in_step_burns_nothing_and_spends_32_authentication_bytes_each_way() {
    let rig = big();
    let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
    for round in 1..=3u64 {
        let (x, y) = exchange(&ei, &er);
        assert!(x.was_in_step() && y.was_in_step(), "round {round}");
        assert_eq!(ei.cursors().unwrap().send_auth, 32 * round);
        assert_eq!(
            er.cursors().unwrap().recv_auth,
            32 * round,
            "the receiver spent the same 32"
        );
        assert!(in_step(ei.cursors().unwrap(), er.cursors().unwrap()));
    }
}

#[test]
fn a_response_is_accepted_once_and_only_for_the_request_it_answers() {
    let rig = big();
    let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
    let mut rq1 = ei.sync_request().unwrap();
    let m1 = er.sync_response(&rq1.to_bytes()).unwrap();
    ei.resync(&m1, &mut rq1, POLICY).unwrap();
    let after = (ei.cursors().unwrap(), er.cursors().unwrap());
    // The same request cannot be used again, even for the genuine response it just applied.
    assert!(matches!(
        ei.resync(&m1, &mut rq1, POLICY),
        Err(TransportError::SyncNotRequested)
    ));
    // Replay of the genuine, already-applied response against a new request: a different nonce.
    let mut rq2 = ei.sync_request().unwrap();
    assert!(matches!(
        ei.resync(&m1, &mut rq2, POLICY),
        Err(TransportError::SyncNotRequested)
    ));
    // The response made for another request is refused the same way, however genuine it is.
    let other = er.sync_response(&rq2.to_bytes()).unwrap();
    let mut rq3 = ei.sync_request().unwrap();
    assert!(matches!(
        ei.resync(&other, &mut rq3, POLICY),
        Err(TransportError::SyncNotRequested)
    ));
    assert_eq!(
        (ei.cursors().unwrap(), er.cursors().unwrap()),
        (after.0, er.cursors().unwrap()),
        "the initiator changed nothing"
    );
    // The right request still takes the right response after all those refusals.
    ei.resync(&other, &mut rq2, POLICY).unwrap();
    // Nonces are fresh.
    assert_ne!(rq1.to_bytes(), rq2.to_bytes());
    assert_ne!(rq2.to_bytes(), rq3.to_bytes());
}

#[test]
fn a_replayed_response_names_spent_material_and_is_stale() {
    // With a request carrying the same nonce (built by hand, which a real caller cannot do), the
    // material check is still there: a response that was already applied names spent bytes.
    let rig = big();
    let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
    let mut rq = ei.sync_request().unwrap();
    let m1 = er.sync_response(&rq.to_bytes()).unwrap();
    let mut same = SyncRequest {
        nonce: rq.nonce,
        role: rq.role,
        used: false,
    };
    ei.resync(&m1, &mut rq, POLICY).unwrap();
    let now = (ei.cursors().unwrap(), er.cursors().unwrap());
    assert!(matches!(
        ei.resync(&m1, &mut same, POLICY),
        Err(TransportError::SyncStale)
    ));
    assert_eq!((ei.cursors().unwrap(), er.cursors().unwrap()), now);
}

#[test]
fn forged_and_tampered_messages_burn_nothing() {
    let rig = big();
    let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
    let before = (ei.cursors().unwrap(), er.cursors().unwrap());
    let mine = er.cursors().unwrap();
    // The responder asks; the request (and so the nonce) is public.
    let mut rq = er.sync_request().unwrap();
    let nonce = rq.nonce;
    // A forger with the right shape and a guessed tag, at the right offset and far ahead.
    for ahead in [0u64, 8, 64, 1000] {
        let target = mine.recv_auth + 32 + ahead;
        let m = forged(
            Role::Initiator,
            &nonce,
            [mine.recv_enc + ahead, target, mine.send_enc, mine.send_auth],
            [7; 16],
        );
        assert!(
            matches!(
                er.resync(&m, &mut rq, POLICY),
                Err(TransportError::SyncAuthentication)
            ),
            "ahead {ahead}"
        );
    }
    // A genuine response with any one byte of the body flipped is no longer authentic, even when
    // the flipped cursor would be a plausible, in-policy burn.
    let genuine = ei.sync_response(&rq.to_bytes()).unwrap();
    for i in 3..BODY_LEN {
        let mut m = genuine.clone();
        m[i] ^= 1;
        assert!(er.resync(&m, &mut rq, POLICY).is_err(), "byte {i}");
    }
    let mut m = genuine.clone();
    m[SYNC_LEN - 1] ^= 1;
    assert!(matches!(
        er.resync(&m, &mut rq, POLICY),
        Err(TransportError::SyncAuthentication)
    ));
    // Reflecting a response back to its sender, with or without relabelling its role.
    let mut rq_i = ei.sync_request().unwrap();
    assert!(matches!(
        ei.resync(&genuine, &mut rq_i, POLICY),
        Err(TransportError::BadSync)
    ));
    let mut relabelled = genuine.clone();
    relabelled[2] = Role::Responder as u8;
    assert!(ei.resync(&relabelled, &mut rq_i, POLICY).is_err());
    assert!(
        er.resync(&relabelled, &mut rq, POLICY).is_err(),
        "wrong role for the claimed sender"
    );
    // Material that differs from the sender's does not authenticate: flip one byte of the
    // receiver's copy at the exact offset the message spent, then put it back.
    let second = ei.sync_response(&rq.to_bytes()).unwrap();
    let path = rig.dr.path().join(format!("{}.pool", hex_id(IR_AUTH)));
    let at = 26 + spent_offset(&second) as usize;
    let mut raw = std::fs::read(&path).unwrap();
    for byte in [at, at + 16, at + 31] {
        raw[byte] ^= 0x01;
        std::fs::write(&path, &raw).unwrap();
        assert!(
            matches!(
                er.resync(&second, &mut rq, POLICY),
                Err(TransportError::SyncAuthentication)
            ),
            "material byte {}",
            byte - at
        );
        raw[byte] ^= 0x01;
    }
    std::fs::write(&path, &raw).unwrap();
    // Far beyond the provisioned material.
    let m = forged(Role::Initiator, &nonce, [0, u64::MAX / 2, 0, 0], [0; 16]);
    assert!(matches!(
        er.resync(&m, &mut rq, POLICY),
        Err(TransportError::ResyncExceedsPool { .. })
    ));
    // None of that changed anything on the receiver (answering spent bytes of the initiator's pool).
    let after = (ei.cursors().unwrap(), er.cursors().unwrap());
    assert_eq!(after.1, before.1, "the receiver burned nothing");
    assert_eq!(after.0.send_enc, before.0.send_enc);
    // And a long stream of forgeries cannot drain the pools.
    for i in 0..300u64 {
        let m = forged(
            Role::Initiator,
            &nonce,
            [i, mine.recv_auth + 32 + (i % 500), 0, 0],
            [i as u8; 16],
        );
        assert!(er.resync(&m, &mut rq, POLICY).is_err());
    }
    assert_eq!(er.cursors().unwrap(), before.1);
    // The genuine response still works afterwards: the request survived every refusal.
    er.resync(&genuine, &mut rq, POLICY).unwrap();
}

#[test]
fn a_forged_request_costs_the_responder_32_authentication_bytes() {
    // Pinned as a known cost, not a defence: anyone who can reach the responder can make it spend
    // authentication material and leave the pair out of step until the next resync.
    let rig = big();
    let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
    let mut request = vec![b'Q', 3, Role::Initiator as u8];
    request.extend_from_slice(&[9u8; NONCE_LEN]);
    let before = er.cursors().unwrap();
    er.sync_response(&request).unwrap();
    assert_eq!(er.cursors().unwrap().send_auth, before.send_auth + 32);
    assert!(!in_step(ei.cursors().unwrap(), er.cursors().unwrap()));
    // Healing is the ordinary exchange.
    exchange(&ei, &er);
    assert!(in_step(ei.cursors().unwrap(), er.cursors().unwrap()));
    // Malformed requests are refused and spend nothing.
    let c = er.cursors().unwrap();
    for bad in [
        vec![],
        request[..REQUEST_LEN - 1].to_vec(),
        [request.clone(), vec![0]].concat(),
        {
            let mut v = request.clone();
            v[0] = b'S';
            v
        },
        {
            let mut v = request.clone();
            v[1] = 2;
            v
        },
        {
            let mut v = request.clone();
            v[2] = 7;
            v
        },
        {
            let mut v = request.clone();
            v[2] = Role::Responder as u8;
            v
        },
    ] {
        assert!(matches!(
            er.sync_response(&bad),
            Err(TransportError::BadSync)
        ));
    }
    assert_eq!(er.cursors().unwrap(), c);
}

#[test]
fn a_genuine_message_further_ahead_than_the_policy_is_refused_until_it_is_raised() {
    let rig = big();
    let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
    // The initiator's authentication pool runs 1,024 bytes ahead of the responder's copy.
    open(rig.di.path(), IR_AUTH).reserve(1024).unwrap();
    let mut rq = er.sync_request().unwrap();
    let m = ei.sync_response(&rq.to_bytes()).unwrap();
    let before = er.cursors().unwrap();
    assert!(matches!(
        er.resync(&m, &mut rq, 64),
        Err(TransportError::ResyncExceedsPolicy {
            gap: 1024,
            max: 64,
            ..
        })
    ));
    assert_eq!(er.cursors().unwrap(), before, "refused without burning");
    let r = er.resync(&m, &mut rq, 2048).unwrap();
    assert_eq!(
        r.burned[3], 1024,
        "the skipped bytes, not the message's own 32"
    );
}

#[test]
fn malformed_sync_messages_are_refused() {
    let rig = big();
    let e = rig.ep(Role::Responder);
    let mut rq = e.sync_request().unwrap();
    let good = rig
        .ep(Role::Initiator)
        .sync_response(&rq.to_bytes())
        .unwrap();
    assert_eq!(good.len(), SYNC_LEN);
    for bad in [
        vec![],
        good[..SYNC_LEN - 1].to_vec(),
        [good.clone(), vec![0]].concat(),
        {
            let mut v = good.clone();
            v[0] = b'X';
            v
        },
        {
            let mut v = good.clone();
            v[1] = 2;
            v
        },
        {
            let mut v = good.clone();
            v[2] = 7;
            v
        },
    ] {
        assert!(matches!(
            e.resync(&bad, &mut rq, POLICY),
            Err(TransportError::BadSync)
        ));
    }
    // A reported send-authentication cursor too small to hold the tag's 32 bytes.
    let m = forged(Role::Initiator, &rq.nonce, [0, 10, 0, 0], [0; 16]);
    assert!(matches!(
        e.resync(&m, &mut rq, POLICY),
        Err(TransportError::BadSync)
    ));
    // A request made by the other role is not this role's request, even with the right nonce.
    let mut other = SyncRequest {
        nonce: rq.nonce,
        role: Role::Initiator as u8,
        used: false,
    };
    assert!(matches!(
        e.resync(&good, &mut other, POLICY),
        Err(TransportError::SyncNotRequested)
    ));
}

#[test]
fn burned_bytes_are_erased_on_disk_and_never_issued() {
    let rig = big();
    let (mut a, _b) = connect_fresh(&rig).unwrap();
    for _ in 0..3 {
        let _ = a.seal(&[5u8; 100]).unwrap();
    }
    drop(a);
    let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
    let from = er.cursors().unwrap().recv_enc;
    let to = ei.cursors().unwrap().send_enc;
    exchange(&ei, &er);
    let pool = open(rig.dr.path(), IR_ENC);
    assert_eq!(pool.stats().unwrap().consumed, to);
    let path = rig.dr.path().join(format!("{}.pool", hex_id(IR_ENC)));
    let raw = std::fs::read(path).unwrap();
    let base = 26usize;
    assert!(
        raw[base + from as usize..base + to as usize]
            .iter()
            .all(|&b| b == 0)
    );
    let _ = (RI_ENC, RI_AUTH);
}

fn hex_id(tag: u8) -> String {
    format!("{tag:02x}").repeat(16)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]
    #[test]
    fn any_loss_pattern_can_be_resynchronised(sent_a in 1usize..6, sent_b in 0usize..5, delivered_a in 0usize..6, lens in proptest::collection::vec(0usize..200, 12)) {
        let rig = big();
        let (mut a, mut b) = connect_fresh(&rig).unwrap();
        let recs: Vec<Vec<u8>> = (0..sent_a).map(|i| a.seal(&vec![1u8; lens[i]]).unwrap()).collect();
        for r in recs.iter().take(delivered_a.min(sent_a)) { b.open(r).unwrap(); }
        for i in 0..sent_b { let _ = b.seal(&vec![2u8; lens[6 + i]]).unwrap(); }
        drop((a, b));
        let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
        exchange(&ei, &er);
        prop_assert!(in_step(ei.cursors().unwrap(), er.cursors().unwrap()));
        drop((ei, er));
        let (mut a, mut b) = connect_fresh(&rig).unwrap();
        prop_assert_eq!(b.open(&a.seal(b"ping").unwrap()).unwrap(), Opened::Data(b"ping".to_vec()));
        prop_assert_eq!(a.open(&b.seal(b"pong").unwrap()).unwrap(), Opened::Data(b"pong".to_vec()));
    }
}

// ---- restoring a backup of the pools ----------------------------------------------------------
//
// A complete copy of a pool directory taken earlier brings back both the cursor and the unerased
// material. These tests pin down exactly what the transport does and does not defend against.

fn snapshot(dir: &std::path::Path) -> tempfile::TempDir {
    let snap = tempfile::tempdir().unwrap();
    copy_files(dir, snap.path());
    snap
}

fn copy_files(from: &std::path::Path, to: &std::path::Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}

/// The ciphertext part of a record (after the 30-byte header, before the 16-byte tag).
fn ciphertext(rec: &[u8]) -> &[u8] {
    &rec[30..rec.len() - 16]
}

/// The offset in a pool of the 32 bytes a sync message spent: its reported cursor minus 32.
fn spent_offset(msg: &[u8]) -> u64 {
    u64::from_be_bytes(msg[CURSORS_AT + 8..CURSORS_AT + 16].try_into().unwrap()) - 32
}

#[test]
fn a_restored_pool_hands_out_pad_bytes_that_were_already_used() {
    let rig = big();
    let snap = snapshot(rig.di.path());
    let (mut a, mut b) = connect_fresh(&rig).unwrap();
    let rec = a.seal(b"first message").unwrap();
    b.open(&rec).unwrap();
    drop((a, b));
    copy_files(snap.path(), rig.di.path());
    let again = open(rig.di.path(), IR_ENC).reserve(18).unwrap();
    let before = &crate::session::tests::fixture(IR_ENC, 1 << 18)[..18];
    assert_eq!(again.as_bytes(), before, "the consumed pad is back");
}

#[test]
fn restoring_one_party_is_healed_when_the_restored_side_asks_first() {
    let rig = big();
    let snap = snapshot(rig.di.path());
    // A first session, driven by hand so its hello can be compared later.
    let (ini, hello1) = Initiator::start(rig.ep(Role::Initiator)).unwrap();
    let (res, reply) = Responder::accept(rig.ep(Role::Responder), &hello1).unwrap();
    let (mut a, fin) = ini.finish(&reply).unwrap();
    let mut b = res.finish(&fin).unwrap();
    let first = a.seal(b"message sent before the restore").unwrap();
    b.open(&first).unwrap();
    drop((a, b));
    let ahead = rig.ep(Role::Responder).cursors().unwrap();

    // The initiator's directory is restored from the earlier backup.
    copy_files(snap.path(), rig.di.path());
    assert_eq!(
        rig.ep(Role::Initiator).cursors().unwrap().send_enc,
        0,
        "rolled back"
    );

    // The restored side does not know it was restored, and tries a new handshake. The hello is
    // refused; but its tag is made from the **same authentication key and pad** as the first
    // hello (the same offset): the restore has already reused authentication material.
    let (_i, hello2) = Initiator::start(rig.ep(Role::Initiator)).unwrap();
    assert_eq!(
        hello1[20..28],
        hello2[20..28],
        "same authentication offset: material reused"
    );
    assert!(matches!(
        Responder::accept(rig.ep(Role::Responder), &hello2),
        Err(TransportError::OutOfStep { .. })
    ));

    // The restored side asks first; the responder's pools are ahead, so its answer uses fresh
    // material.
    let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
    let report = ask(&ei, &er);
    assert!(!report.was_in_step());
    // Now the restored side is burned past everything the peer has used, in both pool kinds...
    let healed = ei.cursors().unwrap();
    assert!(
        healed.send_enc >= ahead.recv_enc,
        "no encryption byte below the peer's cursor is offered again"
    );
    assert!(
        healed.send_auth >= ahead.recv_auth,
        "nor any authentication byte"
    );
    // ...so its own message is made from fresh material and the peer accepts it.
    let mut rq = er.sync_request().unwrap();
    let from_restored = ei.sync_response(&rq.to_bytes()).unwrap();
    assert!(spent_offset(&from_restored) >= ahead.recv_auth);
    er.resync(&from_restored, &mut rq, POLICY).unwrap();
    assert!(in_step(ei.cursors().unwrap(), er.cursors().unwrap()));
    drop((ei, er));
    let (mut a, mut b) = connect_fresh(&rig).unwrap();
    let second = a.seal(b"message sent after the restore").unwrap();
    assert_eq!(
        b.open(&second).unwrap(),
        Opened::Data(b"message sent after the restore".to_vec())
    );
}

#[test]
fn a_restored_side_that_speaks_first_is_refused_as_stale_and_reuses_authentication_material() {
    let rig = big();
    let snap = snapshot(rig.di.path());
    let (mut a, mut b) = connect_fresh(&rig).unwrap();
    let first = a.seal(b"before").unwrap();
    b.open(&first).unwrap();
    drop((a, b));
    copy_files(snap.path(), rig.di.path());
    let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
    let before = er.cursors().unwrap();
    // The naive order: the restored initiator answers the peer's request before asking. It spends
    // authentication bytes at a cursor the peer has long passed: bytes it already used before the
    // restore.
    let mut rq = er.sync_request().unwrap();
    let stale = ei.sync_response(&rq.to_bytes()).unwrap();
    assert!(
        spent_offset(&stale) < before.recv_auth,
        "material the peer has already spent"
    );
    assert!(matches!(
        er.resync(&stale, &mut rq, POLICY),
        Err(TransportError::SyncStale)
    ));
    assert_eq!(er.cursors().unwrap(), before, "refused without any change");
    // The way out is still to ask first.
    ask(&ei, &er);
    ask(&er, &ei);
    assert!(in_step(ei.cursors().unwrap(), er.cursors().unwrap()));
}

// Found by the TLA+ model (`formal/tla`): before the nonce, a restored side accepted a genuine but
// old response from its peer, which burned nothing past what it had already used. The nonce closes
// that: an old response answers an old request and is not accepted after a restart.
#[test]
fn a_stale_genuine_response_is_refused_by_a_restored_side_which_then_heals_properly() {
    let rig = big();
    let snap = snapshot(rig.di.path());
    // The initiator asks and the responder answers while the pair is fresh; the answer is kept.
    // (The request lives only in this block: the process that made it will be gone after the restore.)
    let stale = {
        let old_request = rig.ep(Role::Initiator).sync_request().unwrap();
        rig.ep(Role::Responder)
            .sync_response(&old_request.to_bytes())
            .unwrap()
    };
    // A later, fresh exchange brings the pair back in step, so a session can run.
    exchange(&rig.ep(Role::Initiator), &rig.ep(Role::Responder));
    let (mut a, mut b) = connect_fresh(&rig).unwrap();
    b.open(&a.seal(b"sent before the restore").unwrap())
        .unwrap();
    drop((a, b));
    let ahead = rig.ep(Role::Initiator).cursors().unwrap();
    assert!(ahead.send_enc > 0 && ahead.send_auth > 0);

    // The initiator is restored (a new process: the old request is gone) and asks again.
    copy_files(snap.path(), rig.di.path());
    let ei = rig.ep(Role::Initiator);
    let mut rq = ei.sync_request().unwrap();
    let rolled_back = ei.cursors().unwrap();
    // The genuine old response is refused, and nothing changed.
    assert!(matches!(
        ei.resync(&stale, &mut rq, POLICY),
        Err(TransportError::SyncNotRequested)
    ));
    assert_eq!(ei.cursors().unwrap(), rolled_back);
    // A response to this request burns the restored side past everything it had used.
    let fresh = rig
        .ep(Role::Responder)
        .sync_response(&rq.to_bytes())
        .unwrap();
    ei.resync(&fresh, &mut rq, POLICY).unwrap();
    let after = ei.cursors().unwrap();
    assert!(
        after.send_enc >= ahead.send_enc,
        "no encryption pad byte that was used is on offer"
    );
    assert!(
        after.send_auth >= ahead.send_auth,
        "nor any authentication byte"
    );
}

#[test]
fn restoring_both_parties_is_not_detected_and_reuses_the_pad() {
    // The unresolved case: both copies roll back to the same moment, so their cursors agree and
    // nothing local can tell. The same plaintext meets the same pad again.
    let rig = big();
    let (snap_i, snap_r) = (snapshot(rig.di.path()), snapshot(rig.dr.path()));
    let (mut a, mut b) = connect_fresh(&rig).unwrap();
    let rec1 = a.seal(b"identical plaintext!").unwrap();
    b.open(&rec1).unwrap();
    drop((a, b));
    copy_files(snap_i.path(), rig.di.path());
    copy_files(snap_r.path(), rig.dr.path());
    let (mut a, mut b) =
        connect_fresh(&rig).expect("the handshake succeeds: the pair looks in step");
    let rec2 = a.seal(b"identical plaintext!").unwrap();
    assert_eq!(
        b.open(&rec2).unwrap(),
        Opened::Data(b"identical plaintext!".to_vec())
    );
    assert_eq!(
        ciphertext(&rec1),
        ciphertext(&rec2),
        "same pad, same plaintext, same ciphertext"
    );
    // With two different plaintexts under that reused pad, the XOR of the ciphertexts would be the
    // XOR of the plaintexts: the one-time pad is void. This is what a backup restore costs.
    let _ = (RI_ENC, RI_AUTH);
}
