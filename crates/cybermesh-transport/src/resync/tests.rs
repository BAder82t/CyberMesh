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

fn exchange(a: &Endpoint, b: &Endpoint) -> (ResyncReport, ResyncReport) {
    let (ma, mb) = (a.sync_message().unwrap(), b.sync_message().unwrap());
    (
        a.resync(&mb, POLICY).unwrap(),
        b.resync(&ma, POLICY).unwrap(),
    )
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
    // Out of step, and a new handshake says so before consuming anything.
    let (ci, cr) = all_cursors(&rig);
    assert!(!in_step(ci, cr));
    assert!(matches!(
        Responder::accept(
            rig.ep(Role::Responder),
            &Initiator::start(rig.ep(Role::Initiator)).unwrap().1
        ),
        Err(TransportError::OutOfStep { .. })
    ));
    // Resync: the leader burns nothing, the lagging receiver burns what it never read.
    let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
    let (before_i, before_r) = (ei.cursors().unwrap(), er.cursors().unwrap());
    let (ri, rr) = exchange(&ei, &er);
    assert!(ri.was_in_step() || ri.burned.iter().sum::<u64>() > 0);
    let (after_i, after_r) = (ei.cursors().unwrap(), er.cursors().unwrap());
    assert!(in_step(after_i, after_r));
    // Cursors never moved backwards.
    for (b, a) in [(before_i, after_i), (before_r, after_r)] {
        assert!(a.send_enc >= b.send_enc && a.send_auth >= b.send_auth);
        assert!(a.recv_enc >= b.recv_enc && a.recv_auth >= b.recv_auth);
    }
    // The responder burned exactly what the sender spent that it never read.
    assert_eq!(rr.burned[2], before_i.send_enc - before_r.recv_enc);
    assert_eq!(
        ri.burned[0], 0,
        "the sender is the leader and burns nothing"
    );
    drop((ei, er));
    // A fresh handshake and traffic work again, both ways.
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
    // Both processes "crash": only the pools survive.
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
    bad[REC_HEADER_FOR_TEST] ^= 1;
    assert!(b.open(&bad).is_err());
    // b is terminated; its pools come back and still resync.
    let (ea, eb) = (a.into_endpoint(), b.into_endpoint());
    exchange(&ea, &eb);
    assert!(in_step(ea.cursors().unwrap(), eb.cursors().unwrap()));
}
const REC_HEADER_FOR_TEST: usize = 30 + 2;

#[test]
fn resync_is_idempotent_and_a_replayed_or_stale_message_changes_nothing() {
    let rig = big();
    let (mut a, _b) = connect_fresh(&rig).unwrap();
    let old = rig.ep(Role::Responder).sync_message().unwrap(); // the responder, before any traffic
    let _ = a.seal(b"lost").unwrap();
    let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
    exchange(&ei, &er);
    let settled = (ei.cursors().unwrap(), er.cursors().unwrap());
    // Again: nothing to do.
    let (x, y) = exchange(&ei, &er);
    assert!(x.was_in_step() && y.was_in_step());
    // A stale message from before the traffic moves nothing.
    assert!(ei.resync(&old, POLICY).unwrap().was_in_step());
    assert_eq!((ei.cursors().unwrap(), er.cursors().unwrap()), settled);
}

#[test]
fn a_lie_can_only_burn_material_within_policy_and_heals_on_the_next_exchange() {
    let rig = big();
    let ei = rig.ep(Role::Initiator);
    // A forged message as if from the responder, claiming to have received `recv_enc` bytes of
    // the initiator->responder encryption pool (its third cursor), which pairs with the
    // initiator's send pool.
    let lie_enc = |recv_enc: u64| {
        let mut m = vec![b'S', 1];
        for c in [0u64, 0, recv_enc, 0] {
            m.extend_from_slice(&c.to_be_bytes());
        }
        m
    };
    let before = ei.cursors().unwrap();
    // Beyond the pool: refused, nothing burned.
    assert!(matches!(
        ei.resync(&lie_enc(u64::MAX / 2), u64::MAX),
        Err(TransportError::ResyncExceedsPool { .. })
    ));
    // Over the caller's policy: refused, nothing burned.
    assert!(matches!(
        ei.resync(&lie_enc(4096), 1024),
        Err(TransportError::ResyncExceedsPolicy {
            gap: 4096,
            max: 1024,
            ..
        })
    ));
    // A gap no honest sequence of records can produce.
    assert!(matches!(
        ei.resync(&lie_enc(3), POLICY),
        Err(TransportError::Misaligned { gap: 3, .. })
    ));
    assert_eq!(ei.cursors().unwrap(), before, "refusals burn nothing");
    // Within policy the lie succeeds in burning 64 bytes of the initiator's send pool...
    let r = ei.resync(&lie_enc(64), POLICY).unwrap();
    assert_eq!(r.burned[0], 64);
    drop(ei);
    // ...and the honest responder then no longer matches, so the handshake refuses...
    assert!(matches!(
        Responder::accept(
            rig.ep(Role::Responder),
            &Initiator::start(rig.ep(Role::Initiator)).unwrap().1
        ),
        Err(TransportError::OutOfStep { .. })
    ));
    // ...until an honest exchange brings both to the larger cursor. Cost: burned bytes only.
    let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
    exchange(&ei, &er);
    drop((ei, er));
    let (mut a, mut b) = connect_fresh(&rig).unwrap();
    assert_eq!(
        b.open(&a.seal(b"still works").unwrap()).unwrap(),
        Opened::Data(b"still works".to_vec())
    );
}

#[test]
fn malformed_sync_messages_are_refused() {
    let rig = big();
    let e = rig.ep(Role::Initiator);
    let good = e.sync_message().unwrap();
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
            v[1] = 9;
            v
        },
    ] {
        assert!(matches!(
            e.resync(&bad, POLICY),
            Err(TransportError::BadSync)
        ));
    }
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
    // The receiver's copy of the initiator->responder encryption pool is zero over what it burned,
    // and its cursor sits at the sender's.
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
    let _ = (RI_ENC, IR_AUTH, RI_AUTH);
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

#[test]
fn a_restored_pool_hands_out_pad_bytes_that_were_already_used() {
    // The risk, shown directly: after a full restore the pool offers the same bytes again.
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
fn restoring_one_party_is_detected_by_the_live_peer_and_healed_without_reuse() {
    let rig = big();
    let snap = snapshot(rig.di.path());
    let (mut a, mut b) = connect_fresh(&rig).unwrap();
    let first = a.seal(b"message sent before the restore").unwrap();
    b.open(&first).unwrap();
    drop((a, b));
    let high_water = rig.ep(Role::Responder).cursors().unwrap().recv_enc;
    assert!(high_water > 0);

    // The initiator's directory is restored from the earlier backup.
    copy_files(snap.path(), rig.di.path());
    assert_eq!(
        rig.ep(Role::Initiator).cursors().unwrap().send_enc,
        0,
        "rolled back"
    );

    // 1. The responder refuses the handshake: its copy of the pool is ahead.
    let (_i, hello) = Initiator::start(rig.ep(Role::Initiator)).unwrap();
    assert!(matches!(
        Responder::accept(rig.ep(Role::Responder), &hello),
        Err(TransportError::OutOfStep { .. })
    ));
    // 2. Resync burns the restored side forward to the peer's cursor, erasing the material.
    let (ei, er) = (rig.ep(Role::Initiator), rig.ep(Role::Responder));
    exchange(&ei, &er);
    assert!(
        ei.cursors().unwrap().send_enc >= high_water,
        "no byte below the peer's cursor is offered again"
    );
    drop((ei, er));
    // 3. New traffic uses pad bytes beyond everything used before.
    let (mut a, mut b) = connect_fresh(&rig).unwrap();
    let second = a.seal(b"message sent after the restore").unwrap();
    assert_eq!(
        b.open(&second).unwrap(),
        Opened::Data(b"message sent after the restore".to_vec())
    );
    let fresh_start = rig.ep(Role::Responder).cursors().unwrap().recv_enc;
    assert!(fresh_start > high_water);
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
}
