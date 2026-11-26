#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

const ID: PoolId = PoolId([9; 16]);

/// Non-zero, position-dependent material so every region is distinguishable and non-erased.
/// Test fixture only; NOT secret randomness.
fn material(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8 + 1).collect()
}

fn new_pool(dir: &Path, n: usize) -> Pool {
    Pool::create(
        dir,
        ID,
        Purpose::Encryption,
        Provenance::ProvisionedShared,
        &material(n),
    )
    .unwrap()
}

#[test]
fn bytes_are_issued_once_in_order_and_accounted() {
    let d = tempfile::tempdir().unwrap();
    let pool = new_pool(d.path(), 100);
    assert_eq!(
        pool.stats().unwrap(),
        Stats {
            capacity: 100,
            consumed: 0,
            remaining: 100
        }
    );
    let a = pool.reserve(16).unwrap();
    let b = pool.reserve(24).unwrap();
    assert_eq!((a.offset(), a.len(), b.offset(), b.len()), (0, 16, 16, 24));
    assert_eq!(a.as_bytes(), &material(100)[..16]);
    assert_eq!(b.as_bytes(), &material(100)[16..40]);
    assert_eq!(a.purpose(), Purpose::Encryption);
    assert_eq!(a.pool(), ID);
    assert_eq!(pool.stats().unwrap().remaining, 60);
    // The spent region is erased on disk.
    let raw = std::fs::read(paths(d.path(), ID).0).unwrap();
    assert!(
        raw[HEADER_LEN as usize..HEADER_LEN as usize + 40]
            .iter()
            .all(|&x| x == 0)
    );
    assert_eq!(&raw[HEADER_LEN as usize + 40..], &material(100)[40..]);
}

#[test]
fn exhaustion_fails_without_spending() {
    let d = tempfile::tempdir().unwrap();
    let pool = new_pool(d.path(), 20);
    pool.reserve(16).unwrap();
    match pool.reserve(8) {
        Err(EntropyError::Exhausted {
            remaining: 4,
            requested: 8,
        }) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(
        pool.stats().unwrap().consumed,
        16,
        "failed request spent nothing"
    );
    assert!(pool.needs_replenishment(8).unwrap());
    // Replenish, then the same request works and continues from the cursor.
    pool.replenish(&[7u8; 40]).unwrap();
    assert!(!pool.needs_replenishment(8).unwrap());
    let r = pool.reserve(8).unwrap();
    assert_eq!(r.offset(), 16);
    assert_eq!(
        r.as_bytes(),
        &[
            material(20)[16],
            material(20)[17],
            material(20)[18],
            material(20)[19],
            7,
            7,
            7,
            7
        ]
    );
}

#[test]
fn length_bounds() {
    let d = tempfile::tempdir().unwrap();
    let pool = new_pool(d.path(), 64);
    for bad in [0, 1, MIN_RESERVATION - 1, MAX_RESERVATION + 1] {
        assert!(
            matches!(pool.reserve(bad), Err(EntropyError::InvalidLength)),
            "{bad}"
        );
    }
    assert!(matches!(
        pool.replenish(&[]),
        Err(EntropyError::InvalidLength)
    ));
}

#[test]
fn unsuitable_randomness_is_refused() {
    let d = tempfile::tempdir().unwrap();
    for p in [Provenance::Pseudorandom, Provenance::Public] {
        let e = Pool::create(d.path(), ID, Purpose::Encryption, p, &material(32)).unwrap_err();
        assert!(matches!(e, EntropyError::Unsuitable(q) if q == p));
        assert!(!p.is_secret() && !p.is_shared_secret());
    }
    assert!(!paths(d.path(), ID).0.exists(), "nothing was created");
    assert!(Provenance::LocalSecret.is_secret() && !Provenance::LocalSecret.is_shared_secret());
    assert!(Provenance::QuantumShared.is_shared_secret());
    assert!(
        Pool::create(
            d.path(),
            ID,
            Purpose::Local,
            Provenance::LocalSecret,
            &material(8)
        )
        .is_ok()
    );
}

#[test]
fn will_not_overwrite_and_validates_what_it_opens() {
    let d = tempfile::tempdir().unwrap();
    new_pool(d.path(), 32);
    assert!(matches!(
        Pool::create(
            d.path(),
            ID,
            Purpose::Encryption,
            Provenance::QuantumShared,
            &material(32)
        ),
        Err(EntropyError::Exists)
    ));
    assert!(matches!(
        Pool::create(
            d.path(),
            PoolId([1; 16]),
            Purpose::Local,
            Provenance::Public,
            &[1]
        ),
        Err(EntropyError::Unsuitable(_))
    ));
    assert!(matches!(
        Pool::create(
            d.path(),
            PoolId([2; 16]),
            Purpose::Local,
            Provenance::LocalSecret,
            &[]
        ),
        Err(EntropyError::InvalidLength)
    ));
    // A pool file moved under another id is rejected.
    let (pp, cp) = paths(d.path(), ID);
    let other = PoolId([5; 16]);
    let (op, oc) = paths(d.path(), other);
    std::fs::copy(&pp, &op).unwrap();
    std::fs::copy(&cp, &oc).unwrap();
    assert!(matches!(
        Pool::open(d.path(), other),
        Err(EntropyError::Corrupt(_))
    ));
    // Reopening the genuine one works and keeps its labels.
    let p = Pool::open(d.path(), ID).unwrap();
    assert_eq!(
        (p.purpose(), p.provenance()),
        (Purpose::Encryption, Provenance::ProvisionedShared)
    );
}

#[cfg(unix)]
#[test]
fn files_are_private_and_loose_permissions_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    new_pool(d.path(), 32);
    let (pp, _) = paths(d.path(), ID);
    assert_eq!(
        std::fs::metadata(&pp).unwrap().permissions().mode() & 0o777,
        0o600
    );
    std::fs::set_permissions(&pp, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Pool::open(d.path(), ID),
        Err(EntropyError::Permissions)
    ));
}

#[test]
fn a_crash_after_the_cursor_burns_material_and_never_reissues_it() {
    let d = tempfile::tempdir().unwrap();
    let pool = new_pool(d.path(), 64);
    pool.crash_after_cursor.store(true, Ordering::SeqCst);
    assert!(matches!(pool.reserve(16), Err(EntropyError::Injected)));
    drop(pool);
    // Restart: the 16 bytes are gone for good, and the next reservation starts after them.
    let pool = Pool::open(d.path(), ID).unwrap();
    assert_eq!(pool.stats().unwrap().consumed, 16);
    let r = pool.reserve(16).unwrap();
    assert_eq!(r.offset(), 16);
    assert_eq!(r.as_bytes(), &material(64)[16..32]);
}

#[test]
fn restoring_an_old_cursor_cannot_reissue_spent_bytes() {
    let d = tempfile::tempdir().unwrap();
    let pool = new_pool(d.path(), 64);
    let (_, cp) = paths(d.path(), ID);
    let old_cursor = std::fs::read(&cp).unwrap();
    let first = pool.reserve(16).unwrap();
    drop(pool);
    // Attacker (or a bad restore) puts the old cursor back.
    std::fs::write(&cp, &old_cursor).unwrap();
    let pool = Pool::open(d.path(), ID).unwrap();
    assert_eq!(pool.stats().unwrap().consumed, 0);
    // The region it points at is erased, so it fails closed instead of reusing bytes...
    assert!(matches!(pool.reserve(16), Err(EntropyError::Burned)));
    // ...and that region is spent now; later bytes are still fine and never repeat `first`.
    let next = pool.reserve(16).unwrap();
    assert_eq!(next.offset(), 16);
    assert_ne!(next.as_bytes(), first.as_bytes());
}

#[test]
fn a_torn_cursor_write_falls_back_to_the_other_slot_and_both_bad_fails_closed() {
    let d = tempfile::tempdir().unwrap();
    let pool = new_pool(d.path(), 64);
    pool.reserve(16).unwrap(); // seq 1 in slot 1, seq 0 in slot 0
    drop(pool);
    let (_, cp) = paths(d.path(), ID);
    let mut raw = std::fs::read(&cp).unwrap();
    // Tear the newest slot (slot 1).
    raw[SLOT_LEN + 3] ^= 0xff;
    std::fs::write(&cp, &raw).unwrap();
    let pool = Pool::open(d.path(), ID).unwrap();
    assert_eq!(pool.stats().unwrap().consumed, 0, "older slot");
    // Spent region is erased, so the fallback cannot reissue it.
    assert!(matches!(pool.reserve(16), Err(EntropyError::Burned)));
    drop(pool);
    // Damage both slots: refuse to open.
    let mut raw = std::fs::read(&cp).unwrap();
    raw[0] ^= 0xff;
    raw[SLOT_LEN] ^= 0xff;
    std::fs::write(&cp, &raw).unwrap();
    assert!(matches!(
        Pool::open(d.path(), ID),
        Err(EntropyError::Corrupt(_))
    ));
    // A truncated cursor file too.
    std::fs::write(&cp, &raw[..10]).unwrap();
    assert!(matches!(
        Pool::open(d.path(), ID),
        Err(EntropyError::Corrupt(_))
    ));
}

#[test]
fn a_cursor_beyond_the_pool_is_corrupt() {
    let d = tempfile::tempdir().unwrap();
    new_pool(d.path(), 16);
    let (_, cp) = paths(d.path(), ID);
    let mut raw = std::fs::read(&cp).unwrap();
    raw[..SLOT_LEN].copy_from_slice(&encode_slot(ID, 5, 1_000));
    std::fs::write(&cp, &raw).unwrap();
    assert!(matches!(
        Pool::open(d.path(), ID),
        Err(EntropyError::Corrupt(_))
    ));
}

#[test]
fn concurrent_threads_and_separate_handles_never_share_a_byte() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().to_path_buf();
    let total = 8 * 50 * 16;
    new_pool(&dir, total);
    // 8 threads, each with its OWN handle on the same files (as separate processes would have).
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let dir = dir.clone();
            std::thread::spawn(move || {
                let pool = Pool::open(&dir, ID).unwrap();
                (0..50)
                    .map(|_| {
                        let r = pool.reserve(16).unwrap();
                        (r.offset(), r.as_bytes().to_vec())
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut offsets = BTreeSet::new();
    let reference = material(total);
    for h in handles {
        for (off, bytes) in h.join().unwrap() {
            assert!(offsets.insert(off), "offset {off} issued twice");
            assert_eq!(bytes, &reference[off as usize..off as usize + 16]);
        }
    }
    assert_eq!(offsets.len(), 400);
    assert_eq!(
        offsets.iter().copied().collect::<Vec<_>>(),
        (0..400).map(|i| i * 16).collect::<Vec<_>>()
    );
    let pool = Pool::open(&dir, ID).unwrap();
    assert_eq!(pool.stats().unwrap().remaining, 0);
    assert!(matches!(
        pool.reserve(8),
        Err(EntropyError::Exhausted { .. })
    ));
}

#[test]
fn threads_sharing_one_handle_are_serialised() {
    let d = tempfile::tempdir().unwrap();
    let pool = std::sync::Arc::new(new_pool(d.path(), 4 * 40 * 8));
    let hs: Vec<_> = (0..4)
        .map(|_| {
            let p = pool.clone();
            std::thread::spawn(move || {
                (0..40)
                    .map(|_| p.reserve(8).unwrap().offset())
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let all: BTreeSet<u64> = hs.into_iter().flat_map(|h| h.join().unwrap()).collect();
    assert_eq!(all.len(), 160);
}

#[test]
fn reservations_are_redacted_and_into_secret_keeps_the_bytes() {
    let d = tempfile::tempdir().unwrap();
    let pool = new_pool(d.path(), 32);
    let r = pool.reserve(8).unwrap();
    let dbg = format!("{r:?}");
    assert!(dbg.contains("offset") && !dbg.contains("bytes"));
    assert!(!r.is_empty());
    let s = r.into_secret();
    assert_eq!(&s[..], &material(32)[..8]);
    assert!(!format!("{pool:?}").contains("material"));
}

#[test]
fn peeking_reads_unspent_bytes_without_consuming_them() {
    let d = tempfile::tempdir().unwrap();
    let pool = new_pool(d.path(), 128);
    let want = &material(128)[40..72];
    // Ahead of the cursor, twice: the same bytes, and nothing is spent.
    assert_eq!(&pool.peek_unspent(40, 32).unwrap()[..], want);
    assert_eq!(&pool.peek_unspent(40, 32).unwrap()[..], want);
    assert_eq!(pool.stats().unwrap().consumed, 0);
    // They are still unspent: a later reservation hands the same bytes out (the documented hazard
    // of peeking, which is why it is for verification only).
    pool.reserve(40).unwrap();
    let again = pool.reserve(32).unwrap();
    assert_eq!(again.as_bytes(), want);
}

#[test]
fn peeking_refuses_spent_out_of_range_and_erased_regions() {
    let d = tempfile::tempdir().unwrap();
    let pool = new_pool(d.path(), 64);
    pool.reserve(24).unwrap();
    // Below or straddling the cursor.
    assert!(matches!(
        pool.peek_unspent(0, 16),
        Err(EntropyError::AlreadySpent {
            offset: 0,
            cursor: 24
        })
    ));
    assert!(matches!(
        pool.peek_unspent(16, 16),
        Err(EntropyError::AlreadySpent { .. })
    ));
    assert!(
        pool.peek_unspent(24, 16).is_ok(),
        "exactly at the cursor is unspent"
    );
    // Beyond the material, including a wrapping offset.
    assert!(matches!(
        pool.peek_unspent(56, 16),
        Err(EntropyError::OutOfRange)
    ));
    assert!(matches!(
        pool.peek_unspent(u64::MAX - 4, 16),
        Err(EntropyError::OutOfRange)
    ));
    // Length bounds.
    for bad in [0, MIN_RESERVATION - 1, MAX_RESERVATION + 1] {
        assert!(
            matches!(pool.peek_unspent(24, bad), Err(EntropyError::InvalidLength)),
            "{bad}"
        );
    }
    // An erased region ahead of the cursor (an old cursor restored) is refused too.
    let (_, cp) = paths(d.path(), ID);
    let old = std::fs::read(&cp).unwrap();
    pool.reserve(16).unwrap();
    drop(pool);
    std::fs::write(&cp, &old).unwrap();
    let pool = Pool::open(d.path(), ID).unwrap();
    assert!(matches!(
        pool.peek_unspent(24, 16),
        Err(EntropyError::Burned)
    ));
}
