#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use cybermesh_analysis::{CtLogInfo, Engine, EvidenceBundle};
use cybermesh_ct::checkpoint::fetch_verified_checkpoint;
use cybermesh_ct::mock::{MockEntry, MockLog, demo_entries, serve};
use cybermesh_ct::names::certificate_names;
use cybermesh_ct::proof::TileAuthenticator;
use cybermesh_ct::tile::parse_data_tile;
use cybermesh_ct::{TileSource, scan_tile, scan_tiles};

fn engine() -> Engine {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../datasets/demo/evidence");
    Engine::new(EvidenceBundle::load(&dir).unwrap())
}

#[test]
fn scan_over_http_matches_log_commitments_and_finds_lookalikes() {
    let log = Arc::new(MockLog::build("ct.example/test", &demo_entries(3)).unwrap());
    let (url, _h) = serve(Arc::clone(&log), "127.0.0.1:0").unwrap();
    let info: CtLogInfo = log.log_info("mock", &url);
    let src = cybermesh_ct::http::HttpTileSource::new(&info, Duration::from_secs(10)).unwrap();
    // Over HTTP: the checkpoint is signed by the pinned key and every tile root is proven.
    let cp = fetch_verified_checkpoint(&src, &info).unwrap();
    let auth = TileAuthenticator::new(&src, cp.clone());
    assert_eq!(cp.size, 768);
    assert_eq!(cp.full_tiles(), 3);

    let e = engine();
    let (tiles, bytes) = scan_tiles(&src, 0, 3, &e).unwrap();
    assert!(bytes > 0);
    for t in &tiles {
        // Worker commitment equals the log's own level-1 hash for that tile.
        assert_eq!(t.root.0, auth.tile_root(t.tile_index).unwrap());
        assert_eq!(t.unparsed, 0);
    }
    let names: Vec<&str> = tiles
        .iter()
        .flat_map(|t| t.matches.iter().map(|m| m.name.as_str()))
        .collect();
    assert!(
        names.contains(&"examplebank-secure-login.example.net"),
        "{names:?}"
    );
    assert!(names.contains(&"paypa1-account-verify.com"));
    assert!(names.contains(&"xn--pypal-4ve.com"));
    assert!(
        !names
            .iter()
            .any(|n| n.ends_with("paypal.com") && !n.contains('-')),
        "legitimate brand domain flagged"
    );
    // Determinism: scanning again gives byte-identical results.
    let (again, _) = scan_tiles(log.as_ref(), 0, 3, &e).unwrap();
    assert_eq!(again, tiles);
}

#[test]
fn precertificate_and_certificate_names_are_extracted() {
    let entries: Vec<MockEntry> = (0..256)
        .map(|i| MockEntry {
            names: vec![
                format!("*.host{i}.example.com"),
                format!("Host{i}.Example.COM"),
            ],
            precert: i % 2 == 1,
        })
        .collect();
    let log = MockLog::build("o", &entries).unwrap();
    let parsed = parse_data_tile(&log.data_tile(0).unwrap(), 0).unwrap();
    for (i, e) in parsed.iter().enumerate() {
        let n = certificate_names(e).unwrap();
        assert_eq!(
            n,
            vec![format!("host{i}.example.com")],
            "wildcard and case folded, deduplicated"
        );
    }
}

#[test]
fn tampered_tile_bytes_change_the_commitment() {
    let mut log = MockLog::build("o", &demo_entries(1)).unwrap();
    let e = engine();
    let honest = scan_tile(&log.data_tile(0).unwrap(), 0, &e).unwrap();
    // Flip one byte inside the first certificate (keeps the framing valid).
    let mut bytes = log.data_tile(0).unwrap();
    bytes[40] ^= 0x01;
    log.replace_file("tile/data/000", bytes.clone());
    // Either the edit breaks parsing or it changes the commitment; never the honest result.
    if let Ok(t) = scan_tile(&bytes, 0, &e) {
        assert_ne!(t.root, honest.root);
    }
}

#[test]
fn caps_keep_the_highest_risk_matches_and_commit_every_name() {
    use cybermesh_protocol::ct::{MAX_MATCHES_PER_ENTRY, MAX_MATCHES_PER_TILE};
    // Entry 3 carries many brand-token decoys plus one strong typosquat; entries 10..30 each
    // carry one lookalike, so the tile exceeds the per-tile cap as well.
    let decoys: Vec<String> = (0..12)
        .map(|i| format!("paypal-cdn{i}.example-org.com"))
        .chain(["paypa1-secure-login-verify.example-shop.net".to_owned()])
        .collect();
    let entries: Vec<MockEntry> = (0..256)
        .map(|i| MockEntry {
            names: match i {
                3 => decoys.clone(),
                10..30 => vec![format!("examp1ebank-login{i}.example.net")],
                _ => vec![format!("host{i}.example-org.com")],
            },
            precert: false,
        })
        .collect();
    let log = MockLog::build("ct.example/caps", &entries).unwrap();
    let e = engine();
    let t = scan_tile(&log.data_tile(0).unwrap(), 0, &e).unwrap();
    assert!(t.truncated);
    assert_eq!(t.matches.len(), MAX_MATCHES_PER_TILE);
    assert!(t.matches.iter().filter(|m| m.index == 3).count() <= MAX_MATCHES_PER_ENTRY);
    // Sorted by (index, name) after priority selection.
    assert!(
        t.matches
            .windows(2)
            .all(|w| (w[0].index, &w[0].name) < (w[1].index, &w[1].name))
    );
    // Every kept match outranks every dropped candidate (risk first).
    let kept_min = t.matches.iter().map(|m| m.risk_score_bp).min().unwrap();
    let strong = e
        .assess("paypa1-secure-login-verify.example-shop.net")
        .unwrap();
    assert!(strong.risk_score_bp >= kept_min);
    assert!(
        t.matches
            .iter()
            .any(|m| m.name == "paypa1-secure-login-verify.example-shop.net"),
        "the decoys must not push the strongest name out"
    );
    // All names are counted and committed, not only the matches.
    assert_eq!(t.names, 256 - 1 + 13);
    let again = scan_tile(&log.data_tile(0).unwrap(), 0, &e).unwrap();
    assert_eq!(t, again, "deterministic");
    let mut other = entries.clone();
    other[200].names = vec!["host200-renamed.example-org.com".into()];
    let log2 = MockLog::build("ct.example/caps", &other).unwrap();
    let t2 = scan_tile(&log2.data_tile(0).unwrap(), 0, &e).unwrap();
    assert_eq!(t2.matches, t.matches);
    assert_ne!(
        t2.names_digest, t.names_digest,
        "a non-matching name change is visible"
    );
}

#[test]
fn checkpoints_and_tiles_that_the_log_did_not_sign_are_refused() {
    let mut log = MockLog::build("ct.example/test", &demo_entries(2)).unwrap();
    let info = log.log_info("mock", "http://127.0.0.1/");
    let cp = fetch_verified_checkpoint(&log, &info).unwrap();
    assert_eq!(cp.size, 512);
    // Another origin or key pinned: refused.
    let mut wrong = info.clone();
    wrong.origin = "ct.example/other".into();
    assert!(fetch_verified_checkpoint(&log, &wrong).is_err());
    // A CDN serving a different level-1 hash tile: the proof fails for that tile.
    let p = cybermesh_ct::tile::hash_tile_path(1, 0, Some(2));
    let mut tile = log.files[&p].clone();
    tile[0] ^= 1;
    log.replace_file(&p, tile);
    let auth = TileAuthenticator::new(&log, cp);
    assert!(matches!(
        auth.tile_root(0),
        Err(cybermesh_ct::CtError::Unauthenticated(_))
    ));
    // An edited checkpoint (larger tree claimed) is refused.
    let text = log.checkpoint().unwrap().replacen("512", "768", 1);
    log.replace_file("checkpoint", text.into_bytes());
    assert!(fetch_verified_checkpoint(&log, &info).is_err());
}

#[test]
fn a_growing_log_keeps_its_history_and_proves_it() {
    let mut log = MockLog::build("ct.example/grow", &demo_entries(2)).unwrap();
    let info = log.log_info("mock", "http://127.0.0.1/");
    let before = fetch_verified_checkpoint(&log, &info).unwrap();
    let tiles_before: Vec<Vec<u8>> = (0..2).map(|t| log.data_tile(t).unwrap()).collect();
    log.extend(&demo_entries(3)).unwrap();
    let after = fetch_verified_checkpoint(&log, &info).unwrap();
    assert_eq!((before.size, after.size), (512, 1280));
    for (t, bytes) in tiles_before.iter().enumerate() {
        assert_eq!(
            &log.data_tile(t as u64).unwrap(),
            bytes,
            "history unchanged"
        );
    }
    // The new checkpoint provably extends the old one, and the old tree's partial tile is
    // still served for clients that hold the old checkpoint.
    let auth = TileAuthenticator::new(&log, after.clone());
    auth.prove_extends(&before).unwrap();
    assert_eq!(
        auth.tile_root(4).unwrap(),
        scan_tile(&log.data_tile(4).unwrap(), 4, &engine())
            .unwrap()
            .root
            .0
    );
    let old_auth = TileAuthenticator::new(&log, before);
    assert!(old_auth.tile_root(1).is_ok());
}
