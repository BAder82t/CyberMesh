//! Compatibility with the reference OpenTimestamps client (`opentimestamps-client` 0.8.0),
//! checked offline against two proofs made on 2026-11-22 with the public calendars:
//!
//! * `cybermesh-stamp.ots`: written by `cybermesh anchor commit --adapter ots`, read by the
//!   reference client (`ots info` showed its file hash equal to the commitment and the
//!   three pending calendar attestations below);
//! * `reference-input.txt.ots`: written by `ots stamp reference-input.txt`, read here.
//!
//! Both are still pending, so no Bitcoin block is involved and nothing here needs a network.
#![cfg(feature = "ots")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cybermesh_anchor::AnchorStatus;
use cybermesh_anchor::ots::DetachedTimestamp;
use sha2::{Digest, Sha256};

const CYBERMESH_STAMP: &[u8] = include_bytes!("vectors/cybermesh-stamp.ots");
const REFERENCE_INPUT: &[u8] = include_bytes!("vectors/reference-input.txt");
const REFERENCE_STAMP: &[u8] = include_bytes!("vectors/reference-input.txt.ots");
/// The checkpoint commitment `cybermesh-stamp.ots` was made for.
const COMMITMENT: &str = "64c4cf450998f12356784946f52d736354ab323b95695f13e4e40be04183fe6c";

fn pending(statuses: Vec<AnchorStatus>) -> Vec<String> {
    let mut calendars: Vec<String> = statuses
        .into_iter()
        .map(|s| match s {
            AnchorStatus::Pending { calendar } => calendar,
            other => panic!("expected a pending attestation, got {other:?}"),
        })
        .collect();
    calendars.sort();
    calendars
}

#[test]
fn a_proof_made_by_the_reference_client_is_read_and_verified() {
    let digest: [u8; 32] = Sha256::digest(REFERENCE_INPUT).into();
    assert_eq!(
        hex::encode(digest),
        "767206331fe704fcbc189cacaf993767ee4d2b03683e0d31743d90b8fc3bf671"
    );
    let proof = DetachedTimestamp::parse(REFERENCE_STAMP).unwrap();
    let calendars = pending(proof.verify(&digest).unwrap());
    // What `ots info` listed for this file.
    assert_eq!(
        calendars,
        [
            "https://alice.btc.calendar.opentimestamps.org",
            "https://bob.btc.calendar.opentimestamps.org",
            "https://btc.calendar.catallaxy.com",
            "https://finney.calendar.eternitywall.com",
        ]
    );
    // Re-writing a proof reads back as the same proof.
    let again = DetachedTimestamp::parse(&proof.serialize()).unwrap();
    assert_eq!(pending(again.verify(&digest).unwrap()), calendars);
    // A proof is for one file only.
    assert!(proof.verify(&[0u8; 32]).is_err());
}

#[test]
fn a_proof_made_by_cybermesh_is_what_the_reference_client_read() {
    let commitment: [u8; 32] = hex::decode(COMMITMENT).unwrap().try_into().unwrap();
    let proof = DetachedTimestamp::parse(CYBERMESH_STAMP).unwrap();
    let calendars = pending(proof.verify(&commitment).unwrap());
    // What `ots info` listed for this proof.
    assert_eq!(
        calendars,
        [
            "https://alice.btc.calendar.opentimestamps.org",
            "https://bob.btc.calendar.opentimestamps.org",
            "https://finney.calendar.eternitywall.com",
        ]
    );
    // CyberMesh writes the proof back exactly as it wrote it (and as the reference client read it).
    assert_eq!(proof.serialize(), CYBERMESH_STAMP);
    assert!(proof.verify(&[1u8; 32]).is_err());
}
