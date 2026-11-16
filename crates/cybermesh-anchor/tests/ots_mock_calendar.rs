//! OpenTimestamps client against a local mock calendar (no public network access).
#![cfg(feature = "ots")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]


use std::thread;
use std::time::Duration;

use cybermesh_anchor::ots::{Attestation, DetachedTimestamp, Op, Timestamp, stamp};
use cybermesh_anchor::ots::OtsAnchor as OtsAnchorForTest;
use cybermesh_anchor::{Anchor, AnchorReceipt, AnchorStatus};

fn mock_calendar(fail: bool) -> String {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = format!("http://{}", server.server_addr().to_ip().unwrap());
    let uri = addr.clone();
    thread::spawn(move || {
        for mut req in server.incoming_requests() {
            if fail {
                let _ = req.respond(tiny_http::Response::empty(503));
                continue;
            }
            let mut body = Vec::new();
            req.as_reader().read_to_end(&mut body).unwrap();
            // Calendar commits the digest into its own aggregation tree and returns a
            // pending attestation pointing back at itself.
            let appended = [body.as_slice(), b"calendar-salt".as_slice()].concat();
            let t = Timestamp {
                msg: body.clone(),
                attestations: vec![],
                ops: vec![(
                    Op::Append(b"calendar-salt".to_vec()),
                    Timestamp {
                        msg: appended.clone(),
                        attestations: vec![],
                        ops: vec![(
                            Op::Sha256,
                            Timestamp {
                                msg: sha256(&appended),
                                attestations: vec![Attestation::Pending { uri: uri.clone() }],
                                ops: vec![],
                            },
                        )],
                    },
                )],
            };
            let mut out = Vec::new();
            t.serialize(&mut out);
            let _ = req.respond(tiny_http::Response::from_data(out));
        }
    });
    addr
}

fn sha256(b: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    sha2::Sha256::digest(b).to_vec()
}

#[test]
fn stamp_against_mock_calendar_and_verify_offline() {
    let good = mock_calendar(false);
    let down = mock_calendar(true);
    let commitment = [9u8; 32];
    let dt = stamp(commitment, &[down, good.clone()], Duration::from_secs(5)).unwrap();
    let parsed = DetachedTimestamp::parse(&dt.serialize()).unwrap();
    let statuses = parsed.verify(&commitment).unwrap();
    assert_eq!(statuses, vec![AnchorStatus::Pending { calendar: good }]);
}

#[test]
fn all_calendars_down_is_an_error_not_a_panic() {
    let down = mock_calendar(true);
    assert!(stamp([1u8; 32], &[down], Duration::from_secs(5)).is_err());
    assert!(stamp([1u8; 32], &["http://127.0.0.1:9".into()], Duration::from_millis(500)).is_err());
}

#[test]
fn anchor_trait_receipt() {
    let good = mock_calendar(false);
    let mut a = OtsAnchorForTest {
        calendars: vec![good],
        timeout: Duration::from_secs(5),
    };
    let r = a.submit(cybermesh_crypto::Digest([3u8; 32]), 0).unwrap();
    assert!(matches!(r, AnchorReceipt::OpenTimestamps { .. }));
}
