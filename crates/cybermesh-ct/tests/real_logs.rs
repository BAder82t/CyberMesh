//! The shipped lists of real CT logs: every entry is valid evidence, and the keys parse.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use cybermesh_analysis::{CtLogApi, CtLogInfo};
use cybermesh_ct::LogKey;

fn load(name: &str) -> Vec<CtLogInfo> {
    let path = format!(
        "{}/../../datasets/ct-logs/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn every_listed_log_is_valid_evidence_with_a_usable_key() {
    let static_logs = load("public-static-ct-logs.json");
    let classic = load("public-rfc6962-ct-logs.json");
    assert!(!static_logs.is_empty() && !classic.is_empty());
    assert!(static_logs.iter().all(|l| l.api == CtLogApi::Static));
    assert!(classic.iter().all(|l| l.api == CtLogApi::Rfc6962));
    let mut ids = BTreeSet::new();
    let mut origins = BTreeSet::new();
    for l in static_logs.iter().chain(&classic) {
        l.validate().unwrap_or_else(|e| panic!("{}: {e}", l.log_id));
        LogKey::from_info(l).unwrap();
        assert!(ids.insert(l.log_id.clone()), "duplicate id {}", l.log_id);
        // Two logs must not share an origin: a checkpoint of one would pass for the other.
        assert!(
            origins.insert(l.origin.clone()),
            "duplicate origin {}",
            l.origin
        );
    }
}
