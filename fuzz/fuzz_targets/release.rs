#![no_main]
use std::sync::OnceLock;

use cybermesh_intelligence::{TrustRoot, verify_release};
use cybermesh_protocol::testkit::TestNetwork;
use libfuzzer_sys::fuzz_target;

static ROOT: OnceLock<TrustRoot> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let root = ROOT.get_or_init(|| {
        TrustRoot::from_manifest(&TestNetwork::new(&[("org-a", 1), ("org-b", 1)], 1_800_000_000).manifest)
    });
    let _ = verify_release(data, root, 1_800_000_000, None);
});
