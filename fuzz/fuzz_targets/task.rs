#![no_main]
use std::sync::OnceLock;

use cybermesh_protocol::testkit::TestNetwork;
use cybermesh_protocol::validate::{verify_heartbeat, verify_result, verify_task};
use cybermesh_protocol::Limits;
use libfuzzer_sys::fuzz_target;

static NET: OnceLock<TestNetwork> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let net = NET.get_or_init(|| TestNetwork::new(&[("org-a", 1), ("org-b", 1), ("org-c", 1)], 1_800_000_000));
    let l = Limits::default();
    let _ = verify_task(data, &net.manifest, 1_800_000_000, &l);
    let _ = verify_result(data, &net.manifest, 1_800_000_000, &l);
    let _ = verify_heartbeat(data, &net.manifest, 1_800_000_000, &l);
});
