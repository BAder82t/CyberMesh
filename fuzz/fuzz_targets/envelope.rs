#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = cybermesh_crypto::Envelope::parse(data, 1 << 20) {
        let _ = env.verify("application/vnd.cybermesh.task+json;v=1", 1, |_| None);
        let _ = env.payload_bytes();
    }
    let _ = cybermesh_crypto::canonical::from_slice::<cybermesh_protocol::TaskResult>(data);
});
