#![no_main]
//! Checkpoint (signed note) parsing and signature verification against a pinned key.
use cybermesh_analysis::CtLogInfo;
use cybermesh_ct::checkpoint::{Checkpoint, LogKey, verify_checkpoint};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = Checkpoint::parse(text);
    let log = CtLogInfo {
        log_id: "fuzz".into(),
        description: String::new(),
        monitoring_url: "https://mon.example.org/".into(),
        origin: "log.willow.ct.letsencrypt.org/2027h1".into(),
        public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzsMKtojO0BVB4t59lVyAhxtqObVA+wId5BpJGA8pZrw5GTjzuhpvLu/heQGi0hHCeislkDe34N/2D0SwEUBE0w==".into(),
    };
    if let Ok(key) = LogKey::from_info(&log) {
        let _ = verify_checkpoint(text, &key);
    }
});
