#![no_main]
//! Checkpoint (signed note) parsing and signature verification against a pinned key, witness
//! cosignature verification, and split-view proof checking (all take peer-supplied notes).
use cybermesh_analysis::CtLogInfo;
use cybermesh_ct::checkpoint::{Checkpoint, LogKey, verify_checkpoint};
use cybermesh_ct::witness::{SplitViewProof, verify_cosignature};
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
        // A split-view proof whose notes are the input (and a JSON-encoded proof).
        let proof = SplitViewProof {
            v: 1,
            origin: key.origin().to_owned(),
            larger: text.to_owned(),
            smaller: text.to_owned(),
            prefix_root: String::new(),
            proof: vec![],
        };
        let _ = proof.verify(&key);
        if let Ok(p) = serde_json::from_str::<SplitViewProof>(text) {
            let _ = p.verify(&key);
        }
    }
    let witness = cybermesh_crypto::SecretKey::from_seed(&[1; 32]).public_key();
    let _ = verify_cosignature(text, "cybermesh/fuzz/w", &witness);
});
