#![no_main]
use std::sync::OnceLock;

use cybermesh_analysis::{Engine, EvidenceBundle};
use cybermesh_ct::names::certificate_names;
use cybermesh_ct::tile::{Entry, EntryKind};
use libfuzzer_sys::fuzz_target;

static ENGINE: OnceLock<Engine> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let engine = ENGINE.get_or_init(|| Engine::new(EvidenceBundle::default()));
    // Whole tiles (framing) ...
    let _ = cybermesh_ct::scan_tile(data, 0, engine);
    // ... and arbitrary DER as certificate or precertificate TBS (x509-parser path).
    for kind in [EntryKind::X509, EntryKind::Precert] {
        let e = Entry { index: 0, timestamp: 0, kind, der: data.to_vec(), leaf_hash: [0; 32] };
        let _ = certificate_names(&e);
    }
});
