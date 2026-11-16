#![no_main]
use std::sync::OnceLock;

use cybermesh_analysis::{Engine, EvidenceBundle, normalize_domain};
use libfuzzer_sys::fuzz_target;

static ENGINE: OnceLock<Engine> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let engine = ENGINE.get_or_init(|| Engine::new(EvidenceBundle::default()));
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(d) = normalize_domain(s)
    {
        assert_eq!(normalize_domain(&d).as_deref(), Ok(d.as_str()), "normalisation must be idempotent");
        let _ = engine.assess(&d).expect("normalised domains must be assessable");
    }
});
