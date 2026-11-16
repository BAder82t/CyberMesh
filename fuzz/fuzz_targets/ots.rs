#![no_main]
use cybermesh_anchor::ots::DetachedTimestamp;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Prepend a valid header so the fuzzer spends its time in the timestamp tree parser.
    let mut buf = cybermesh_anchor::ots::header_magic();
    buf.push(1);
    buf.push(0x08);
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(data);
    if let Ok(dt) = DetachedTimestamp::parse(&buf) {
        let _ = dt.verify(&[0u8; 32]);
        let _ = DetachedTimestamp::parse(&dt.serialize());
    }
    let _ = DetachedTimestamp::parse(data);
});
