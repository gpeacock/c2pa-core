#![no_main]

//! Fuzz target: the parser must never panic, over-allocate, or loop forever on
//! arbitrary input. Run with `cargo +nightly fuzz run parse` (requires
//! `cargo install cargo-fuzz`).

use libfuzzer_sys::fuzz_target;

use c2pa_store::ManifestStore;

fuzz_target!(|data: &[u8]| {
    if let Ok(store) = ManifestStore::parse(data) {
        let _ = store.verify_label_consistency();
        // Walk every accessor so lazy paths are exercised too.
        for manifest in store.manifests() {
            let _ = manifest.label();
            let _ = manifest.claim_cbor();
            let _ = manifest.signature_cose();
            if let Ok(assertions) = manifest.assertions() {
                for assertion in assertions {
                    let _ = assertion.label();
                    let _ = assertion.payload();
                }
            }
        }
    }
});
