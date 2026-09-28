//! Parse a raw `.c2pa` manifest store and print its structure.
//!
//! Usage: `cargo run --example dump -- <path-to.c2pa>`

use std::process::ExitCode;

use c2pa_store::ManifestStore;

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: dump <path-to.c2pa>");
        return ExitCode::FAILURE;
    };

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("file: {path} ({} bytes)", bytes.len());

    let store = match ManifestStore::parse(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("parse error: {e}");
            return ExitCode::FAILURE;
        }
    };

    match store.verify_label_consistency() {
        Ok(()) => println!("label/UUID consistency: OK"),
        Err(e) => println!("label/UUID consistency: {e}"),
    }

    let manifests: Vec<_> = store.manifests().collect();
    println!("manifests: {}", manifests.len());

    for (i, m) in manifests.iter().enumerate() {
        let active = store
            .active_manifest()
            .and_then(|a| a.label())
            .zip(m.label())
            .is_some_and(|(a, l)| a == l);
        println!(
            "\n[{i}] {}{}",
            m.label().unwrap_or("<no label>"),
            if active { "  (active)" } else { "" }
        );
        println!("    kind: {:?}", m.kind());
        if let Some(salt) = m.salt() {
            println!("    manifest salt: {} bytes", salt.len());
        }

        match m.claim_cbor() {
            Ok(c) => println!("    claim: {} bytes CBOR", c.len()),
            Err(e) => println!("    claim: {e}"),
        }
        match m.signature_cose() {
            Ok(s) => println!("    signature: {} bytes COSE_Sign1", s.len()),
            Err(e) => println!("    signature: {e}"),
        }

        match m.assertions() {
            Ok(assertions) => {
                let assertions: Vec<_> = assertions.collect();
                println!("    assertions: {}", assertions.len());
                for a in &assertions {
                    let label = a.label().unwrap_or("<no label>");
                    match a.payload() {
                        Ok(d) => {
                            let mut extra = String::new();
                            if let Some(mt) = d.media_type {
                                extra.push_str(&format!(", media_type={mt}"));
                            }
                            if let Some(fnm) = d.file_name {
                                extra.push_str(&format!(", file_name={fnm}"));
                            }
                            if let Some(salt) = d.salt {
                                extra.push_str(&format!(", salt={}B", salt.len()));
                            }
                            println!(
                                "      - {label} [{:?}] {}B{extra}",
                                d.content_type,
                                d.data.len()
                            );
                        }
                        Err(e) => println!("      - {label} <error: {e}>"),
                    }
                }
            }
            Err(e) => println!("    assertions: {e}"),
        }
    }

    ExitCode::SUCCESS
}
