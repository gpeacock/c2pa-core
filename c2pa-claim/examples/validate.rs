//! Validate the assertion hashed-URIs in a real `.c2pa` manifest store.
//!
//! Usage: `cargo run --example validate -- <path-to.c2pa>`
//!
//! Decodes the active manifest's claim permissively (works for both v1
//! `assertions` and v2 `created_assertions`/`gathered_assertions`), then
//! verifies each hashed URI's stored hash against the referenced box.

use std::process::ExitCode;

use c2pa_claim::HashedUri;
use c2pa_store::ManifestStore;
use serde::Deserialize;

/// Version-agnostic view of the assertion references and default algorithm in a
/// claim. Missing arrays default to empty; unknown fields are ignored.
#[derive(Deserialize, Default)]
struct AnyClaim {
    #[serde(default)]
    created_assertions: Vec<HashedUri>,
    #[serde(default)]
    gathered_assertions: Vec<HashedUri>,
    #[serde(default)]
    assertions: Vec<HashedUri>,
    #[serde(default)]
    alg: Option<String>,
}

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: validate <path-to.c2pa>");
        return ExitCode::FAILURE;
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let store = match ManifestStore::parse(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("parse error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut failures = 0;
    for manifest in store.manifests() {
        let label = manifest.label().unwrap_or("<no label>");
        println!("\nmanifest: {label}");

        let claim_bytes = match manifest.claim_cbor() {
            Ok(c) => c,
            Err(e) => {
                println!("  no claim: {e}");
                continue;
            }
        };
        let claim: AnyClaim = match c2pa_cbor::from_slice(claim_bytes) {
            Ok(c) => c,
            Err(e) => {
                println!("  claim decode error: {e}");
                failures += 1;
                continue;
            }
        };
        let default_alg = claim.alg.as_deref();
        println!("  default alg: {}", default_alg.unwrap_or("<none>"));

        let refs = claim
            .created_assertions
            .iter()
            .map(|h| ("created", h))
            .chain(claim.gathered_assertions.iter().map(|h| ("gathered", h)))
            .chain(claim.assertions.iter().map(|h| ("assertion", h)));

        for (kind, href) in refs {
            match href.verify(&store, &manifest, default_alg) {
                Ok(()) => println!("  ok   [{kind}] {}", href.url()),
                Err(e) => {
                    println!("  FAIL [{kind}] {} -> {e:?}", href.url());
                    failures += 1;
                }
            }
        }
    }

    if failures == 0 {
        println!("\nall hashed URIs verified");
        ExitCode::SUCCESS
    } else {
        println!("\n{failures} verification failure(s)");
        ExitCode::FAILURE
    }
}
