//! Read a `.c2pa` manifest store, display each embedded claim, and validate
//! its assertions' hashed-URI references against the referenced boxes.
//!
//! Usage: `cargo run --example dump -- <path-to.c2pa>`
//!
//! Claims decode as the typed (v2-only) [`Claim`] when possible, for full
//! display of `instanceID`, generator info, and title. A claim that doesn't
//! fit that shape (e.g. a v1 `claim-map`) falls back to a permissive decode
//! that only recovers the assertion references and default algorithm, so
//! verification still runs.

use std::process::ExitCode;

use c2pa_claim::{Claim, HashedUri};
use c2pa_store::ManifestStore;
use serde::Deserialize;

/// Version-agnostic view of the assertion references and default algorithm in
/// a claim. Used as a fallback when a claim doesn't decode as [`Claim`].
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

    let manifests: Vec<_> = store.manifests().collect();
    println!("manifests: {}", manifests.len());

    let mut verified = 0usize;
    let mut failures = 0usize;

    for manifest in &manifests {
        let label = manifest.label().unwrap_or("<no label>");
        let active = store
            .active_manifest()
            .and_then(|a| a.label())
            .zip(manifest.label())
            .is_some_and(|(a, l)| a == l);
        println!("\n[{label}]{}", if active { "  (active)" } else { "" });

        let claim_bytes = match manifest.claim_cbor() {
            Ok(c) => c,
            Err(e) => {
                println!("  no claim: {e}");
                failures += 1;
                continue;
            }
        };

        let (default_alg, refs): (Option<String>, Vec<(&str, HashedUri)>) =
            match Claim::from_cbor(claim_bytes) {
                Ok(claim) => {
                    println!("  instanceID: {}", claim.instance_id);
                    let version = claim
                        .claim_generator_info
                        .version
                        .as_deref()
                        .map(|v| format!(" {v}"))
                        .unwrap_or_default();
                    println!("  generator: {}{version}", claim.claim_generator_info.name);
                    if let Some(title) = &claim.title {
                        println!("  title: {title}");
                    }
                    println!(
                        "  default alg: {}",
                        claim.alg.as_deref().unwrap_or("<none>")
                    );

                    let mut refs: Vec<(&str, HashedUri)> = claim
                        .created_assertions
                        .into_iter()
                        .map(|h| ("created", h))
                        .collect();
                    if let Some(gathered) = claim.gathered_assertions {
                        refs.extend(gathered.into_iter().map(|h| ("gathered", h)));
                    }
                    (claim.alg, refs)
                }
                Err(e) => {
                    println!("  claim: not a v2 claim ({e}); using permissive decode");
                    match c2pa_cbor::from_slice::<AnyClaim>(claim_bytes) {
                        Ok(any) => {
                            println!("  default alg: {}", any.alg.as_deref().unwrap_or("<none>"));
                            let refs = any
                                .created_assertions
                                .into_iter()
                                .map(|h| ("created", h))
                                .chain(any.gathered_assertions.into_iter().map(|h| ("gathered", h)))
                                .chain(any.assertions.into_iter().map(|h| ("assertion", h)))
                                .collect();
                            (any.alg, refs)
                        }
                        Err(e) => {
                            println!("  claim decode error: {e}");
                            failures += 1;
                            continue;
                        }
                    }
                }
            };

        println!("  assertions:");
        for (kind, href) in &refs {
            match href.verify(&store, manifest, default_alg.as_deref()) {
                Ok(()) => {
                    println!("    ok   [{kind}] {}", href.url());
                    verified += 1;
                }
                Err(e) => {
                    println!("    FAIL [{kind}] {} -> {e:?}", href.url());
                    failures += 1;
                }
            }
        }
    }

    println!("\n{verified} hashed URI(s) verified, {failures} failure(s)");
    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
