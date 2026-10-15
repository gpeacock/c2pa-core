//! Build a minimal, real C2PA manifest for a file and write it to a sidecar
//! `.c2pa` next to the source -- no embedding, just the shape: a
//! `c2pa.hash.data` hard binding over the whole file, a `c2pa.actions.v2`
//! assertion recording a `c2pa.created` action, a v2 claim referencing both,
//! and a real Ed25519 `COSE_Sign1` over the claim bytes, with a freshly
//! generated self-signed CA + end-entity certificate chain in `x5chain`.
//!
//! **WARNING:** The CA is generated fresh on every run and isn't anchored to
//! any trust store, so this cannot produce a manifest a verifier would trust
//! by default. It also gets written out as `<sidecar>.ca.pem` so a verifier
//! can be told to trust it for local testing, e.g.
//! `c2patool trust --trust_anchors <sidecar>.ca.pem`.
//!
//! The work runs through [`sign_session::SignSession`], a caller-driven state
//! machine: this `main` loop reads the file in chunks, feeds them in, reports
//! progress, and answers the session's request for a signature. Nothing is a
//! callback and nothing assumes a thread model or async runtime -- the same
//! session could be driven from an event loop, an async task, or a UI tick,
//! and cancelled at any yield point by dropping it.
//!
//! Usage: `cargo run -- <path-to-file>`

mod ephemeral_cert;
mod sign_session;

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use c2pa_claim::GeneratorInfo;
use ed25519_dalek::Signer;
use sign_session::{Action, Progress, SignParams, SignSession};

const MANIFEST_LABEL: &str = "urn:c2pa:sign-sample";
const SIGNER_COMMON_NAME: &str = "c2pa-sign-sample-ephemeral.local";
const CHUNK_SIZE: usize = 64 * 1024;

/// COSE algorithm identifier for EdDSA (RFC 8152 §8.2, IANA COSE Algorithms
/// registry). `c2pa-cbor`'s `cose` module doesn't ship an `iana` enum, so
/// this is the raw registered value.
const COSE_ALG_EDDSA: i64 = -8;

/// A throwaway, unique-enough instance ID: no identity infrastructure here,
/// just random bytes hex-encoded into the `xmp:iid:` form claims use.
fn random_instance_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("failed to generate random instance id");
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("xmp:iid:{hex}")
}

fn report(p: Progress) {
    match p.asset_len {
        Some(total) if total > 0 => eprint!(
            "\r{:?}: {}/{} bytes ({}%)   ",
            p.phase,
            p.asset_bytes_hashed,
            total,
            p.asset_bytes_hashed * 100 / total
        ),
        _ => eprint!("\r{:?}: {} bytes   ", p.phase, p.asset_bytes_hashed),
    }
    std::io::stderr().flush().ok();
}

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: c2pa-sign-sample <path-to-file>");
        return ExitCode::FAILURE;
    };
    let path = PathBuf::from(path);

    let mut file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("open {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let asset_len = file.metadata().ok().map(|m| m.len());

    // A real Ed25519 key from a freshly generated self-signed CA + end-entity
    // certificate chain -- real crypto, but with no trust anchoring (see the
    // module doc comment). The session only needs the certificates; the key
    // stays here, with the caller.
    let chain = ephemeral_cert::generate_ephemeral_chain(SIGNER_COMMON_NAME);

    let mut generator = GeneratorInfo::new("c2pa-sign-sample");
    generator.version = Some(env!("CARGO_PKG_VERSION").to_string());

    let mut session = SignSession::new(SignParams {
        manifest_label: MANIFEST_LABEL.to_string(),
        instance_id: random_instance_id(),
        generator,
        data_hash_alg: "sha256".to_string(),
        cose_alg: COSE_ALG_EDDSA,
        x5chain: vec![chain.ee_der.clone(), chain.ca_der.clone()],
        asset_len,
    })
    .expect("start signing session");

    let mut buf = vec![0u8; CHUNK_SIZE];
    // Each iteration is a yield point: this is where a host would check for
    // cancellation, update a UI, or go service other work.
    let result = loop {
        let action = match session.poll() {
            Ok(a) => a,
            Err(e) => break Err(e.to_string()),
        };
        let step = match action {
            Action::NeedAssetData => match file.read(&mut buf) {
                Ok(0) => session.end_asset().map_err(|e| e.to_string()),
                Ok(n) => session.write_asset(&buf[..n]).map_err(|e| e.to_string()),
                Err(e) => Err(format!("read {}: {e}", path.display())),
            },
            Action::NeedSignature(tbs) => {
                let signature = chain.ee_signing_key.sign(tbs).to_bytes().to_vec();
                session
                    .provide_signature(signature)
                    .map_err(|e| e.to_string())
            }
            Action::Continue => Ok(()),
            Action::Complete => break Ok(()),
        };
        if let Err(e) = step {
            break Err(e);
        }
        report(session.progress());
    };
    eprintln!();

    let store_bytes =
        match result.and_then(|()| session.into_store_bytes().map_err(|e| e.to_string())) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("sign {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        };

    let sidecar_path = path.with_extension("c2pa");
    if let Err(e) = std::fs::write(&sidecar_path, &store_bytes) {
        eprintln!("write {}: {e}", sidecar_path.display());
        return ExitCode::FAILURE;
    }
    let ca_pem_path = path.with_extension("ca.pem");
    if let Err(e) = std::fs::write(&ca_pem_path, &chain.ca_pem) {
        eprintln!("write {}: {e}", ca_pem_path.display());
        return ExitCode::FAILURE;
    }

    println!(
        "wrote {} ({} bytes)",
        sidecar_path.display(),
        store_bytes.len()
    );
    println!(
        "wrote {} -- not a trusted CA; to validate with c2patool, run:\n  \
         c2patool {:?} trust --trust_anchors \"{}\"",
        ca_pem_path.display(),
        path,
        ca_pem_path.display()
    );
    ExitCode::SUCCESS
}
