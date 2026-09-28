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
//! Usage: `cargo run -- <path-to-file>`

mod ephemeral_cert;

use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::ExitCode;

use c2pa_claim::{Action, Actions, Claim, DataHash, GeneratorInfo, HashedUri};
use c2pa_store::{AssertionHash, ManifestStoreBuilder};
use coset::cbor::value::Value;
use coset::iana::EnumI64;
use coset::{CoseSign1Builder, HeaderBuilder, TaggedCborSerializable, iana};
use ed25519_dalek::Signer;

const MANIFEST_LABEL: &str = "urn:c2pa:sign-sample";
const SIGNER_COMMON_NAME: &str = "c2pa-sign-sample-ephemeral.local";

/// Convert a `ManifestStoreBuilder` result into the `HashedUri` a claim
/// references.
fn hashed_uri(a: AssertionHash) -> HashedUri {
    HashedUri::new(a.url, Some(a.alg.to_string()), &a.hash)
}

/// A throwaway, unique-enough instance ID: no identity infrastructure here,
/// just random bytes hex-encoded into the `xmp:iid:` form claims use.
fn random_instance_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("failed to generate random instance id");
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("xmp:iid:{hex}")
}

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: c2pa-sign-sample <path-to-file>");
        return ExitCode::FAILURE;
    };
    let path = PathBuf::from(path);

    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("open {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    // Streams the file's bytes through the hasher rather than buffering the
    // whole thing in memory.
    let data_hash = match DataHash::from_reader("sha256", BufReader::new(file)) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("hash {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let data_hash_cbor = data_hash.to_cbor().expect("encode data hash assertion");

    let mut builder =
        ManifestStoreBuilder::new(Vec::<u8>::new(), MANIFEST_LABEL).expect("start manifest store");

    let data_hash_href = hashed_uri(
        builder
            .add_cbor_assertion(DataHash::LABEL, None, &data_hash_cbor)
            .expect("add data hash assertion"),
    );

    let mut actions = Actions::new();
    actions.add_action(
        Action::new(Action::CREATED).with_digital_source_type(Action::DIGITAL_SOURCE_TYPE_EMPTY),
    );
    let actions_cbor = actions.to_cbor().expect("encode actions assertion");
    let actions_href = hashed_uri(
        builder
            .add_cbor_assertion(Actions::LABEL, None, &actions_cbor)
            .expect("add actions assertion"),
    );

    let mut generator_info = GeneratorInfo::new("c2pa-sign-sample");
    generator_info.version = Some(env!("CARGO_PKG_VERSION").to_string());

    let mut claim = Claim::new(MANIFEST_LABEL, random_instance_id(), generator_info);
    // Must match the algorithm `ManifestStoreBuilder` actually hashed
    // assertions with (currently always SHA-256).
    claim.alg = Some("sha256".to_string());
    claim.add_created_assertion(data_hash_href);
    claim.add_created_assertion(actions_href);
    let claim_cbor = claim.to_cbor().expect("encode claim");

    builder
        .add_claim("c2pa.claim.v2", &claim_cbor)
        .expect("add claim");

    // A real Ed25519 signature over the claim bytes, from a freshly generated
    // self-signed CA + end-entity certificate chain -- real crypto, but with
    // no trust anchoring (see the module doc comment and this binary's own).
    let chain = ephemeral_cert::generate_ephemeral_chain(SIGNER_COMMON_NAME);
    let x5chain = Value::Array(vec![
        Value::Bytes(chain.ee_der.clone()),
        Value::Bytes(chain.ca_der.clone()),
    ]);

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .value(iana::HeaderParameter::X5Chain.to_i64(), x5chain)
        .build();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(claim_cbor)
        .create_signature(&[], |tbs| {
            chain.ee_signing_key.sign(tbs).to_bytes().to_vec()
        })
        .build();
    // c2pa-rs/c2patool expect the tagged form (CBOR tag 18), not the bare
    // 4-element array `CborSerializable::to_vec` would produce.
    let signature_cbor = sign1.to_tagged_vec().expect("encode COSE_Sign1");

    builder
        .add_signature(&signature_cbor)
        .expect("add signature");

    let store_bytes = builder.finish().expect("finish manifest store");

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
         c2patool trust --trust_anchors {}",
        ca_pem_path.display(),
        ca_pem_path.display()
    );
    ExitCode::SUCCESS
}
