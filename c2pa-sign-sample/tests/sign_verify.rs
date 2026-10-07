//! End-to-end check that the binary's output is a *cryptographically valid*
//! Ed25519 signature over the claim, not just structurally present: runs the
//! binary against a temp file, decodes the `COSE_Sign1` from the written
//! sidecar, pulls the end-entity cert's public key out of its `x5chain`, and
//! verifies the signature against it.

use std::io::Write;
use std::process::Command;

use c2pa_cbor::Value;
use c2pa_cbor::cose::{CoseSign1, Label};
use c2pa_store::ManifestStore;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// IANA COSE Header Parameters registry label for `x5chain`.
const COSE_HEADER_X5CHAIN: i64 = 33;

/// Pulls the raw 32-byte Ed25519 public key out of a cert's DER: finds the
/// id-Ed25519 OID (1.3.101.112), then the BIT STRING right after it that
/// holds the key (`03 21 00` = tag, 33-byte length, zero unused bits).
fn ed25519_public_key_from_der(der: &[u8]) -> [u8; 32] {
    let oid = [0x06, 0x03, 0x2B, 0x65, 0x70];
    let oid_pos = der
        .windows(oid.len())
        .position(|w| w == oid)
        .expect("ed25519 OID in cert DER");
    let bitstring_tag = [0x03, 0x21, 0x00];
    let search_from = oid_pos + oid.len();
    let rel_pos = der[search_from..]
        .windows(bitstring_tag.len())
        .position(|w| w == bitstring_tag)
        .expect("ed25519 SPKI bit string in cert DER");
    let key_start = search_from + rel_pos + bitstring_tag.len();
    der[key_start..key_start + 32].try_into().unwrap()
}

#[test]
fn signature_verifies_against_x5chain_public_key() {
    let dir = std::env::temp_dir();
    let asset_path = dir.join("c2pa-sign-sample-test-asset.txt");
    std::fs::File::create(&asset_path)
        .unwrap()
        .write_all(b"end-to-end test asset bytes")
        .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_c2pa-sign-sample"))
        .arg(&asset_path)
        .output()
        .expect("run binary");
    assert!(output.status.success(), "{:?}", output);

    let sidecar_path = asset_path.with_extension("c2pa");
    let store_bytes = std::fs::read(&sidecar_path).unwrap();
    let store = ManifestStore::parse(&store_bytes).unwrap();
    let manifest = store.active_manifest().unwrap();
    let claim_cbor = manifest.claim_cbor().unwrap().to_vec();
    let sig_cbor = manifest.signature_cose().unwrap();

    let mut sign1 = CoseSign1::from_tagged_slice(sig_cbor).unwrap();

    let (_l, x5chain_value) = sign1
        .protected
        .header
        .rest
        .iter()
        .find(|(l, _)| matches!(l, Label::Int(i) if *i == COSE_HEADER_X5CHAIN))
        .expect("x5chain header present");
    let Value::Array(certs) = x5chain_value else {
        panic!("x5chain not an array");
    };
    let Value::Bytes(ee_der) = &certs[0] else {
        panic!("x5chain[0] not bytes");
    };
    let verifying_key =
        VerifyingKey::from_bytes(&ed25519_public_key_from_der(ee_der)).unwrap();

    // Detached-content check: the signature box's payload is only present in
    // memory for our own convenience, so restore it from the claim box the
    // same way an external verifier would before recomputing the TBS bytes.
    sign1.payload = Some(claim_cbor);
    let tbs = sign1.tbs_data(&[]).expect("build Sig_structure");
    let signature = Signature::from_slice(&sign1.signature).unwrap();
    verifying_key
        .verify(&tbs, &signature)
        .expect("signature must verify against the x5chain's end-entity public key");

    std::fs::remove_file(&asset_path).ok();
    std::fs::remove_file(&sidecar_path).ok();
    std::fs::remove_file(asset_path.with_extension("ca.pem")).ok();
}

