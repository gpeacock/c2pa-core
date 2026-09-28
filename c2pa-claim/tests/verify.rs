//! End-to-end tests: resolve a hashed URI against a real (hand-built) manifest
//! store and verify the referenced assertion box's payload hash.

use c2pa_claim::{HashedUri, VerifyError};
use c2pa_store::{uuids, ManifestStore};
use sha2::{Digest, Sha256};

// --- minimal JUMBF builders (mirrors c2pa-store's test helpers) ---

fn boxed(tbox: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let len = (8 + payload.len()) as u32;
    let mut v = Vec::with_capacity(8 + payload.len());
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(tbox);
    v.extend_from_slice(payload);
    v
}

fn jumd(uuid: &[u8; 16], label: &str, salt: Option<&[u8]>) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(uuid);
    let mut toggles = 0x03u8;
    if salt.is_some() {
        toggles |= 0x10;
    }
    p.push(toggles);
    p.extend_from_slice(label.as_bytes());
    p.push(0);
    if let Some(s) = salt {
        p.extend_from_slice(&boxed(b"c2sh", s));
    }
    boxed(b"jumd", &p)
}

fn superbox(uuid: &[u8; 16], label: &str, salt: Option<&[u8]>, children: &[Vec<u8>]) -> Vec<u8> {
    let mut p = jumd(uuid, label, salt);
    for c in children {
        p.extend_from_slice(c);
    }
    boxed(b"jumb", &p)
}

const SALT: &[u8] = &[7u8; 16];

/// Build a store with one salted CBOR assertion; return (store bytes, the
/// assertion superbox bytes) so the test can hash the assertion's payload.
fn store_with_assertion() -> (Vec<u8>, Vec<u8>) {
    let assertion = superbox(
        &uuids::CBOR,
        "c2pa.hash.data",
        Some(SALT),
        &[boxed(b"cbor", &[0xA1, 0x00, 0x01])],
    );
    let assertions = superbox(
        &uuids::ASSERTION_STORE,
        "c2pa.assertions",
        None,
        std::slice::from_ref(&assertion),
    );
    let claim = superbox(
        &uuids::CLAIM,
        "c2pa.claim.v2",
        None,
        &[boxed(b"cbor", &[0xA0])],
    );
    let manifest = superbox(
        &uuids::MANIFEST,
        "urn:c2pa:test-manifest",
        None,
        &[claim, assertions],
    );
    let store = superbox(&uuids::MANIFEST_STORE, "c2pa", None, &[manifest]);
    (store, assertion)
}

/// The hashed span is the box payload: everything after the 8-byte `jumb`
/// header.
fn payload_sha256(assertion_box: &[u8]) -> Vec<u8> {
    Sha256::digest(&assertion_box[8..]).to_vec()
}

#[test]
fn verifies_matching_assertion_hash() {
    let (bytes, assertion) = store_with_assertion();
    let store = ManifestStore::parse(&bytes).unwrap();
    let m = store.active_manifest().unwrap();

    let href = HashedUri::new(
        "self#jumbf=c2pa.assertions/c2pa.hash.data",
        Some("sha256".to_string()),
        &payload_sha256(&assertion),
    );
    assert_eq!(href.verify(&store, &m, None), Ok(()));
}

#[test]
fn uses_default_alg_when_uri_omits_it() {
    let (bytes, assertion) = store_with_assertion();
    let store = ManifestStore::parse(&bytes).unwrap();
    let m = store.active_manifest().unwrap();

    let href = HashedUri::new(
        "self#jumbf=c2pa.assertions/c2pa.hash.data",
        None,
        &payload_sha256(&assertion),
    );
    assert_eq!(href.verify(&store, &m, Some("sha256")), Ok(()));
    assert_eq!(href.verify(&store, &m, None), Err(VerifyError::MissingAlg));
}

#[test]
fn detects_tampered_hash() {
    let (bytes, _) = store_with_assertion();
    let store = ManifestStore::parse(&bytes).unwrap();
    let m = store.active_manifest().unwrap();

    let href = HashedUri::new(
        "self#jumbf=c2pa.assertions/c2pa.hash.data",
        Some("sha256".to_string()),
        &[0u8; 32],
    );
    assert_eq!(
        href.verify(&store, &m, None),
        Err(VerifyError::HashMismatch)
    );
}

#[test]
fn reports_unknown_alg() {
    let (bytes, assertion) = store_with_assertion();
    let store = ManifestStore::parse(&bytes).unwrap();
    let m = store.active_manifest().unwrap();

    let href = HashedUri::new(
        "self#jumbf=c2pa.assertions/c2pa.hash.data",
        Some("md5".to_string()),
        &payload_sha256(&assertion),
    );
    assert_eq!(
        href.verify(&store, &m, None),
        Err(VerifyError::UnknownAlg("md5".to_string()))
    );
}

#[test]
fn reports_unresolved_uri() {
    let (bytes, assertion) = store_with_assertion();
    let store = ManifestStore::parse(&bytes).unwrap();
    let m = store.active_manifest().unwrap();

    let href = HashedUri::new(
        "self#jumbf=c2pa.assertions/c2pa.nonexistent",
        Some("sha256".to_string()),
        &payload_sha256(&assertion),
    );
    assert!(matches!(
        href.verify(&store, &m, None),
        Err(VerifyError::Unresolved(_))
    ));
}

#[test]
fn verifies_via_absolute_uri() {
    let (bytes, assertion) = store_with_assertion();
    let store = ManifestStore::parse(&bytes).unwrap();
    let m = store.active_manifest().unwrap();

    let href = HashedUri::new(
        "self#jumbf=/c2pa/urn:c2pa:test-manifest/c2pa.assertions/c2pa.hash.data",
        Some("sha256".to_string()),
        &payload_sha256(&assertion),
    );
    assert_eq!(href.verify(&store, &m, None), Ok(()));
}
