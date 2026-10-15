//! Tests for the `c2pa.hash.data` hard-binding assertion: CBOR field names,
//! stream-vs-slice hashing parity, and how it plugs into a real manifest via
//! `c2pa_store::ManifestStoreBuilder`.

use std::io::Cursor;

use c2pa_cbor::Value;
use c2pa_claim::{Claim, DataHash, GeneratorInfo};
use c2pa_store::ManifestStore;
use sha2::{Digest, Sha256};

const ASSET: &[u8] = b"pretend this is a whole image file's bytes";

/// The top-level keys of a CBOR map, as strings.
fn map_keys(bytes: &[u8]) -> Vec<String> {
    let value: Value = c2pa_cbor::from_slice(bytes).unwrap();
    match value {
        Value::Map(m) => m
            .into_keys()
            .filter_map(|k| match k {
                Value::Text(s) => Some(s),
                _ => None,
            })
            .collect(),
        other => panic!("expected a CBOR map, got {other:?}"),
    }
}

#[test]
fn from_reader_matches_a_direct_digest() {
    let expected = Sha256::digest(ASSET).to_vec();

    let from_reader = DataHash::from_reader("sha256", Cursor::new(ASSET)).unwrap();
    assert_eq!(from_reader.hash, expected);
    assert_eq!(from_reader.alg.as_deref(), Some("sha256"));
    assert_eq!(from_reader.exclusions, None);
    assert!(from_reader.pad.is_empty());
    assert_eq!(from_reader.pad2, None);

    let direct = DataHash::new("sha256", expected.clone());
    assert_eq!(direct, from_reader);
}

#[test]
fn from_reader_rejects_an_unknown_algorithm() {
    let err = DataHash::from_reader("md5", Cursor::new(ASSET)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn round_trips_through_cbor() {
    let dh = DataHash::from_reader("sha256", Cursor::new(ASSET)).unwrap();
    let bytes = dh.to_cbor().unwrap();
    assert_eq!(DataHash::from_cbor(&bytes).unwrap(), dh);
}

#[test]
fn uses_spec_field_names_and_omits_unset_optionals() {
    let dh = DataHash::from_reader("sha256", Cursor::new(ASSET)).unwrap();
    let keys = map_keys(&dh.to_cbor().unwrap());
    assert!(keys.contains(&"alg".to_string()));
    assert!(keys.contains(&"hash".to_string()));
    assert!(keys.contains(&"pad".to_string()));
    // No exclusions, name, or pad2 were set, so they must not appear on the
    // wire (they're not required by the CDDL).
    assert!(!keys.contains(&"exclusions".to_string()));
    assert!(!keys.contains(&"name".to_string()));
    assert!(!keys.contains(&"pad2".to_string()));
}

#[test]
fn plugs_into_a_real_manifest_and_verifies() {
    let dh = DataHash::from_reader("sha256", Cursor::new(ASSET)).unwrap();
    let dh_cbor = dh.to_cbor().unwrap();

    let mut builder =
        c2pa_store::ManifestStoreBuilder::new(Vec::<u8>::new(), "urn:c2pa:test").unwrap();
    let dh_href = builder
        .add_cbor_assertion(DataHash::LABEL, Some(&[7u8; 16]), &dh_cbor)
        .unwrap();

    let mut claim = Claim::new(
        "urn:c2pa:test",
        "xmp:iid:test-instance",
        GeneratorInfo::new("test_generator"),
    );
    claim.alg = Some("sha256".to_string());
    claim.add_created_assertion(c2pa_claim::HashedUri::new(
        dh_href.url,
        Some(dh_href.alg.to_string()),
        &dh_href.hash,
    ));
    let claim_cbor = claim.to_cbor().unwrap();

    builder.add_claim("c2pa.claim.v2", &claim_cbor).unwrap();
    let bytes = builder.finish().unwrap();

    let store = ManifestStore::parse(&bytes).unwrap();
    let manifest = store.active_manifest().unwrap();
    let decoded = Claim::from_cbor(manifest.claim_cbor().unwrap()).unwrap();

    let href = &decoded.created_assertions[0];
    assert_eq!(
        href.verify(&store, &manifest, decoded.alg.as_deref()),
        Ok(())
    );

    let assertion = manifest.assertions().unwrap().next().unwrap();
    assert_eq!(assertion.label(), Some(DataHash::LABEL));
    let decoded_dh = DataHash::from_cbor(assertion.payload().unwrap().data).unwrap();
    assert_eq!(decoded_dh, dh);
}

#[test]
fn incremental_hasher_matches_from_reader_for_any_chunking() {
    let expected = DataHash::from_reader("sha256", Cursor::new(ASSET)).unwrap();
    for chunk in [1, 5, ASSET.len()] {
        let mut h = DataHash::hasher("sha256").unwrap();
        for piece in ASSET.chunks(chunk) {
            h.update(piece);
        }
        assert_eq!(h.bytes_hashed(), ASSET.len() as u64);
        assert_eq!(h.finish(), expected);
    }
    assert!(DataHash::hasher("md5").is_none());
}
