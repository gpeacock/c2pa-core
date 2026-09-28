//! Tests for `HashedUri` CBOR encoding/decoding and JUMBF URI integration.

use c2pa_claim::HashedUri;

const HASH: &[u8] = &[
    0x53, 0xd1, 0xb2, 0xcf, 0x4e, 0x6d, 0x9a, 0x97, 0xed, 0x92, 0x81, 0x18, 0x3f, 0xa5, 0xd8, 0x36,
];

#[test]
fn round_trips_with_alg() {
    let h = HashedUri::new(
        "self#jumbf=c2pa.assertions/c2pa.hash.data",
        Some("sha256".to_string()),
        HASH,
    );
    let bytes = h.to_cbor().unwrap();
    let decoded = HashedUri::from_cbor(&bytes).unwrap();
    assert_eq!(decoded, h);
    assert_eq!(decoded.url(), "self#jumbf=c2pa.assertions/c2pa.hash.data");
    assert_eq!(decoded.alg(), Some("sha256"));
    assert_eq!(decoded.hash(), HASH);
}

#[test]
fn round_trips_without_alg() {
    let h = HashedUri::new("self#jumbf=c2pa.assertions/x", None, HASH);
    let bytes = h.to_cbor().unwrap();
    let decoded = HashedUri::from_cbor(&bytes).unwrap();
    assert_eq!(decoded, h);
    assert_eq!(decoded.alg(), None);
}

#[test]
fn alg_is_omitted_from_the_wire_when_none() {
    // Deterministic CBOR encodes a small map as 0xA0 + entry count. With `alg`
    // omitted the map has 2 entries (url, hash); with it present, 3.
    let with_alg = HashedUri::new("self#jumbf=x", Some("sha256".to_string()), HASH)
        .to_cbor()
        .unwrap();
    let without_alg = HashedUri::new("self#jumbf=x", None, HASH)
        .to_cbor()
        .unwrap();
    assert_eq!(
        with_alg[0], 0xA3,
        "map should have 3 entries with alg present"
    );
    assert_eq!(
        without_alg[0], 0xA2,
        "map should have 2 entries with alg omitted"
    );
}

#[test]
fn salt_is_never_serialized() {
    let mut h = HashedUri::new("self#jumbf=x", Some("sha256".to_string()), HASH);
    h.set_salt(Some(vec![7u8; 16]));
    let bytes = h.to_cbor().unwrap();
    // Salt must not appear on the wire (still a 3-entry map: url, alg, hash).
    assert_eq!(bytes[0], 0xA3);
    let decoded = HashedUri::from_cbor(&bytes).unwrap();
    assert_eq!(decoded.salt(), None);
}

#[test]
fn hash_encodes_as_a_cbor_byte_string() {
    // A 16-byte byte string is major type 2, short form: 0x40 + 16 = 0x50.
    let bytes = HashedUri::new("self#jumbf=x", None, HASH)
        .to_cbor()
        .unwrap();
    // Find the 0x50 length prefix followed by the hash bytes.
    let needle = {
        let mut v = vec![0x50u8];
        v.extend_from_slice(HASH);
        v
    };
    assert!(
        bytes.windows(needle.len()).any(|w| w == needle),
        "hash should be encoded as a definite-length CBOR byte string"
    );
}

#[test]
fn jumbf_uri_reflects_relative_vs_absolute() {
    let rel = HashedUri::new("self#jumbf=c2pa.assertions/c2pa.hash.data", None, HASH);
    assert!(!rel.jumbf_uri().unwrap().is_absolute());

    let abs = HashedUri::new(
        "self#jumbf=/c2pa/urn:c2pa:test/c2pa.assertions/c2pa.hash.data",
        None,
        HASH,
    );
    assert!(abs.jumbf_uri().unwrap().is_absolute());
}

#[test]
fn set_hash_replaces_digest() {
    let mut h = HashedUri::new("self#jumbf=x", None, HASH);
    let new_hash = vec![0xFFu8; 16];
    h.set_hash(new_hash.clone());
    assert_eq!(h.hash(), new_hash.as_slice());
}
