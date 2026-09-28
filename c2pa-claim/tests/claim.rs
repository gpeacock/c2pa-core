//! Tests for v2 `Claim` CBOR encoding/decoding and field mapping.

use c2pa_cbor::Value;
use c2pa_claim::{Claim, GeneratorInfo, HashedUri};

const HASH: &[u8] = &[0xAB; 32];

const MANIFEST_LABEL: &str = "urn:c2pa:test-manifest";

fn sample_claim() -> Claim {
    let mut claim = Claim::new(
        MANIFEST_LABEL,
        "xmp:iid:test-instance",
        GeneratorInfo::new("test_generator"),
    );
    claim.add_created_assertion(HashedUri::new(
        "self#jumbf=c2pa.assertions/c2pa.hash.data",
        Some("sha256".to_string()),
        HASH,
    ));
    claim
}

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
fn round_trips_v2_claim() {
    let claim = sample_claim();
    let bytes = claim.to_cbor().unwrap();
    let decoded = Claim::from_cbor(&bytes).unwrap();
    assert_eq!(decoded, claim);
    assert_eq!(decoded.instance_id, "xmp:iid:test-instance");
    assert_eq!(decoded.claim_generator_info.name, "test_generator");
    assert_eq!(
        decoded.signature,
        format!("self#jumbf=/c2pa/{MANIFEST_LABEL}/c2pa.signature")
    );
    assert_eq!(decoded.created_assertions.len(), 1);
    assert_eq!(decoded.created_assertions[0].alg(), Some("sha256"));
}

#[test]
fn uses_spec_field_names() {
    let keys = map_keys(&sample_claim().to_cbor().unwrap());
    for required in [
        "instanceID",
        "claim_generator_info",
        "signature",
        "created_assertions",
    ] {
        assert!(
            keys.contains(&required.to_string()),
            "missing key {required}"
        );
    }
    // Optional fields left unset must not appear on the wire.
    assert!(!keys.contains(&"gathered_assertions".to_string()));
    assert!(!keys.contains(&"dc:title".to_string()));
    assert!(!keys.contains(&"alg".to_string()));
}

#[test]
fn title_uses_dc_prefix_when_set() {
    let mut claim = sample_claim();
    claim.title = Some("My Asset".to_string());
    let bytes = claim.to_cbor().unwrap();
    assert!(map_keys(&bytes).contains(&"dc:title".to_string()));
    assert_eq!(
        Claim::from_cbor(&bytes).unwrap().title,
        Some("My Asset".to_string())
    );
}

#[test]
fn decode_ignores_unknown_fields() {
    // A superset struct with an extra field the reader doesn't know about.
    #[derive(serde::Serialize)]
    struct ClaimPlusExtra<'a> {
        #[serde(rename = "instanceID")]
        instance_id: &'a str,
        claim_generator_info: GeneratorInfo,
        signature: &'a str,
        created_assertions: Vec<HashedUri>,
        future_field: &'a str,
    }

    let extended = ClaimPlusExtra {
        instance_id: "xmp:iid:x",
        claim_generator_info: GeneratorInfo::new("g"),
        signature: "self#jumbf=c2pa.signature",
        created_assertions: vec![HashedUri::new("self#jumbf=c2pa.assertions/a", None, HASH)],
        future_field: "ignored",
    };
    let bytes = c2pa_cbor::to_vec_deterministic(&extended).unwrap();

    let claim = Claim::from_cbor(&bytes).expect("unknown fields should be ignored");
    assert_eq!(claim.instance_id, "xmp:iid:x");
    assert_eq!(claim.created_assertions.len(), 1);
}

#[test]
fn created_assertions_expose_jumbf_uris() {
    let claim = Claim::from_cbor(&sample_claim().to_cbor().unwrap()).unwrap();
    let uri = claim.created_assertions[0].jumbf_uri().unwrap();
    assert!(!uri.is_absolute());
    assert_eq!(
        uri.segments().collect::<Vec<_>>(),
        vec!["c2pa.assertions", "c2pa.hash.data"]
    );
}

#[test]
fn generator_info_optionals_round_trip() {
    let mut gi = GeneratorInfo::new("gen");
    gi.version = Some("1.2.3".to_string());
    gi.spec_version = Some("2.1".to_string());
    let mut claim = sample_claim();
    claim.claim_generator_info = gi;

    let decoded = Claim::from_cbor(&claim.to_cbor().unwrap()).unwrap();
    assert_eq!(
        decoded.claim_generator_info.version,
        Some("1.2.3".to_string())
    );
    assert_eq!(
        decoded.claim_generator_info.spec_version,
        Some("2.1".to_string())
    );
}
