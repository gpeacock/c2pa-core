//! Integration tests. These build minimal JUMBF structures by hand and exercise
//! the happy path, C2PA content-type/UUID checks, salt handling, and the
//! hardening limits.

use c2pa_store::{uuids, ContentType, Error, JumbfUri, Limits, ManifestKind, ManifestStore};

/// Wrap `payload` in a JUMBF box with the given 4-byte type.
fn boxed(tbox: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let len = (8 + payload.len()) as u32;
    let mut v = Vec::with_capacity(8 + payload.len());
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(tbox);
    v.extend_from_slice(payload);
    v
}

/// Build a `jumd` description box: UUID, toggles, label, optional salt (`c2sh`).
fn jumd(uuid: &[u8; 16], label: &str, salt: Option<&[u8]>) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(uuid);
    let mut toggles = 0x03u8; // requestable | label present
    if salt.is_some() {
        toggles |= 0x10; // private box present
    }
    p.push(toggles);
    p.extend_from_slice(label.as_bytes());
    p.push(0); // NUL terminator
    if let Some(s) = salt {
        p.extend_from_slice(&boxed(b"c2sh", s));
    }
    boxed(b"jumd", &p)
}

/// Build a `jumb` superbox: description + child boxes.
fn superbox(uuid: &[u8; 16], label: &str, salt: Option<&[u8]>, children: &[Vec<u8>]) -> Vec<u8> {
    let mut p = jumd(uuid, label, salt);
    for c in children {
        p.extend_from_slice(c);
    }
    boxed(b"jumb", &p)
}

/// A `uuid` content box: 16-byte UUID prefix + data (used for signatures and
/// UUID assertions).
fn uuid_content(uuid: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(uuid);
    d.extend_from_slice(data);
    boxed(b"uuid", &d)
}

/// An embedded-file description (`bfdb`) box: toggle + NUL-terminated media type
/// (+ optional NUL-terminated file name when `toggle == 1`).
fn bfdb(media_type: &str, file_name: Option<&str>) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(if file_name.is_some() { 1 } else { 0 });
    p.extend_from_slice(media_type.as_bytes());
    p.push(0);
    if let Some(name) = file_name {
        p.extend_from_slice(name.as_bytes());
        p.push(0);
    }
    boxed(b"bfdb", &p)
}

/// An embedded-file data (`bidb`) box.
fn bidb(data: &[u8]) -> Vec<u8> {
    boxed(b"bidb", data)
}

/// Wrap an assertion superbox in an otherwise-minimal valid store.
fn store_with_assertion(assertion: Vec<u8>) -> Vec<u8> {
    let claim = superbox(
        &uuids::CLAIM,
        "c2pa.claim",
        None,
        &[boxed(b"cbor", &[0xA0])],
    );
    let assertions = superbox(
        &uuids::ASSERTION_STORE,
        "c2pa.assertions",
        None,
        &[assertion],
    );
    let manifest = superbox(
        &uuids::MANIFEST,
        "urn:c2pa:test",
        None,
        &[claim, assertions],
    );
    superbox(&uuids::MANIFEST_STORE, "c2pa", None, &[manifest])
}

const COSE: &[u8] = &[0xD2, 0x84, 0x40, 0xA0]; // stand-in COSE_Sign1 bytes
const SALT: &[u8] = &[7u8; 16];

/// A complete, minimal, valid manifest store with one standard manifest.
fn sample_store() -> Vec<u8> {
    let claim = superbox(
        &uuids::CLAIM,
        "c2pa.claim.v2",
        None,
        &[boxed(b"cbor", &[0xA0])],
    );
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
        &[assertion],
    );
    // Real manifests store the COSE_Sign1 directly in a `cbor` box.
    let signature = superbox(
        &uuids::SIGNATURE,
        "c2pa.signature",
        None,
        &[boxed(b"cbor", COSE)],
    );
    let manifest = superbox(
        &uuids::MANIFEST,
        "urn:c2pa:test-manifest",
        None,
        &[claim, assertions, signature],
    );
    superbox(&uuids::MANIFEST_STORE, "c2pa", None, &[manifest])
}

#[test]
fn parses_valid_store() {
    let bytes = sample_store();
    let store = ManifestStore::parse(&bytes).expect("parse");

    assert_eq!(store.manifests().count(), 1);
    let m = store.active_manifest().expect("active manifest");
    assert_eq!(m.label(), Some("urn:c2pa:test-manifest"));
    assert_eq!(m.kind(), ManifestKind::Standard);
    assert_eq!(m.claim_cbor().unwrap(), &[0xA0]);

    // Signature UUID prefix is stripped, leaving the COSE bytes.
    assert_eq!(m.signature_cose().unwrap(), COSE);

    let assertions: Vec<_> = m.assertions().unwrap().collect();
    assert_eq!(assertions.len(), 1);
    assert_eq!(assertions[0].label(), Some("c2pa.hash.data"));
    assert_eq!(assertions[0].content_type(), ContentType::Cbor);
    let data = assertions[0].payload().unwrap();
    assert_eq!(data.content_type, ContentType::Cbor);
    assert_eq!(data.data, &[0xA1, 0x00, 0x01]);
}

#[test]
fn legacy_uuid_signature_box_is_stripped() {
    // Legacy form: signature in a `uuid` content box with a 16-byte UUID prefix.
    let claim = superbox(
        &uuids::CLAIM,
        "c2pa.claim",
        None,
        &[boxed(b"cbor", &[0xA0])],
    );
    let signature = superbox(
        &uuids::SIGNATURE,
        "c2pa.signature",
        None,
        &[uuid_content(&uuids::SIGNATURE, COSE)],
    );
    let manifest = superbox(
        &uuids::MANIFEST,
        "urn:c2pa:legacy",
        None,
        &[claim, signature],
    );
    let bytes = superbox(&uuids::MANIFEST_STORE, "c2pa", None, &[manifest]);
    let store = ManifestStore::parse(&bytes).unwrap();
    assert_eq!(
        store.active_manifest().unwrap().signature_cose().unwrap(),
        COSE
    );
}

#[test]
fn reads_assertion_and_manifest_salt() {
    let bytes = sample_store();
    let store = ManifestStore::parse(&bytes).unwrap();
    let m = store.active_manifest().unwrap();
    let a = m.assertions().unwrap().next().unwrap();
    assert_eq!(a.salt(), Some(SALT));
    assert_eq!(a.payload().unwrap().salt, Some(SALT));
    // The manifest itself carried no salt in this fixture.
    assert_eq!(m.salt(), None);
}

#[test]
fn manifest_with_salt_round_trips() {
    let claim = superbox(
        &uuids::CLAIM,
        "c2pa.claim",
        None,
        &[boxed(b"cbor", &[0xA0])],
    );
    let assertions = superbox(&uuids::ASSERTION_STORE, "c2pa.assertions", None, &[]);
    let signature = superbox(
        &uuids::SIGNATURE,
        "c2pa.signature",
        None,
        &[uuid_content(&uuids::SIGNATURE, COSE)],
    );
    let manifest = superbox(
        &uuids::MANIFEST,
        "urn:c2pa:salted",
        Some(SALT),
        &[claim, assertions, signature],
    );
    let bytes = superbox(&uuids::MANIFEST_STORE, "c2pa", None, &[manifest]);

    let store = ManifestStore::parse(&bytes).unwrap();
    let m = store.active_manifest().unwrap();
    assert_eq!(m.salt(), Some(SALT));
    assert_eq!(m.claim_cbor().unwrap(), &[0xA0]);
}

#[test]
fn classifies_uuid_assertion() {
    let uuid_val = [0xABu8; 16];
    let assertion = superbox(
        &uuids::UUID,
        "org.example.thing",
        None,
        &[uuid_content(&uuid_val, &[1, 2, 3])],
    );
    let assertions = superbox(
        &uuids::ASSERTION_STORE,
        "c2pa.assertions",
        None,
        &[assertion],
    );
    let claim = superbox(
        &uuids::CLAIM,
        "c2pa.claim",
        None,
        &[boxed(b"cbor", &[0xA0])],
    );
    let manifest = superbox(
        &uuids::MANIFEST,
        "urn:c2pa:test",
        None,
        &[claim, assertions],
    );
    let bytes = superbox(&uuids::MANIFEST_STORE, "c2pa", None, &[manifest]);

    let store = ManifestStore::parse(&bytes).unwrap();
    let a = store
        .active_manifest()
        .unwrap()
        .assertions()
        .unwrap()
        .next()
        .unwrap();
    assert_eq!(a.content_type(), ContentType::Uuid);
    let data = a.payload().unwrap();
    assert_eq!(data.uuid, Some(uuid_val));
    assert_eq!(data.data, &[1, 2, 3]);
}

#[test]
fn classifies_json_assertion() {
    // JSON-LD rides on the plain `json` content box; its `@context`/`@type`
    // structure is opaque to this crate either way.
    let json_ld = br#"{"@context":"http://schema.org/","@type":"CreativeWork"}"#;
    let assertion = superbox(
        &uuids::JSON,
        "org.example.json-ld",
        None,
        &[boxed(b"json", json_ld)],
    );
    let bytes = store_with_assertion(assertion);

    let store = ManifestStore::parse(&bytes).unwrap();
    let a = store
        .active_manifest()
        .unwrap()
        .assertions()
        .unwrap()
        .next()
        .unwrap();
    assert_eq!(a.content_type(), ContentType::Json);
    let data = a.payload().unwrap();
    assert_eq!(data.data, json_ld);
}

#[test]
fn classifies_update_manifest() {
    let claim = superbox(
        &uuids::CLAIM,
        "c2pa.claim",
        None,
        &[boxed(b"cbor", &[0xA0])],
    );
    let manifest = superbox(&uuids::UPDATE_MANIFEST, "urn:c2pa:upd", None, &[claim]);
    let bytes = superbox(&uuids::MANIFEST_STORE, "c2pa", None, &[manifest]);
    let store = ManifestStore::parse(&bytes).unwrap();
    assert_eq!(
        store.active_manifest().unwrap().kind(),
        ManifestKind::Update
    );
}

#[test]
fn classifies_embedded_file_assertion() {
    let jpeg = &[0xFF, 0xD8, 0xFF, 0xE0];
    let assertion = superbox(
        &uuids::EMBEDDED_FILE,
        "c2pa.thumbnail.claim.jpeg",
        None,
        &[bfdb("image/jpeg", None), bidb(jpeg)],
    );
    let bytes = store_with_assertion(assertion);

    let store = ManifestStore::parse(&bytes).unwrap();
    let a = store
        .active_manifest()
        .unwrap()
        .assertions()
        .unwrap()
        .next()
        .unwrap();
    assert_eq!(a.content_type(), ContentType::EmbeddedFile);
    let data = a.payload().unwrap();
    assert_eq!(data.data, jpeg);
    assert_eq!(data.media_type, Some("image/jpeg"));
    assert_eq!(data.file_name, None);
}

#[test]
fn embedded_file_with_file_name() {
    let assertion = superbox(
        &uuids::EMBEDDED_FILE,
        "c2pa.thumbnail.claim.jpeg",
        None,
        &[bfdb("image/png", Some("thumb.png")), bidb(&[1, 2, 3])],
    );
    let bytes = store_with_assertion(assertion);
    let store = ManifestStore::parse(&bytes).unwrap();
    let a = store
        .active_manifest()
        .unwrap()
        .assertions()
        .unwrap()
        .next()
        .unwrap();
    let data = a.payload().unwrap();
    assert_eq!(data.media_type, Some("image/png"));
    assert_eq!(data.file_name, Some("thumb.png"));
    assert_eq!(data.data, &[1, 2, 3]);
}

#[test]
fn label_consistency_passes_on_valid_store() {
    let bytes = sample_store();
    let store = ManifestStore::parse(&bytes).unwrap();
    assert_eq!(store.verify_label_consistency(), Ok(()));
}

#[test]
fn label_consistency_detects_spoofed_claim() {
    // A box labeled "c2pa.claim" but carrying the CBOR content-type UUID.
    let fake_claim = superbox(&uuids::CBOR, "c2pa.claim", None, &[boxed(b"cbor", &[0xA0])]);
    let assertions = superbox(&uuids::ASSERTION_STORE, "c2pa.assertions", None, &[]);
    let manifest = superbox(
        &uuids::MANIFEST,
        "urn:c2pa:test",
        None,
        &[fake_claim, assertions],
    );
    let bytes = superbox(&uuids::MANIFEST_STORE, "c2pa", None, &[manifest]);

    let store = ManifestStore::parse(&bytes).unwrap(); // lenient parse still succeeds
    assert_eq!(
        store.verify_label_consistency().unwrap_err(),
        Error::LabelUuidMismatch
    );
}

#[test]
fn label_consistency_detects_misplaced_reserved_label() {
    // A real assertion-store UUID but wearing the signature label.
    let bad = superbox(&uuids::ASSERTION_STORE, "c2pa.signature", None, &[]);
    let manifest = superbox(&uuids::MANIFEST, "urn:c2pa:test", None, &[bad]);
    let bytes = superbox(&uuids::MANIFEST_STORE, "c2pa", None, &[manifest]);
    let store = ManifestStore::parse(&bytes).unwrap();
    assert_eq!(
        store.verify_label_consistency().unwrap_err(),
        Error::LabelUuidMismatch
    );
}

#[test]
fn borrowed_slices_point_into_input() {
    let bytes = sample_store();
    let store = ManifestStore::parse(&bytes).expect("parse");
    let claim = store.active_manifest().unwrap().claim_cbor().unwrap();
    let base = bytes.as_ptr() as usize;
    let claim_ptr = claim.as_ptr() as usize;
    assert!(claim_ptr >= base && claim_ptr < base + bytes.len());
}

#[test]
fn rejects_wrong_store_uuid() {
    // Correct label "c2pa" but wrong content-type UUID must be rejected.
    let bytes = superbox(&uuids::MANIFEST, "c2pa", None, &[]);
    assert_eq!(
        ManifestStore::parse(&bytes).unwrap_err(),
        Error::NotAManifestStore
    );
}

#[test]
fn rejects_non_superbox() {
    let bytes = boxed(b"cbor", &[0xA0]);
    assert_eq!(
        ManifestStore::parse(&bytes).unwrap_err(),
        Error::NotASuperbox
    );
}

#[test]
fn rejects_truncated_input() {
    let mut bytes = sample_store();
    bytes.truncate(bytes.len() - 4);
    assert!(ManifestStore::parse(&bytes).is_err());
}

#[test]
fn rejects_trailing_bytes() {
    let mut bytes = sample_store();
    bytes.extend_from_slice(&[0xFF, 0xFF]);
    assert_eq!(
        ManifestStore::parse(&bytes).unwrap_err(),
        Error::TrailingBytes
    );
}

#[test]
fn rejects_box_length_smaller_than_header() {
    let bytes = [0, 0, 0, 4, b'j', b'u', b'm', b'b'];
    assert_eq!(
        ManifestStore::parse(&bytes).unwrap_err(),
        Error::InvalidBoxLength
    );
}

#[test]
fn enforces_depth_limit() {
    let bytes = sample_store();
    let limits = Limits {
        max_depth: 1,
        ..Limits::DEFAULT
    };
    assert_eq!(
        ManifestStore::parse_with_limits(&bytes, &limits).unwrap_err(),
        Error::DepthExceeded
    );
}

#[test]
fn enforces_box_budget() {
    let bytes = sample_store();
    let limits = Limits {
        max_total_boxes: 2,
        ..Limits::DEFAULT
    };
    assert_eq!(
        ManifestStore::parse_with_limits(&bytes, &limits).unwrap_err(),
        Error::BoxBudgetExceeded
    );
}

#[test]
fn enforces_input_size_limit() {
    let bytes = sample_store();
    let limits = Limits {
        max_total_len: 4,
        ..Limits::DEFAULT
    };
    assert_eq!(
        ManifestStore::parse_with_limits(&bytes, &limits).unwrap_err(),
        Error::InputTooLarge
    );
}

#[test]
fn jumbf_uri_absolute_vs_relative() {
    let abs = JumbfUri::parse("self#jumbf=/c2pa/urn:c2pa:test/c2pa.assertions/label").unwrap();
    assert!(abs.is_absolute());
    assert_eq!(
        abs.segments().collect::<Vec<_>>(),
        vec!["c2pa", "urn:c2pa:test", "c2pa.assertions", "label"]
    );

    let rel = JumbfUri::parse("self#jumbf=c2pa.assertions/label").unwrap();
    assert!(!rel.is_absolute());
    assert_eq!(
        rel.segments().collect::<Vec<_>>(),
        vec!["c2pa.assertions", "label"]
    );
}

#[test]
fn jumbf_uri_rejects_missing_prefix_empty_path_and_dotdot() {
    assert_eq!(
        JumbfUri::parse("c2pa.assertions/label").unwrap_err(),
        Error::NotAJumbfUri
    );
    assert_eq!(
        JumbfUri::parse("self#jumbf=").unwrap_err(),
        Error::InvalidJumbfUri
    );
    assert_eq!(
        JumbfUri::parse("self#jumbf=/c2pa/../c2pa.assertions").unwrap_err(),
        Error::InvalidJumbfUri
    );
}

#[test]
fn resolves_relative_jumbf_uri_to_assertion() {
    let bytes = sample_store();
    let store = ManifestStore::parse(&bytes).unwrap();
    let m = store.active_manifest().unwrap();

    let uri = JumbfUri::parse("self#jumbf=c2pa.assertions/c2pa.hash.data").unwrap();
    let target = store.resolve(&uri, &m).unwrap();
    assert_eq!(target.label(), Some("c2pa.hash.data"));
    assert_eq!(target.content_type(), ContentType::Cbor);
    assert_eq!(target.salt(), Some(SALT));
}

#[test]
fn resolves_absolute_jumbf_uri_to_assertion() {
    let bytes = sample_store();
    let store = ManifestStore::parse(&bytes).unwrap();
    let m = store.active_manifest().unwrap();

    let uri =
        JumbfUri::parse("self#jumbf=/c2pa/urn:c2pa:test-manifest/c2pa.assertions/c2pa.hash.data")
            .unwrap();
    let target = store.resolve(&uri, &m).unwrap();
    assert_eq!(target.label(), Some("c2pa.hash.data"));
}

#[test]
fn resolves_absolute_uri_to_manifest_itself() {
    // An absolute URI with no path beyond the manifest label resolves to the
    // manifest superbox itself.
    let bytes = sample_store();
    let store = ManifestStore::parse(&bytes).unwrap();
    let m = store.active_manifest().unwrap();

    let uri = JumbfUri::parse("self#jumbf=/c2pa/urn:c2pa:test-manifest").unwrap();
    let target = store.resolve(&uri, &m).unwrap();
    assert_eq!(target.label(), Some("urn:c2pa:test-manifest"));
    assert_eq!(target.content_type(), ContentType::Manifest);
}

#[test]
fn resolves_relative_and_absolute_uri_to_signature() {
    let bytes = sample_store();
    let store = ManifestStore::parse(&bytes).unwrap();
    let m = store.active_manifest().unwrap();

    let rel = JumbfUri::parse("self#jumbf=c2pa.signature").unwrap();
    let target = store.resolve(&rel, &m).unwrap();
    assert_eq!(target.content_type(), ContentType::Signature);

    let abs = JumbfUri::parse("self#jumbf=/c2pa/urn:c2pa:test-manifest/c2pa.signature").unwrap();
    let target = store.resolve(&abs, &m).unwrap();
    assert_eq!(target.content_type(), ContentType::Signature);
}

#[test]
fn resolves_relative_and_absolute_uri_to_assertion_store() {
    let bytes = sample_store();
    let store = ManifestStore::parse(&bytes).unwrap();
    let m = store.active_manifest().unwrap();

    let rel = JumbfUri::parse("self#jumbf=c2pa.assertions").unwrap();
    let target = store.resolve(&rel, &m).unwrap();
    assert_eq!(target.content_type(), ContentType::AssertionStore);

    let abs = JumbfUri::parse("self#jumbf=/c2pa/urn:c2pa:test-manifest/c2pa.assertions").unwrap();
    let target = store.resolve(&abs, &m).unwrap();
    assert_eq!(target.content_type(), ContentType::AssertionStore);
}

#[test]
fn resolve_reports_unresolved_uri() {
    let bytes = sample_store();
    let store = ManifestStore::parse(&bytes).unwrap();
    let m = store.active_manifest().unwrap();

    let missing_segment = JumbfUri::parse("self#jumbf=c2pa.assertions/c2pa.nonexistent").unwrap();
    assert_eq!(
        store.resolve(&missing_segment, &m).unwrap_err(),
        Error::UnresolvedUri
    );

    let missing_manifest =
        JumbfUri::parse("self#jumbf=/c2pa/urn:c2pa:no-such-manifest/c2pa.assertions").unwrap();
    assert_eq!(
        store.resolve(&missing_manifest, &m).unwrap_err(),
        Error::UnresolvedUri
    );
}

#[test]
fn missing_claim_is_reported() {
    let assertions = superbox(&uuids::ASSERTION_STORE, "c2pa.assertions", None, &[]);
    let manifest = superbox(&uuids::MANIFEST, "urn:c2pa:test", None, &[assertions]);
    let bytes = superbox(&uuids::MANIFEST_STORE, "c2pa", None, &[manifest]);
    let store = ManifestStore::parse(&bytes).unwrap();
    assert_eq!(
        store.active_manifest().unwrap().claim_cbor(),
        Err(Error::MissingClaim)
    );
}
