//! Tests for `ManifestStoreEditor`: a placeholder store completed in place is
//! identical to one built with the final values, and edits never change sizes.
#![cfg(feature = "write")]

use c2pa_store::{AssertionHash, Error, ManifestStoreBuilder, ManifestStoreEditor};

const LABEL: &str = "urn:c2pa:test";

/// A store with one CBOR assertion, a claim and a signature, plus the hash the
/// builder reported for the assertion.
fn build(assertion: &[u8], claim: &[u8], signature: &[u8]) -> (Vec<u8>, AssertionHash) {
    let mut builder = ManifestStoreBuilder::new(Vec::<u8>::new(), LABEL).unwrap();
    let hash = builder
        .add_cbor_assertion("c2pa.hash.data", Some(&[3; 16]), assertion)
        .unwrap();
    builder
        .add_cbor_assertion("c2pa.actions.v2", None, &[0xA0])
        .unwrap();
    builder.add_claim("c2pa.claim.v2", claim).unwrap();
    builder.add_signature(signature).unwrap();
    (builder.finish().unwrap(), hash)
}

#[test]
fn completing_a_placeholder_matches_building_with_the_final_values() {
    let (mut store, _) = build(&[0; 6], &[1; 10], &[2; 20]);
    let (expected, expected_hash) = build(&[9, 8, 7, 6, 5, 4], &[5; 10], &[6; 20]);

    let mut editor = ManifestStoreEditor::new(&mut store);
    let hash = editor
        .update_assertion(LABEL, "c2pa.hash.data", &[9, 8, 7, 6, 5, 4])
        .unwrap();
    editor.update_claim(LABEL, &[5; 10]).unwrap();
    editor.update_signature(LABEL, &[6; 20]).unwrap();

    assert_eq!(hash, expected_hash);
    assert_eq!(store, expected);
}

#[test]
fn edits_that_would_move_anything_are_refused() {
    let (mut store, _) = build(&[0; 6], &[1; 10], &[2; 20]);
    let original = store.clone();
    let mut editor = ManifestStoreEditor::new(&mut store);
    assert_eq!(
        editor.update_assertion(LABEL, "c2pa.hash.data", &[0; 7]),
        Err(Error::SizeChanged)
    );
    assert_eq!(editor.update_claim(LABEL, &[1; 9]), Err(Error::SizeChanged));
    assert_eq!(
        editor.update_signature(LABEL, &[2; 21]),
        Err(Error::SizeChanged)
    );
    assert_eq!(
        editor.update_assertion(LABEL, "c2pa.missing", &[0; 6]),
        Err(Error::UnresolvedUri)
    );
    assert_eq!(
        editor.update_claim("urn:c2pa:other", &[1; 10]),
        Err(Error::UnresolvedUri)
    );
    assert_eq!(store, original);
}
