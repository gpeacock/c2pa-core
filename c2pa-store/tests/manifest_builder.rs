//! Tests for `ManifestStoreBuilder`: correctness of the assertions it hashes
//! and writes, streaming vs. in-memory parity, and misuse errors.
#![cfg(all(feature = "write", feature = "std"))]

use std::io::Cursor;

use c2pa_store::{ContentType, Error, JumbfUri, ManifestStore, ManifestStoreBuilder};
use sha2::{Digest, Sha256};

const SALT: &[u8] = &[9u8; 16];

#[test]
fn builds_a_store_that_round_trips_and_hashes_match_payload() {
    let mut builder = ManifestStoreBuilder::new(Vec::<u8>::new(), "urn:c2pa:test").unwrap();

    let cbor = builder
        .add_cbor_assertion("c2pa.hash.data", Some(SALT), &[0xA1, 0x00, 0x01])
        .unwrap();
    let icon = builder
        .add_embedded_file_assertion(
            "com.example.icon",
            Some(SALT),
            "image/svg+xml",
            None,
            b"<svg/>",
        )
        .unwrap();

    assert_eq!(cbor.url, "self#jumbf=c2pa.assertions/c2pa.hash.data");
    assert_eq!(cbor.alg, "sha256");
    assert_eq!(icon.url, "self#jumbf=c2pa.assertions/com.example.icon");

    builder.add_claim("c2pa.claim.v2", &[0xA0]).unwrap();
    let bytes = builder.finish().unwrap();

    let store = ManifestStore::parse(&bytes).unwrap();
    assert_eq!(store.verify_label_consistency(), Ok(()));
    let manifest = store.active_manifest().unwrap();
    assert_eq!(manifest.label(), Some("urn:c2pa:test"));
    assert_eq!(manifest.claim_cbor().unwrap(), &[0xA0]);

    let assertions: Vec<_> = manifest.assertions().unwrap().collect();
    assert_eq!(assertions.len(), 2);

    let cbor_assertion = assertions
        .iter()
        .find(|a| a.label() == Some("c2pa.hash.data"))
        .unwrap();
    assert_eq!(cbor_assertion.payload().unwrap().data, &[0xA1, 0x00, 0x01]);

    let icon_assertion = assertions
        .iter()
        .find(|a| a.label() == Some("com.example.icon"))
        .unwrap();
    let icon_data = icon_assertion.payload().unwrap();
    assert_eq!(icon_data.content_type, ContentType::EmbeddedFile);
    assert_eq!(icon_data.media_type, Some("image/svg+xml"));
    assert_eq!(icon_data.file_name, None);
    assert_eq!(icon_data.data, b"<svg/>");

    // Independently recompute each hash from the resolved box's raw payload
    // (the same span `HashedUri::verify` would hash), to confirm the digest
    // `ManifestStoreBuilder` handed back matches what's actually on the wire.
    for hash in [&cbor, &icon] {
        let uri = JumbfUri::parse(&hash.url).unwrap();
        let target = store.resolve(&uri, &manifest).unwrap();
        assert_eq!(Sha256::digest(target.payload()).to_vec(), hash.hash);
    }
}

#[test]
fn from_reader_matches_in_memory_for_the_same_bytes() {
    let data = b"some file bytes, streamed";

    let mut a = ManifestStoreBuilder::new(Vec::<u8>::new(), "urn:c2pa:test").unwrap();
    let hash_a = a
        .add_embedded_file_assertion(
            "c2pa.thumbnail.ingredient",
            Some(SALT),
            "image/jpeg",
            None,
            data,
        )
        .unwrap();
    a.add_claim("c2pa.claim.v2", &[0xA0]).unwrap();
    let bytes_a = a.finish().unwrap();

    let mut b = ManifestStoreBuilder::new(Vec::<u8>::new(), "urn:c2pa:test").unwrap();
    let hash_b = b
        .add_embedded_file_assertion_from_reader(
            "c2pa.thumbnail.ingredient",
            Some(SALT),
            "image/jpeg",
            None,
            data.len() as u64,
            Cursor::new(data),
        )
        .unwrap();
    b.add_claim("c2pa.claim.v2", &[0xA0]).unwrap();
    let bytes_b = b.finish().unwrap();

    assert_eq!(hash_a, hash_b);
    assert_eq!(bytes_a, bytes_b);
}

#[test]
fn from_reader_rejects_a_length_mismatch() {
    let mut builder = ManifestStoreBuilder::new(Vec::<u8>::new(), "urn:c2pa:test").unwrap();
    let data = b"twelve bytes";
    let result = builder.add_embedded_file_assertion_from_reader(
        "c2pa.thumbnail.ingredient",
        None,
        "image/jpeg",
        None,
        data.len() as u64 + 1,
        Cursor::new(data),
    );
    assert_eq!(result, Err(Error::LengthMismatch));
}

#[test]
fn streaming_writer_matches_in_memory_for_the_same_bytes() {
    let data = b"some file bytes, streamed one piece at a time";

    let mut a = ManifestStoreBuilder::new(Vec::<u8>::new(), "urn:c2pa:test").unwrap();
    let hash_a = a
        .add_embedded_file_assertion(
            "c2pa.thumbnail.ingredient",
            Some(SALT),
            "image/jpeg",
            None,
            data,
        )
        .unwrap();
    a.add_claim("c2pa.claim.v2", &[0xA0]).unwrap();
    let bytes_a = a.finish().unwrap();

    let b = ManifestStoreBuilder::new(Vec::<u8>::new(), "urn:c2pa:test").unwrap();
    let mut writer = b
        .begin_embedded_file_assertion(
            "c2pa.thumbnail.ingredient",
            Some(SALT),
            "image/jpeg",
            None,
            data.len() as u64,
        )
        .unwrap();

    // Simulate a paused/resumed, chunk-at-a-time source: some chunks land
    // together, some arrive one byte at a time, and progress is checked
    // between them.
    assert_eq!(writer.total_len(), data.len() as u64);
    let mut expected_written = 0u64;
    for chunk in [&data[..10], &data[10..11], &data[11..]] {
        writer.write_chunk(chunk).unwrap();
        expected_written += chunk.len() as u64;
        assert_eq!(writer.bytes_written(), expected_written);
    }
    let (mut b, hash_b) = writer.finish().unwrap();
    b.add_claim("c2pa.claim.v2", &[0xA0]).unwrap();
    let bytes_b = b.finish().unwrap();

    assert_eq!(hash_a, hash_b);
    assert_eq!(bytes_a, bytes_b);
}

#[test]
fn streaming_writer_reports_progress_and_rejects_overrun() {
    let data = b"twelve bytes";
    let builder = ManifestStoreBuilder::new(Vec::<u8>::new(), "urn:c2pa:test").unwrap();
    let mut writer = builder
        .begin_embedded_file_assertion(
            "c2pa.thumbnail.ingredient",
            None,
            "image/jpeg",
            None,
            data.len() as u64,
        )
        .unwrap();

    assert_eq!(writer.bytes_written(), 0);
    writer.write_chunk(&data[..5]).unwrap();
    assert_eq!(writer.bytes_written(), 5);
    writer.write_chunk(&data[5..]).unwrap();
    assert_eq!(writer.bytes_written(), data.len() as u64);

    // One byte over the declared length is rejected rather than silently
    // accepted, so `bidb`'s already-hashed header can never be wrong.
    let err = writer.write_chunk(b"!").unwrap_err();
    assert_eq!(err, Error::LengthMismatch);
}

#[test]
fn streaming_writer_rejects_finish_before_all_bytes_written() {
    let builder = ManifestStoreBuilder::new(Vec::<u8>::new(), "urn:c2pa:test").unwrap();
    let mut writer = builder
        .begin_embedded_file_assertion("c2pa.thumbnail.ingredient", None, "image/jpeg", None, 12)
        .unwrap();
    writer.write_chunk(b"not enough").unwrap();

    let err = writer.finish().unwrap_err();
    assert_eq!(err, Error::LengthMismatch);
}

#[test]
fn streaming_writer_cancel_compiles_and_drops_cleanly() {
    let builder = ManifestStoreBuilder::new(Vec::<u8>::new(), "urn:c2pa:test").unwrap();
    let mut writer = builder
        .begin_embedded_file_assertion("c2pa.thumbnail.ingredient", None, "image/jpeg", None, 12)
        .unwrap();
    writer.write_chunk(b"partial").unwrap();
    writer.cancel(); // discards the builder; nothing left to assert on
}

#[test]
fn rejects_assertions_added_after_the_claim() {
    let mut builder = ManifestStoreBuilder::new(Vec::<u8>::new(), "urn:c2pa:test").unwrap();
    builder.add_claim("c2pa.claim.v2", &[0xA0]).unwrap();

    let result = builder.add_cbor_assertion("too.late", None, &[0xA0]);
    assert_eq!(result, Err(Error::AssertionsAlreadyFinalized));
}
