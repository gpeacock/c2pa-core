//! Write-side round-trip tests: emit a manifest store with `BoxWriter`, then
//! parse it back with the reader and confirm the structure matches.
#![cfg(feature = "write")]

use c2pa_store::format::{BOX_BFDB, BOX_BIDB, BOX_CBOR};
use c2pa_store::{uuids, BoxWriter, ContentType, ManifestStore};

const COSE: &[u8] = &[0xD2, 0x84, 0x40, 0xA0];
const SALT: &[u8] = &[7u8; 16];

/// Build a full, valid manifest store using the streaming emitter.
fn write_sample() -> Vec<u8> {
    let mut w = BoxWriter::new(Vec::new());

    w.start_superbox(&uuids::MANIFEST_STORE, "c2pa", None)
        .unwrap();
    {
        w.start_superbox(&uuids::MANIFEST, "urn:c2pa:test", None)
            .unwrap();
        {
            // claim
            w.start_superbox(&uuids::CLAIM, "c2pa.claim.v2", None)
                .unwrap();
            w.content_box(&BOX_CBOR, &[0xA0]).unwrap();
            w.end_box().unwrap();

            // assertion store with one salted CBOR assertion
            w.start_superbox(&uuids::ASSERTION_STORE, "c2pa.assertions", None)
                .unwrap();
            {
                w.start_superbox(&uuids::CBOR, "c2pa.hash.data", Some(SALT))
                    .unwrap();
                w.content_box(&BOX_CBOR, &[0xA1, 0x00, 0x01]).unwrap();
                w.end_box().unwrap();
            }
            w.end_box().unwrap();

            // signature (COSE directly in a cbor box, as real manifests do)
            w.start_superbox(&uuids::SIGNATURE, "c2pa.signature", None)
                .unwrap();
            w.content_box(&BOX_CBOR, COSE).unwrap();
            w.end_box().unwrap();
        }
        w.end_box().unwrap();
    }
    w.end_box().unwrap();

    w.finish().unwrap()
}

#[test]
fn round_trips_through_reader() {
    let bytes = write_sample();

    let store = ManifestStore::parse(&bytes).expect("parse emitted store");
    assert_eq!(store.verify_label_consistency(), Ok(()));
    assert_eq!(store.manifests().count(), 1);

    let m = store.active_manifest().unwrap();
    assert_eq!(m.label(), Some("urn:c2pa:test"));
    assert_eq!(m.claim_cbor().unwrap(), &[0xA0]);
    assert_eq!(m.signature_cose().unwrap(), COSE);

    let a = m.assertions().unwrap().next().unwrap();
    assert_eq!(a.label(), Some("c2pa.hash.data"));
    assert_eq!(a.content_type(), ContentType::Cbor);
    assert_eq!(a.salt(), Some(SALT));
    assert_eq!(a.payload().unwrap().data, &[0xA1, 0x00, 0x01]);
}

#[test]
fn streams_embedded_file_in_chunks() {
    // The `bidb` data box is written incrementally via start_box/write/end_box,
    // exercising size backpatching on a streamed payload.
    let chunk1 = &[0xFFu8; 100];
    let chunk2 = &[0xEEu8; 156];

    let mut w = BoxWriter::new(Vec::new());
    w.start_superbox(&uuids::MANIFEST_STORE, "c2pa", None)
        .unwrap();
    w.start_superbox(&uuids::MANIFEST, "urn:c2pa:test", None)
        .unwrap();
    w.start_superbox(&uuids::CLAIM, "c2pa.claim", None).unwrap();
    w.content_box(&BOX_CBOR, &[0xA0]).unwrap();
    w.end_box().unwrap();
    w.start_superbox(&uuids::ASSERTION_STORE, "c2pa.assertions", None)
        .unwrap();
    {
        w.start_superbox(&uuids::EMBEDDED_FILE, "c2pa.thumbnail.claim.jpeg", None)
            .unwrap();
        // bfdb: toggle(0) + "image/jpeg" + NUL
        let mut bfdb = Vec::new();
        bfdb.push(0u8);
        bfdb.extend_from_slice(b"image/jpeg");
        bfdb.push(0);
        w.content_box(&BOX_BFDB, &bfdb).unwrap();
        // bidb: streamed in two chunks
        w.start_box(&BOX_BIDB).unwrap();
        w.write(chunk1).unwrap();
        w.write(chunk2).unwrap();
        w.end_box().unwrap();
        w.end_box().unwrap();
    }
    w.end_box().unwrap();
    w.end_box().unwrap();
    w.end_box().unwrap();
    let bytes = w.finish().unwrap();

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
    assert_eq!(data.media_type, Some("image/jpeg"));
    assert_eq!(data.data.len(), chunk1.len() + chunk2.len());
    assert_eq!(&data.data[..chunk1.len()], chunk1);
    assert_eq!(&data.data[chunk1.len()..], chunk2);
}

#[test]
fn unbalanced_end_is_an_error() {
    let mut w = BoxWriter::new(Vec::new());
    assert!(w.end_box().is_err());
}
