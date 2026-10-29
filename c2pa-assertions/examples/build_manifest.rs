//! Build a manifest with the plain, sequential procedural API -- no
//! dependency graph, no handles -- using `c2pa_store::ManifestStoreBuilder`
//! for all the JUMBF box construction.
//!
//! Usage: `cargo run --example build_manifest`
//!
//! Each assertion's `HashedUri` is a local variable, produced in source
//! order; `ingredient` borrows `thumbnail`'s `HashedUri` directly, which is
//! only possible because `thumbnail` was already built. The borrow checker
//! already makes a forward reference (and therefore a cycle) impossible --
//! there is no handle indirection to manage because nothing needs it.
//!
//! `actions` and `data_hash` are real assertion types (not toys): a
//! `c2pa.actions.v2` assertion with a `c2pa.created` action, and a
//! `c2pa.hash.data` hard binding over the asset's bytes -- read here from an
//! in-memory placeholder standing in for a real asset file, which
//! `DataHash::from_reader` would just as happily stream from
//! `std::fs::File::open(path)`.
//!
//! `ManifestStoreBuilder` owns all knowledge of *how* JUMBF boxes are laid
//! out (store/manifest/assertion-store nesting, content-type UUIDs, the
//! `bfdb`/`bidb` embedded-file shape) *and* hashes each assertion as it
//! writes it, returning an `AssertionHash` (url + alg + digest) immediately
//! -- not deferred to the end -- because a later assertion (like
//! `ingredient` below) needs to embed an earlier one's hash before it can be
//! serialized. This crate just converts each `AssertionHash` into a real
//! `HashedUri`.
//!
//! Embedded-file data is accepted as `impl std::io::Read` and streamed
//! through in chunks, so a large asset (a real thumbnail, say) never has to
//! be fully in memory -- passing a `&[u8]` (as below) works too, since
//! slices already implement `Read`.

use std::io::Cursor;
use std::process::ExitCode;

use c2pa_assertions::{Action, Actions, Assertion, DataHash};
use c2pa_claim::{Claim, GeneratorInfo, HashedUri};
use c2pa_store::{AssertionHash, ManifestStore, ManifestStoreBuilder};
use serde::Serialize;

/// Stand-in for a real asset's bytes -- in practice, hand `DataHash::from_reader`
/// a `std::fs::File::open(path)?` instead.
const ASSET: &[u8] = b"pretend this is the whole image file's bytes";

const MANIFEST_LABEL: &str = "urn:c2pa:demo-manifest";

/// Convert a `ManifestStoreBuilder` result into the `HashedUri` a later
/// assertion or the claim can reference.
fn hashed_uri(a: AssertionHash) -> HashedUri {
    HashedUri::new(a.url, Some(a.alg.to_string()), &a.hash)
}

fn main() -> ExitCode {
    let mut builder = ManifestStoreBuilder::new(Vec::<u8>::new(), MANIFEST_LABEL).unwrap();

    // Two independent leaves, each an embedded-file assertion. A real salt
    // would be random per assertion; fixed bytes are enough to demonstrate
    // the shape.
    let icon_href = hashed_uri(
        builder
            .add_embedded_file_assertion(
                "com.example.icon",
                Some(&[1u8; 16]),
                "image/svg+xml",
                None,
                b"<svg>...</svg>",
            )
            .unwrap(),
    );

    let thumb_href = hashed_uri(
        builder
            .add_embedded_file_assertion(
                "c2pa.thumbnail.ingredient",
                Some(&[2u8; 16]),
                "image/jpeg",
                Some("thumbnail.jpg"),
                b"\xFF\xD8\xFF...(jpeg bytes)",
            )
            .unwrap(),
    );

    // One dependency: embeds the thumbnail's HashedUri directly -- no
    // handle, just a borrow of the variable built two steps above.
    #[derive(Serialize)]
    struct ToyIngredient<'a> {
        thumbnail: &'a HashedUri,
    }
    let ingredient_cbor = c2pa_cbor::to_vec_deterministic(&ToyIngredient {
        thumbnail: &thumb_href,
    })
    .unwrap();
    let ingredient_href = hashed_uri(
        builder
            .add_cbor_assertion("c2pa.ingredient.v3", Some(&[3u8; 16]), &ingredient_cbor)
            .unwrap(),
    );

    // A real `c2pa.actions.v2` assertion: a single `c2pa.created` action.
    let mut actions = Actions::new();
    actions.add_action(
        Action::new(Action::CREATED).with_digital_source_type(Action::DIGITAL_SOURCE_TYPE_EMPTY),
    );
    let actions_cbor = actions.to_cbor().unwrap();
    let actions_href = hashed_uri(
        builder
            .add_cbor_assertion(Actions::LABEL, Some(&[4u8; 16]), &actions_cbor)
            .unwrap(),
    );

    // The hard binding: a real `c2pa.hash.data` assertion over the asset's
    // bytes. No exclusions -- this is a sidecar/remote manifest, so there's
    // nothing of its own embedded in the asset to exclude.
    let data_hash = DataHash::from_reader("sha256", Cursor::new(ASSET)).unwrap();
    let data_hash_cbor = data_hash.to_cbor().unwrap();
    let data_hash_href = hashed_uri(
        builder
            .add_cbor_assertion(DataHash::LABEL, Some(&[5u8; 16]), &data_hash_cbor)
            .unwrap(),
    );

    let mut generator_info = GeneratorInfo::new("build-manifest-demo");
    generator_info.icon = Some(icon_href.clone());

    let mut claim = Claim::new(MANIFEST_LABEL, "xmp:iid:demo-instance", generator_info);
    // Every hashed URI already carries its own `alg`; this is just the
    // claim-level default, and must match what `ManifestStoreBuilder`
    // actually used (currently always SHA-256).
    claim.alg = Some("sha256".to_string());
    claim.add_created_assertion(thumb_href);
    claim.add_created_assertion(icon_href);
    claim.add_created_assertion(ingredient_href);
    claim.add_created_assertion(data_hash_href);
    claim.add_created_assertion(actions_href);
    let claim_cbor = claim.to_cbor().unwrap();

    builder.add_claim("c2pa.claim.v2", &claim_cbor).unwrap();
    let store_bytes = builder.finish().unwrap();
    println!("built store: {} bytes", store_bytes.len());

    // Re-parse from scratch and verify every hashed URI the normal way.
    let store = ManifestStore::parse(&store_bytes).unwrap();
    let manifest = store.active_manifest().unwrap();
    let claim = Claim::from_cbor(manifest.claim_cbor().unwrap()).unwrap();

    let mut failures = 0;
    for href in &claim.created_assertions {
        match href.verify(&store, &manifest, claim.alg.as_deref()) {
            Ok(()) => println!("ok   {}", href.url()),
            Err(e) => {
                println!("FAIL {} -> {e:?}", href.url());
                failures += 1;
            }
        }
    }
    if let Some(icon_href) = &claim.claim_generator_info.icon {
        match icon_href.verify(&store, &manifest, claim.alg.as_deref()) {
            Ok(()) => println!("ok   [generator icon] {}", icon_href.url()),
            Err(e) => {
                println!("FAIL [generator icon] {} -> {e:?}", icon_href.url());
                failures += 1;
            }
        }
    }

    // Confirm the embedded-file assertions actually decode as embedded files
    // (media type + file name round-trip), not just as opaque hashed blobs.
    for a in manifest.assertions().unwrap() {
        if let Ok(data) = a.payload() {
            if let c2pa_store::ContentType::EmbeddedFile = data.content_type {
                println!(
                    "embedded file [{}]: media_type={:?}, file_name={:?}, {} bytes",
                    a.label().unwrap_or("<no label>"),
                    data.media_type,
                    data.file_name,
                    data.data.len()
                );
            }
        }
    }

    if failures == 0 {
        println!("\nall hashed URIs verified");
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
