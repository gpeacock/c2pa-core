//! C2PA / JUMBF content-type UUIDs and their classification.
//!
//! Every JUMBF description box (`jumd`) carries a 16-byte content-type UUID that
//! is the *authoritative* discriminator for what a box is (labels are for
//! identity, not type). These values mirror the constants in `c2pa-rs`
//! (`sdk/src/jumbf/boxes.rs`). We store them as raw byte arrays so classification
//! is a plain 16-byte compare — no hex decoding or allocation per parse.

/// Build a "fourcc" content-type UUID: 4 ASCII bytes + the fixed JUMBF suffix
/// `00 11 00 10 80 00 00 AA 00 38 9B 71`.
const fn fourcc(tag: [u8; 4]) -> [u8; 16] {
    [
        tag[0], tag[1], tag[2], tag[3], 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38,
        0x9B, 0x71,
    ]
}

// --- C2PA superbox content types ---

/// Manifest store (`c2pa`).
pub const MANIFEST_STORE: [u8; 16] = fourcc(*b"c2pa");
/// Standard manifest (`c2ma`).
pub const MANIFEST: [u8; 16] = fourcc(*b"c2ma");
/// Update manifest (`c2um`).
pub const UPDATE_MANIFEST: [u8; 16] = fourcc(*b"c2um");
/// Manifest variant (`c2md`).
pub const MANIFEST_C2MD: [u8; 16] = fourcc(*b"c2md");
/// Compressed (Brotli) manifest (`c2cm`).
pub const COMPRESSED_MANIFEST: [u8; 16] = fourcc(*b"c2cm");
/// Claim (`c2cl`).
pub const CLAIM: [u8; 16] = fourcc(*b"c2cl");
/// Claim signature (`c2cs`).
pub const SIGNATURE: [u8; 16] = fourcc(*b"c2cs");
/// Assertion store (`c2as`).
pub const ASSERTION_STORE: [u8; 16] = fourcc(*b"c2as");
/// Ingredient store (`cais`).
pub const INGREDIENT_STORE: [u8; 16] = fourcc(*b"cais");
/// Ingredient (`cain`).
pub const INGREDIENT: [u8; 16] = fourcc(*b"cain");
/// Verifiable-credentials store (`c2vc`).
pub const VC_STORE: [u8; 16] = fourcc(*b"c2vc");
/// Data-box store (`c2db`).
pub const DATABOX_STORE: [u8; 16] = fourcc(*b"c2db");

// --- JUMBF content (leaf) types ---

/// CBOR content (`cbor`). Also the content type of a CBOR assertion superbox.
pub const CBOR: [u8; 16] = fourcc(*b"cbor");
/// JSON content (`json`). Also the content type of a JSON assertion superbox.
pub const JSON: [u8; 16] = fourcc(*b"json");
/// UUID content (`uuid`). Also the content type of a UUID assertion superbox.
pub const UUID: [u8; 16] = fourcc(*b"uuid");
/// Brotli content (`brob`).
pub const BROTLI: [u8; 16] = fourcc(*b"brob");
/// Embedded-file description (`bfdb`).
pub const EMBEDDED_FILE_DESCRIPTION: [u8; 16] = fourcc(*b"bfdb");
/// Embedded-file data (`bidb`).
pub const EMBEDDED_FILE_DATA: [u8; 16] = fourcc(*b"bidb");

/// Embedded-file superbox (not a fourcc; a fixed UUID).
pub const EMBEDDED_FILE: [u8; 16] = [
    0x40, 0xCB, 0x0C, 0x32, 0xBB, 0x8A, 0x48, 0x9D, 0xA7, 0x0B, 0x2A, 0xD6, 0xF4, 0x7F, 0x43, 0x69,
];

/// JPEG 2000 codestream (not a fourcc; a fixed UUID).
pub const CODESTREAM: [u8; 16] = [
    0x65, 0x79, 0xD6, 0xFB, 0xDB, 0xA2, 0x44, 0x6B, 0xB2, 0xAC, 0x1B, 0x82, 0xFE, 0xEB, 0x89, 0xD1,
];

/// A classified JUMBF content type.
///
/// `Unknown` carries the raw UUID so callers can still inspect it. The enum is
/// `#[non_exhaustive]`; new known types can be added without a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentType {
    /// Manifest store (`c2pa`).
    ManifestStore,
    /// Standard manifest (`c2ma`).
    Manifest,
    /// Update manifest (`c2um`).
    UpdateManifest,
    /// Manifest variant (`c2md`).
    ManifestC2md,
    /// Compressed (Brotli) manifest (`c2cm`).
    CompressedManifest,
    /// Claim (`c2cl`).
    Claim,
    /// Claim signature (`c2cs`).
    Signature,
    /// Assertion store (`c2as`).
    AssertionStore,
    /// Ingredient store (`cais`).
    IngredientStore,
    /// Ingredient (`cain`).
    Ingredient,
    /// Verifiable-credentials store (`c2vc`).
    VcStore,
    /// Data-box store (`c2db`).
    DataboxStore,
    /// CBOR content / CBOR assertion.
    Cbor,
    /// JSON content / JSON assertion.
    Json,
    /// UUID content / UUID assertion.
    Uuid,
    /// Brotli content.
    Brotli,
    /// Embedded-file superbox.
    EmbeddedFile,
    /// Embedded-file description (`bfdb`).
    EmbeddedFileDescription,
    /// Embedded-file data (`bidb`).
    EmbeddedFileData,
    /// JPEG 2000 codestream.
    Codestream,
    /// An unrecognized content type.
    Unknown([u8; 16]),
}

/// Classify a 16-byte content-type UUID.
pub fn classify(uuid: &[u8; 16]) -> ContentType {
    let u = *uuid;
    if u == MANIFEST_STORE {
        ContentType::ManifestStore
    } else if u == MANIFEST {
        ContentType::Manifest
    } else if u == UPDATE_MANIFEST {
        ContentType::UpdateManifest
    } else if u == MANIFEST_C2MD {
        ContentType::ManifestC2md
    } else if u == COMPRESSED_MANIFEST {
        ContentType::CompressedManifest
    } else if u == CLAIM {
        ContentType::Claim
    } else if u == SIGNATURE {
        ContentType::Signature
    } else if u == ASSERTION_STORE {
        ContentType::AssertionStore
    } else if u == INGREDIENT_STORE {
        ContentType::IngredientStore
    } else if u == INGREDIENT {
        ContentType::Ingredient
    } else if u == VC_STORE {
        ContentType::VcStore
    } else if u == DATABOX_STORE {
        ContentType::DataboxStore
    } else if u == CBOR {
        ContentType::Cbor
    } else if u == JSON {
        ContentType::Json
    } else if u == UUID {
        ContentType::Uuid
    } else if u == BROTLI {
        ContentType::Brotli
    } else if u == EMBEDDED_FILE {
        ContentType::EmbeddedFile
    } else if u == EMBEDDED_FILE_DESCRIPTION {
        ContentType::EmbeddedFileDescription
    } else if u == EMBEDDED_FILE_DATA {
        ContentType::EmbeddedFileData
    } else if u == CODESTREAM {
        ContentType::Codestream
    } else {
        ContentType::Unknown(u)
    }
}
