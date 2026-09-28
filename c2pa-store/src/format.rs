//! Shared JUMBF wire-format definitions used by both the reader and the writer.
//!
//! These are the facts about how a JUMBF box is laid out on the wire. Keeping
//! them in one place means the parser and emitter can never disagree (e.g. on
//! which toggle bit means "salt present"). Everything here is `const` data, so
//! it costs nothing in a read-only build.

/// Base box header size: `LBox` (4) + `TBox` (4).
pub const HDR_BASE: usize = 8;
/// Extended box header size: base + `XLBox` (8), used when `LBox == 1`.
pub const HDR_XL: usize = 16;

// Description-box toggle bits (ISO/IEC 19566-5). When present, fields follow the
// UUID + toggle byte in this order: label, box id (4), signature (32), private box.
/// The box is requestable.
pub const TOGGLE_REQUESTABLE: u8 = 0x01;
/// A label is present.
pub const TOGGLE_LABEL: u8 = 0x02;
/// A 4-byte box id is present.
pub const TOGGLE_ID: u8 = 0x04;
/// A 32-byte signature hash is present.
pub const TOGGLE_SIGNATURE: u8 = 0x08;
/// A private box is present (C2PA carries the salt here).
pub const TOGGLE_PRIVATE: u8 = 0x10;

/// Size of the box-id field when present.
pub const BOX_ID_LEN: usize = 4;
/// Size of the signature-hash field when present (SHA-256).
pub const SIGNATURE_HASH_LEN: usize = 32;

// Box type codes (`TBox`).
/// Superbox.
pub const BOX_JUMB: [u8; 4] = *b"jumb";
/// Description box.
pub const BOX_JUMD: [u8; 4] = *b"jumd";
/// CBOR content box.
pub const BOX_CBOR: [u8; 4] = *b"cbor";
/// JSON content box.
pub const BOX_JSON: [u8; 4] = *b"json";
/// UUID content box.
pub const BOX_UUID: [u8; 4] = *b"uuid";
/// C2PA salt-hash private box.
pub const BOX_SALT: [u8; 4] = *b"c2sh";
/// Embedded-file description box.
pub const BOX_BFDB: [u8; 4] = *b"bfdb";
/// Embedded-file data box.
pub const BOX_BIDB: [u8; 4] = *b"bidb";
/// Brotli-compressed content box.
pub const BOX_BROB: [u8; 4] = *b"brob";
/// JPEG 2000 codestream box.
pub const BOX_JP2C: [u8; 4] = *b"jp2c";
/// Padding box.
pub const BOX_FREE: [u8; 4] = *b"free";
