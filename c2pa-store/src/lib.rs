//! `c2pa-store` — a structural, zero-copy parser for C2PA manifest stores.
//!
//! # Scope (first pass)
//!
//! This crate does exactly one thing: given a byte slice that contains a C2PA
//! manifest store (a JUMBF superbox), it validates the box structure and hands
//! back **borrowed views** into that slice — the claim CBOR, the assertion
//! store, and the signature — without copying manifest data.
//!
//! It does **not** do I/O, signing, signature verification, or CBOR decoding.
//! Those belong in higher layers that consume the borrowed views produced here.
//!
//! # Design
//!
//! * **Two layers.** [`jumbf`]-level parsing ([`SuperBox`]/[`ContentBox`]) is
//!   spec-agnostic: it only understands JUMBF boxes and produces a tree of
//!   spans into the input. The [`ManifestStore`] layer interprets that tree
//!   using C2PA labels. [`JumbfUri`] parsing is likewise spec-agnostic (path
//!   syntax only); [`ManifestStore::resolve`] walks it using C2PA label
//!   knowledge.
//! * **Zero-copy.** Every payload returned is a `&'a [u8]` (or `&'a str`)
//!   borrowing from the input buffer. The only allocation is the box tree
//!   itself (small structs of slices), bounded by [`Limits`].
//! * **`no_std` + `alloc`.** No I/O, no `std`. Portable to WASM/embedded/FFI.
//! * **Hardened.** `#![forbid(unsafe_code)]`, every length is bounds- and
//!   overflow-checked, recursion depth and total box count are capped, and the
//!   parser never panics on adversarial input (see the `fuzz/` target).
//!
//! ```no_run
//! use c2pa_store::ManifestStore;
//!
//! # fn get_bytes() -> &'static [u8] { &[] }
//! let bytes: &[u8] = get_bytes();
//! let store = ManifestStore::parse(bytes)?;
//! if let Some(manifest) = store.active_manifest() {
//!     let _claim: &[u8] = manifest.claim_cbor()?;      // raw CBOR, decode later
//!     let _sig: &[u8] = manifest.signature_cose()?;    // raw COSE_Sign1
//!     for assertion in manifest.assertions()? {
//!         let _label = assertion.label();
//!         let _data = assertion.payload()?;            // raw content box bytes
//!     }
//! }
//! # Ok::<(), c2pa_store::Error>(())
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
// Strict safety lints for the library itself (not tests/examples).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod box_reader;
#[cfg(feature = "write")]
mod box_writer;
#[cfg(feature = "write")]
mod editor;
mod error;
pub mod format;
mod jumbf;
mod jumbf_uri;
mod limits;
#[cfg(feature = "write")]
mod manifest_builder;
mod store;
pub mod uuids;

#[cfg(all(feature = "write", feature = "std"))]
pub use box_writer::IoSink;
#[cfg(feature = "write")]
pub use box_writer::{BoxWriter, SeekSink, Sink};
#[cfg(feature = "write")]
pub use editor::ManifestStoreEditor;
pub use error::Error;
pub use jumbf::{ContentBox, Description, Node, SuperBox};
pub use jumbf_uri::JumbfUri;
pub use limits::Limits;
#[cfg(feature = "write")]
pub use manifest_builder::{AssertionHash, ManifestStoreBuilder};
pub use store::{Assertion, AssertionData, Manifest, ManifestKind, ManifestStore};
pub use uuids::ContentType;
