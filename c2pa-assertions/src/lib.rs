//! C2PA assertions: the content a claim references by hashed URI.
//!
//! Every assertion implements [`Assertion`], the API the claim and store layers
//! use: its label and its deterministic CBOR. Each type models a deliberate subset
//! of its CDDL, with field names matching `c2pa-rs` so real manifests round-trip.
//!
//! # Layering
//!
//! This crate depends on [`c2pa_claim`] for [`HashedUri`](c2pa_claim::HashedUri)
//! and the shared [`hash`](c2pa_claim::hash) functions, and on [`c2pa_cbor`]. It
//! knows nothing about containers or JUMBF: a hard binding is told the asset's
//! byte ranges or boxes by its caller (see [`HashRange`] and [`AssetBox`]), and
//! the store writes whatever bytes an assertion encodes to.
//!
//! Hashing an asset is sans-I/O: [`DataHash::task`] and [`BoxHash::task`]
//! return a [`Feed`] that names the byte ranges it needs and hashes the slices
//! the caller supplies in place, so any I/O model (blocking, `async`, memory
//! map, range requests) drives the same code. The `std` feature (on by default)
//! adds blocking drivers over `std::io::Read`: [`feed_reader`],
//! [`DataHash::from_reader`], [`BoxHash::update`] and [`BoxHash::verify`].
//!
//! See `C2PA_SPEC_NOTES.md` in this crate for the specification rules the hard
//! bindings follow.

mod actions;
mod assertion;
mod box_hash;
mod data_hash;
mod feed;

pub use actions::{Action, Actions};
pub use assertion::Assertion;
pub use box_hash::{
    AssetBox, BoxExclusion, BoxHash, BoxHashError, BoxHashReport, BoxHashTask, BoxMap, C2PA_BOX,
};
pub use data_hash::{DataHash, DataHashError, HashRange, PadError};
#[cfg(feature = "std")]
pub use feed::feed_reader;
pub use feed::{feed_slice, Feed, Need, RangeDigest, RangeError};
