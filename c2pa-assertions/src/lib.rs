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
//! The `std` feature (on by default) enables hashing an asset from a
//! `std::io::Read` source: [`DataHash::from_reader`], [`BoxHash::update`] and
//! [`BoxHash::verify`].
//!
//! See `C2PA_SPEC_NOTES.md` in this crate for the specification rules the hard
//! bindings follow.

mod actions;
mod assertion;
mod box_hash;
mod data_hash;

pub use actions::{Action, Actions};
pub use assertion::Assertion;
pub use box_hash::{
    AssetBox, BoxExclusion, BoxHash, BoxHashError, BoxHashReport, BoxMap, C2PA_BOX,
};
pub use data_hash::{DataHash, HashRange, PadError};
