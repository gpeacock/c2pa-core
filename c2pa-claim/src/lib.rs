//! C2PA claim and hashed-URI support: the CBOR-backed semantic layer built on
//! top of the structural [`c2pa_store`] (JUMBF) crate.
//!
//! See `PRINCIPLES.md` in this crate's repository root for the priorities
//! this crate family (this crate, [`c2pa_store`], [`c2pa_cbor`]) is held to
//! and the current status against each one.
//!
//! # Layering
//!
//! [`c2pa_store`] is the clean foundation — `no_std`, zero dependencies,
//! structural JUMBF parsing plus the C2PA box tree. This crate is where the
//! dependency-bearing pieces live: [`c2pa_cbor`] for CBOR, `sha2` for hashing.
//! The public API here is kept std-light (borrow `&[u8]`/`&str`, no `std::io`
//! in signatures) with one deliberate exception, gated behind the `std`
//! feature (on by default): [`DataHash::from_reader`] and
//! `hash::digest_reader`, for streaming a whole asset's hash without
//! buffering it (see [`DataHash`]). [`DataHash::hasher`] is the
//! I/O-free alternative: the caller feeds chunks on its own schedule.
//!
//! `no_std` is not a current goal of this crate family, but this std-light
//! boundary is kept anyway: it costs little, keeps the door open for a
//! future embedded consumer, and [`c2pa_cbor`] would need its own `no_std`
//! support before it mattered here regardless.

mod actions;
mod claim;
mod data_hash;
mod generator_info;
mod hash;
mod hashed_uri;

pub use actions::{Action, Actions};
pub use claim::Claim;
pub use data_hash::{DataHash, DataHasher, HashRange};
pub use generator_info::GeneratorInfo;
pub use hash::UnsupportedHashAlgorithm;
pub use hashed_uri::{HashedUri, VerifyError};
