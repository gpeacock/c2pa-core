# Priorities for c2pa-claim, c2pa-store, and c2pa-cbor

This crate (`c2pa-claim`) depends on two sibling crates: `c2pa-store`
(structural, zero-dependency JUMBF/box parsing) and `c2pa-cbor` (deterministic
CBOR encoding/decoding). All three are held to the same priorities, in order.
This document is the reference the code is judged against; update it as the
crates evolve rather than letting intent drift back into scattered comments.

## 1. Spec conformance

Wire behavior must match the C2PA spec (and, for CBOR, RFC 8949's Core
Deterministic Encoding profile) exactly — field names, optionality, and
encoding rules. Where a type intentionally models only a subset of a spec
structure's optional fields (e.g. `Action`, `Actions`, `DataHash` here all
skip fields `c2pa-rs` supports), decoding must still ignore unknown map keys
rather than reject them, so round-tripping a real manifest never loses data
it doesn't understand.

## 2. Attack/crash resistance

Every layer parses untrusted, potentially adversarial bytes (a manifest
embedded in an asset someone else produced). No panics, no unbounded
allocation, no unbounded recursion, no silent acceptance of malformed input
that a strict decoder should reject (e.g. duplicate CBOR map keys, which
violate RFC 8949 determinism and can be used to smuggle a value past a
reviewer who only sees the first occurrence). Prefer fuzzing over hand-picked
test cases alone — hand-picked cases only cover what you already thought of.

## 3. Modularity, no cross-dependencies

Each crate does one job and doesn't reach into a layer above or beside it:
`c2pa-store` only understands box structure (no CBOR, no hashing, no
signing); `c2pa-cbor` only understands CBOR (no C2PA semantics); `c2pa-claim`
only understands claim/assertion semantics (no box-tree parsing of its own).
A dependency should never be added to save a few lines of code if it blurs
this boundary.

## 4. Speed / memory efficiency on huge assets

Assets can be large (video, high-res images); the library must not require
holding a whole asset, or a whole manifest, in memory beyond what's
necessary. Streaming APIs (e.g. `DataHash::from_reader`) exist specifically
so callers never have to buffer an entire file just to hash it.

## 5. Zero-copy where possible

Parsing should borrow from the input buffer instead of copying, all the way
through the stack where the layer below allows it. `c2pa-store` already does
this end-to-end (`&'a [u8]`/`&'a str` throughout). `c2pa-cbor`'s decoder does
not yet — it allocates an owned `String`/`Vec<u8>` per string/bytes value
even when decoding from a `&[u8]` — which is a known gap, not the target
state.

## 6. `no_std` (nice-to-have, not a current requirement)

No consumer has asked for `no_std` yet, but C2PA is known to run on cameras
with custom/embedded OSes, so it's worth not foreclosing it. The concrete
operations here (JUMBF parsing, CBOR decode, hashing, comparison) don't need
threads or files, just `alloc` — so the actionable form of this priority is
"don't hardcode `std`-only types at public API boundaries" (prefer `&[u8]`
over `std::io::Read` where both work), not "port everything to `no_std`
today." Do not take on the maintenance cost of a full `no_std` port
speculatively.

## 7. Clean, documented, simple code

Prefer straightforward code with doc comments explaining spec rationale
(*why* a field is optional, *why* a type only models a subset) over clever
abstractions. A reader unfamiliar with C2PA should be able to follow the
code with the doc comments as a guide.

## Status by crate (as of this audit)

**`c2pa-store`** — meets essentially all seven priorities today: genuinely
zero-copy (`Reader<'a>` returns borrowed slices throughout), `#![no_std]` +
`alloc` by default with `std` purely additive and feature-gated,
`#![forbid(unsafe_code)]`, all offsets `checked_add`/`checked_sub`, DoS
bounded via an explicit `Limits` budget (max depth, max box count, max total
length), and a cargo-fuzz harness with targeted malformed-input tests.

**`c2pa-cbor`** — correctly targets RFC 8949 Core Deterministic Encoding, has
recursion-depth and allocation limits on decode, and rejects duplicate keys
on both encode and decode. Gaps: decoding is not zero-copy (priority 5) and
the crate is `std`-only with no `no_std` path (priority 6, not currently
pursued per the reasoning above); no `fuzz/` harness exists yet, so
adversarial-input coverage is unit tests rather than fuzzed.

**`c2pa-claim`** (this crate) — models a deliberate subset of the claim/
assertion spec, matching `c2pa-rs` field names for wire compatibility.
`std` is isolated to one streaming-hash code path (`hash::digest_reader`,
`DataHash::from_reader`), gated behind the `std` feature (default-on); the
rest of the public API borrows `&[u8]`/`&str`. No `fuzz/` harness yet.
