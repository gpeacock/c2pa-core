# c2pa-core (exploration)

A greenfield rethink of the C2PA parse layer: a **structural, zero-copy,
`no_std` parser** for manifest stores. It answers one question safely and fast —
*given these bytes, what is the box structure, and where are the claim,
assertions, and signature?* — and nothing more.

## Non-goals (by design)

No I/O, no signing, no signature verification, no CBOR decoding, no validation.
Those are higher layers that **consume** the borrowed views this crate produces.
The core physically cannot reach the network or the filesystem.

## Architecture

- **Layer 1 — `jumbf`** (`SuperBox`/`ContentBox`/`Node`): spec-agnostic JUMBF
  box parsing. Output is a tree of *spans* into the input; it knows nothing
  about C2PA.
- **Layer 2 — `store`** (`ManifestStore`/`Manifest`/`Assertion`): interprets the
  tree using C2PA **content-type UUIDs** (the authoritative discriminator; labels
  are for identity). Returns raw bytes; decode later.

## C2PA spec features handled

- **UUID checking** (`uuids` module): every superbox is classified by its 16-byte
  `jumd` content-type UUID via a plain byte compare (`ContentType`). The store
  root is validated as `c2pa`; claim/assertion-store/signature are found by UUID,
  not label; manifests are classified `Standard`/`Update`/`C2md`/`Compressed`.
- **Signatures**: read from the `uuid` content box, stripping the 16-byte UUID
  prefix to yield the raw `COSE_Sign1` bytes.
- **Salts**: extracted from the `c2sh` private box inside a description box (toggle
  bit `0x10`, after the label/id/signature fields). Exposed on manifests and
  assertions via `salt()`.
- **Assertion typing**: CBOR / JSON / UUID (uuid + data split) / embedded file
  classified from the assertion's content-type UUID. Embedded files expose the
  `bidb` file bytes plus the `bfdb` media type and optional file name.
- **Label/UUID consistency** (`verify_label_consistency`): opt-in check that
  rejects boxes where a reserved label (`c2pa`, `c2pa.claim*`, `c2pa.assertions`,
  `c2pa.signature`) is paired with the wrong content-type UUID (or vice versa).
  Parsing stays UUID-authoritative and lenient; callers opt into strictness.

## Guarantees

- **Zero-copy:** every payload is a `&'a [u8]`/`&'a str` borrowing the input.
  The only allocation is the box tree (small structs of slices), bounded by
  `Limits`.
- **`#![forbid(unsafe_code)]`**, all reads bounds-checked, all length math
  overflow-checked. Clippy `indexing_slicing`, `arithmetic_side_effects`,
  `unwrap_used`, `panic` are denied crate-wide.
- **DoS bounds:** `Limits` caps nesting depth, boxes per superbox, total boxes
  (global allocation bound), and total input length.
- **`no_std` + `alloc`:** verified building for `thumbv7em-none-eabi`.

## Writing (feature `write`)

Read-only is the default build. The `write` feature adds a **streaming JUMBF box
emitter** (Layer 1 write) that shares the `format` constants with the reader, so
what it writes is exactly what the reader parses. It never buffers the whole
store: superbox sizes are written as placeholders and backpatched via a
`SeekSink`, so large payloads (thumbnails, ingredients) can be streamed — and, in
a higher layer, hashed — as they're written.

```rust
let mut w = BoxWriter::new(Vec::new());          // or IoSink(file) with `std`
w.start_superbox(&uuids::MANIFEST_STORE, "c2pa", None)?;
w.start_superbox(&uuids::MANIFEST, "urn:c2pa:…", None)?;
w.start_superbox(&uuids::CLAIM, "c2pa.claim", None)?;
w.content_box(&format::BOX_CBOR, claim_cbor)?;   // small: one call
w.end_box()?;
// … assertion store, signature …
w.start_box(&format::BOX_BIDB)?;                 // large: stream in chunks
w.write(chunk)?; /* … */ w.end_box()?;
w.end_box()?; w.end_box()?;
let bytes = w.finish()?;
```

The `Sink` / `SeekSink` split is deliberate: the seekable path (files, `Vec`,
`Cursor`) is built now; a future size-precompute (two-pass) emitter can target a
plain `Sink` with no seek. Hashing, claim assembly, and signing are a higher
write layer (not yet built) that plugs a `Signer` in above this core.

Features: `write` (emitter, `no_std`+`alloc`), `std` (adds `IoSink` over
`std::io::Write`+`Seek`).

## Usage

```rust
let store = ManifestStore::parse(bytes)?;
if let Some(m) = store.active_manifest() {
    let claim = m.claim_cbor()?;        // &[u8], raw CBOR
    let sig   = m.signature_cose()?;    // &[u8], raw COSE_Sign1
    for a in m.assertions()? {
        let label = a.label();
        let data  = a.payload()?;       // AssertionData { kind, data }
    }
}
```

## Fuzzing

`cargo +nightly fuzz run parse` (needs `cargo install cargo-fuzz`). The target
walks every accessor to exercise lazy paths; the invariant is *never panic,
never over-allocate, always terminate.*

## Open questions / next refinements

- Borrowing CBOR decoder (deferred) vs. keeping spans.
- Optional `bytes::Bytes` input variant for shared ownership without a lifetime.
- Strictness knobs (trailing bytes, duplicate boxes, unknown toggles).
- Compressed (`c2cm`) manifests are classified but not Brotli-decompressed here.
