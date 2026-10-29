# Experimental C2PA signing and asset CLI

This package demonstrates `c2pa-claim` and `c2pa-store` with
[`asset-io`](https://github.com/gpeacock/asset-io). File-format code stays in
asset-io; the core crates do not gain filesystem or container dependencies.
This checkout temporarily uses the sibling `../asset-io` repository while its
handler-owned `Structure::c2pa_data_hash_exclusions` API is developed. Restore a
pinned Git revision containing that API before publishing.

**Local experiments only:** every signing invocation generates a fresh Ed25519
key and CA/end-entity certificate chain. The private key is discarded. The CA
is **not trusted by default**. These are not production credentials.

## Asset commands

```sh
# Inspect a file's embedded store, or a raw .c2pa sidecar.
cargo run -p c2pa-sign-sample --bin c2pa-asset -- dump photo.jpg
cargo run -p c2pa-sign-sample --bin c2pa-asset -- dump manifest.c2pa

# Check integrity against the actual asset bytes.
cargo run -p c2pa-sign-sample --bin c2pa-asset -- validate photo.jpg

# Append a new test-signed manifest, preserving any existing store's manifests.
# Uses a box hash where the container has meaningful boxes, else a data hash.
cargo run -p c2pa-sign-sample --bin c2pa-asset -- sign photo.jpg -o signed.jpg
cargo run -p c2pa-sign-sample --bin c2pa-asset -- validate signed.jpg

# Choose a data hash instead of the recommended box hash.
cargo run -p c2pa-sign-sample --bin c2pa-asset -- sign photo.jpg -o data.jpg --data-hash

# A detached store needs the original asset for its hard-binding check.
cargo run -p c2pa-sign-sample --bin c2pa-asset -- validate manifest.c2pa --asset photo.jpg
```

`sign` writes the asset and `signed.jpg.ca.pem`. Neither output may already
exist, and the input is never overwritten. Output files are published only
after the patched asset has been parsed and its integrity checks pass.
Use an output extension appropriate to the input container: signing does not
convert media formats. Known extensions select a handler; unknown extensions
use content detection, which not all handlers implement.

### Format coverage

All container features in the pinned asset-io revision are enabled:

| Container family | Dump | Embedded test signing and active hard-binding validation |
|---|---|---|
| JPEG | yes | box hash; data hash with `--data-hash` |
| PNG | yes | box hash; data hash with `--data-hash` |
| RIFF (WebP, WAV, AVI) | yes | box hash; data hash with `--data-hash` |
| SVG | yes | data hash, including base64-encoded manifest patching |
| ISO BMFF (MP4, HEIC, AVIF, M4A, etc.) | yes | not implemented (needs `c2pa.hash.bmff`) |
| PDF | yes | not implemented |
| Raw C2PA | yes | detached data-hash validation with `--asset`; not an asset to embed into |

TIFF is not included in the pinned upstream revision. Unsupported bindings
and signature algorithms fail explicitly; dumping does not require the
signature or binding to be supported. The store is located with asset-io's
`Structure::c2pa_store`, which selects the C2PA superbox type, ignoring
unrelated JUMBF, and combines a BMFF original/update store.

### What validation means

This is **integrity validation, not full C2PA conformance or trust evaluation**:

- Parse the store and check reserved label/type consistency.
- Verify every manifest's v1/v2 assertion hashed-URI references.
- Verify every manifest's COSE signature over its original claim bytes, using
  the Ed25519 public key parsed from its X.509 end-entity certificate.
- Check the active manifest's referenced hard binding against the current
  asset. For `c2pa.hash.data`, embedded exclusions must exactly match the
  canonical ranges returned by asset-io for the selected manifest item;
  arbitrary exclusions are rejected. For `c2pa.hash.boxes` (C2PA 2.4, 15.12.3), the
  entries must name every box asset-io lists, in order (`unknownBox`
  otherwise, `mismatch` when reordered), and every entry but the C2PA store's
  and those marked `excluded` must match. `exclusions` must be ordered, inside
  their box, and cover only asset metadata asset-io reports in it. The
  algorithm is the entry's, else the assertion's, else the claim's. Excluding
  anything besides the store is reported as
  `assertion.boxesHash.additionalExclusionsPresent`.

Historical asset bindings describe earlier versions and are not compared to the
current asset. Certificate path signatures, trust anchors, certificate validity,
revocation, timestamps, ingredients, redactions and other hard-binding schemes
are **not evaluated**. Certificate trust is explicitly reported as unevaluated,
even on a successful integrity check. External manifests using other algorithms,
bindings or exclusion conventions will fail rather than receive a partial
success. Appending preserves historical manifest bytes but does not yet create
ingredient assertions linking the history.

### Signing flow

Responsibilities are split so no container knowledge reaches the client:

- asset-io says which hard binding the container calls for
  (`Structure::c2pa_hash`): a box hash where every element has a box name, a
  data hash for containers without meaningful boxes (SVG), and a BMFF hash for
  ISO BMFF, which fails explicitly here. The caller may choose a data hash
  instead of a box hash. asset-io also finds the store (`c2pa_item`), lists the
  boxes (`c2pa_boxes`, with the store as one `C2PA` box and trailing data as
  `c2pa.after`) and gives the data-hash exclusions
  (`c2pa_data_hash_exclusions`).
- The binding builds its own placeholder and fills itself in, through the
  `HardBinding` trait the signer uses. `DataHash::placeholder` reserves each
  exclusion at its widest deterministic-CBOR encoding, and `DataHash::update`
  sets the real values and pads back to the placeholder's length.
  `BoxHash::placeholder` lists the planned output's box names with zero
  hashes, and `BoxHash::update` hashes each box of the written asset; box
  hashes cover contents, not positions, so they have a fixed length.
- `c2pa-store`'s `ManifestStoreEditor` writes the updated assertion, claim and
  signature in place, refusing any change in length, and returns the
  assertion's new hash; `Claim::update_assertion_hash` puts it in the claim.

The app plans the placement once to learn how many ranges the container
excludes or which boxes it has, builds and signs the placeholder manifest,
writes it, hashes the output in bounded chunks, then completes the binding, claim
and signature in place and uses `Structure::patch_exact` to fill the same-size
store. Nothing changes size, so no fixed-point iteration is needed. Container
checksums and transfer encoding are handled by asset-io. RIFF excludes the
manifest chunk's header and payload but keeps its alignment padding hashed. A
final re-read verifies the result before publication.

### Dump output

The fully expanded text tree includes labels, type UUIDs, superbox sizes,
content payload sizes, salts, decoded CBOR/JSON, and COSE tags/arrays. Binary
values retain their byte count but display at most **32 bytes** of hex with
`...` on longer values. Decode errors are displayed and return a nonzero exit
status.

## Original sidecar sample

The original default binary remains available. It hashes the whole input file
and writes a detached, test-signed store plus a CA PEM:

```sh
cargo run -p c2pa-sign-sample -- input.png
# Writes input.c2pa and input.ca.pem.
```

It shares the signing implementation with the asset CLI, including detached
COSE payloads. Unlike the new asset CLI, the original sidecar command retains
its existing output-overwrite behavior.

## Tests

```sh
cargo test -p c2pa-sign-sample
```

The CLI tests exercise JPEG/PNG/RIFF/SVG sign/validate/dump roundtrips with
box and data hashes, box-hash tampering and unlisted boxes,
appending without changing historical manifests, detached validation,
tampered assets/signatures/assertions, overbroad exclusions, unsupported
bindings, and no-clobber behavior.
