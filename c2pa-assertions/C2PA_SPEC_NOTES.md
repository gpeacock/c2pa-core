# C2PA specification notes: hard bindings and the general box hash

This crate family targets C2PA **2.4**. **2.5** is published; for box hashing
its changes are editorial (renumbering, "JPEG" renamed "JPEG 1", the normative
CDDL moved to Appendix G.4.4). Code comments cite 2.4 section numbers.

Specifications: `https://spec.c2pa.org/specifications/specifications/<version>/specs/C2PA_Specification.html`

## Section numbers

| Topic | 2.4 | 2.5 |
|---|---|---|
| Hashing using a general box hash | 9.2.2 | — |
| Multiple-step processing (padding) | 10.4 | 11.7 |
| Hashing and algorithms | 13.1 | 12.1 |
| Validating a general box hash | 15.12.3 | 14.12.3 |
| General box hash | 18.7 | 16.3.3 |
| Multi-part assets (`c2pa.after`) | 18.7.2 | 16.3.3.2 |
| Format-specific handling | 18.7.3.x | 16.3.3.3.x |
| Box hash CDDL | in 18.7 | Appendix G.4.4 |

## Which hard binding

- ISO BMFF (MP4, MOV, HEIF, AVIF, …) must use `c2pa.hash.bmff`.
- Non-BMFF box formats should use `c2pa.hash.boxes`. Formats with box-hash
  rules: JPEG 1, PNG, TIFF/DNG, GIF, RIFF (WAV, WebP, AVI), fonts and Ogg.
- Formats without meaningful boxes (SVG, unknown types) use `c2pa.hash.data`.
  A claim generator may choose a data hash instead of a box hash.
- c2pa-rs implements box hashing for JPEG, PNG, GIF and JPEG XL only, so RIFF,
  TIFF and font box hashes cannot be validated there.

## Box hash CDDL (2.4 and 2.5)

```cddl
box-map = {
  "boxes": [1* box-hash-map],
  ? "alg": tstr,                    ; for entries without their own
}
box-hash-map = {
  "names": [1* box-name],           ; box-name: tstr .size (1..10)
  ? "alg": tstr,
  "hash": bstr,
  ? "excluded": bool,
  ? "exclusions": [1* box-exclusions-map],
  ? "pad": bstr,
  ? "pad2": bstr,
}
box-exclusions-map = {
  "start": uint,                    ; offset from the start of the box
  "length": uint,
  ? "boxIndex": int,                ; into names; omittable with one name
}
```

- The C2PA Manifest Store is one box named `C2PA` in its own entry, with the
  hash `00`, even when a JPEG store spans several APP11 segments.
- An entry naming several boxes hashes from the first box's start to the last
  box's end, including any bytes between them.
- For an `excluded: true` entry a generator should still write an accurate hash
  for older validators, or `00` if it does not need them.

## Validation (2.4 15.12.3, 2.5 14.12.3)

| Condition | Result |
|---|---|
| `boxes` or an entry's `names` missing | `assertion.boxesHash.malformed` |
| A box in the asset not listed | `assertion.boxesHash.unknownBox` |
| Boxes listed out of order | `assertion.boxesHash.mismatch` |
| No algorithm, or an unsupported one | `algorithm.unsupported` |
| `boxIndex` naming no box; exclusions unordered, overlapping or negative | `assertion.boxesHash.malformed` |
| An exclusion ending past its box | `assertion.boxesHash.mismatch` |
| An exclusion covering anything but the store, padding or asset metadata | `assertion.boxesHash.mismatch` |
| A hash differing, for an entry not marked `excluded` | `assertion.boxesHash.mismatch` |
| Anything besides the store excluded (exclusions or `excluded` boxes) | informational `assertion.boxesHash.additionalExclusionsPresent` |

- Algorithm precedence: the entry's `alg`, then the box-map's, then the
  claim's. There is no other default.
- Asset metadata is EXIF, XMP and IPTC-equivalent data (2.5 12.2.2.9).
- `pad` and `pad2` contents are ignored.

## Format-specific box rules

- **JPEG 1:** boxes are named by ISO 10918-1 Table B.1 symbols. APP11 segments
  for other standards are listed like any other box. `SOS` and each `RSTn` are
  separate boxes, each including the entropy-coded data after its marker. A
  Multi-Picture Format file lists every image's boxes in order
  (`SOI` … `EOI`, `SOI` … `EOI`), unless it is treated as a multi-part asset, in
  which case `c2pa.after` covers the parts after the first image.
- **PNG:** the first box is `PNGh`, the 8-byte signature; then chunks by type.
- **RIFF:** each top-level `RIFF` chunk is a 12-byte box named by its media type
  (bytes 8–11, such as `WAVE` or `AVIX`). Each other first-level chunk is a box
  named by its chunk ID. Each first-level `LIST` chunk is a box named by its
  list type (bytes 8–11, such as `INFO` or `movi`) that includes everything
  nested in it. Padding bytes belong to the chunk before them.
- **GIF:** a block with a Packed Fields attribute includes the data it
  indicates (color tables). Blocks are named by label.
- **Fonts:** one box per table, in table-directory order; the directory itself
  is not hashed. The `head` table's checkSumAdjustment is treated as 0.
- **Ogg:** each logical bitstream is one box named `Stream-<serial>`, covering
  all its pages; the C2PA store is its own bitstream.
- **Multi-part (`c2pa.after`):** the last box, from the byte after the last box
  to the end of the file, allowed only in the hard binding for the whole asset.
