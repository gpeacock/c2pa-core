use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::hash;

/// A byte range excluded from a [`DataHash`]'s coverage (e.g. the span
/// reserved for the manifest itself, in an embedded manifest). Not produced
/// by [`DataHash::new`]/[`DataHash::from_reader`] -- those always hash the
/// whole stream, which is what a sidecar/remote manifest (nothing embedded
/// to exclude) needs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HashRange {
    /// Byte offset of the excluded range, from the start of the asset.
    pub start: u64,
    /// Length of the excluded range, in bytes.
    pub length: u64,
}

/// The C2PA `c2pa.hash.data` hard-binding assertion: a hash of the asset's
/// bytes (`data-hash-map` in the CDDL), used for a sidecar or remote
/// manifest rather than one embedded in the asset (which would instead use a
/// format-specific hard binding like a BMFF hash).
///
/// Wire-compatible with `c2pa-rs`'s `DataHash`: field names match exactly, so
/// this round-trips with real manifests. `pad`/`pad2` only matter when an
/// embedded manifest's hash assertion is size-matched to a placeholder
/// before being patched in place; a sidecar/remote manifest never does that,
/// so `pad` is always empty and `pad2` always absent here.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DataHash {
    /// Byte ranges to exclude from the hash. Always `None` here -- see
    /// [`HashRange`].
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exclusions: Option<Vec<HashRange>>,

    /// Human-readable name for the hash target (e.g. `"jumbf manifest"`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,

    /// The hash algorithm used. Optional on the wire (a claim can supply a
    /// default), but [`new`](Self::new)/[`from_reader`](Self::from_reader)
    /// always set it explicitly.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alg: Option<String>,

    /// The digest of the asset's bytes (minus `exclusions`, if any).
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,

    /// Padding used only when size-matching an embedded placeholder. Always
    /// empty here.
    #[serde(with = "serde_bytes")]
    pub pad: Vec<u8>,

    /// Additional padding for an already-signed, updated hash assertion.
    /// Always `None` here.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pad2: Option<ByteBuf>,
}

impl DataHash {
    /// The assertion label for a data-hash hard binding.
    pub const LABEL: &'static str = "c2pa.hash.data";

    /// Build a data-hash assertion from an already-computed digest.
    pub fn new(alg: impl Into<String>, hash: Vec<u8>) -> Self {
        Self {
            exclusions: None,
            name: None,
            alg: Some(alg.into()),
            hash,
            pad: Vec::new(),
            pad2: None,
        }
    }

    /// Hash all of `reader`'s bytes under `alg` (no exclusions -- correct for
    /// a sidecar/remote manifest, which has nothing of its own embedded in
    /// the asset to exclude) and build a data-hash assertion from the
    /// result.
    ///
    /// Requires the `std` feature; see [`hash::digest_reader`].
    #[cfg(feature = "std")]
    pub fn from_reader(alg: &str, reader: impl std::io::Read) -> std::io::Result<Self> {
        let digest = hash::digest_reader(alg, reader)?;
        Ok(Self::new(alg, digest))
    }

    /// Start an incremental data hash under `alg`, for callers that want to
    /// feed the asset in chunks on their own schedule (e.g. from a state
    /// machine or async task) instead of handing over a blocking reader.
    /// Returns [`hash::UnsupportedHashAlgorithm`] if the identifier is unsupported.
    pub fn hasher(alg: &str) -> Result<DataHasher, hash::UnsupportedHashAlgorithm> {
        Ok(DataHasher {
            alg: alg.to_string(),
            digest: hash::IncrementalDigest::new(alg)?,
            bytes_hashed: 0,
        })
    }

    /// Encode to deterministic (canonical) CBOR — the form that gets hashed
    /// and signed, as C2PA requires.
    pub fn to_cbor(&self) -> Result<Vec<u8>, c2pa_cbor::Error> {
        c2pa_cbor::to_vec_deterministic(self)
    }

    /// Decode a data-hash assertion from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, c2pa_cbor::Error> {
        c2pa_cbor::from_slice(bytes)
    }
}

/// An in-progress whole-asset data hash, created by [`DataHash::hasher`].
/// Owns all of its state (no borrows), so it can be parked inside a state
/// machine between chunks and driven by any I/O model or none at all.
#[derive(Clone, Debug)]
pub struct DataHasher {
    alg: String,
    digest: hash::IncrementalDigest,
    bytes_hashed: u64,
}

impl DataHasher {
    /// Hash the next chunk of the asset. Work is proportional to
    /// `chunk.len()`, so callers bound each step by choosing the chunk size.
    pub fn update(&mut self, chunk: &[u8]) {
        self.digest.update(chunk);
        self.bytes_hashed = self.bytes_hashed.saturating_add(chunk.len() as u64);
    }

    /// Total bytes fed so far, for progress reporting.
    pub fn bytes_hashed(&self) -> u64 {
        self.bytes_hashed
    }

    /// Finish hashing and build the data-hash assertion.
    pub fn finish(self) -> DataHash {
        DataHash::new(self.alg, self.digest.finalize())
    }
}
