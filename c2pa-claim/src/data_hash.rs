use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::hash;

/// A byte range excluded from a [`DataHash`]'s coverage: for an embedded
/// manifest, the span its container reserves for it. Not produced by
/// [`DataHash::new`]/[`DataHash::from_reader`], which hash the whole stream, as
/// a sidecar/remote manifest needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashRange {
    /// Byte offset of the excluded range, from the start of the asset.
    pub start: u64,
    /// Length of the excluded range, in bytes.
    pub length: u64,
}

/// The C2PA `c2pa.hash.data` hard-binding assertion: a hash of the asset's
/// bytes (`data-hash-map` in the CDDL), outside any exclusions.
///
/// Field names match `c2pa-rs`'s `DataHash`, so this round-trips with real
/// manifests. A sidecar/remote manifest hashes the whole asset, with no
/// exclusions or padding. An embedded manifest excludes its own span, and is
/// first written as a same-size placeholder: [`reserve_exclusions`](Self::reserve_exclusions)
/// sizes the placeholder and [`pad_to_size`](Self::pad_to_size) makes the final
/// assertion the same length, so the store can be patched in place.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DataHash {
    /// Byte ranges to exclude from the hash.
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

    /// Padding that sizes the assertion to match a placeholder; see
    /// [`pad_to_size`](Self::pad_to_size).
    #[serde(with = "serde_bytes")]
    pub pad: Vec<u8>,

    /// Second padding, present (and empty) only when `pad` alone cannot reach
    /// the target length; see [`pad_to_size`](Self::pad_to_size).
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

    /// Encode to deterministic (canonical) CBOR — the form that gets hashed
    /// and signed, as C2PA requires.
    pub fn to_cbor(&self) -> Result<Vec<u8>, c2pa_cbor::Error> {
        c2pa_cbor::to_vec_deterministic(self)
    }

    /// Decode a data-hash assertion from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, c2pa_cbor::Error> {
        c2pa_cbor::from_slice(bytes)
    }

    /// A placeholder for an embedded binding with `exclusion_count` exclusions:
    /// a zero hash of `alg`'s length and each exclusion at its widest encoding,
    /// so the final binding never needs more room; see
    /// [`reserve_exclusions`](Self::reserve_exclusions). `None` if `alg` is not a
    /// supported hash algorithm.
    pub fn placeholder(alg: &str, exclusion_count: usize) -> Option<Self> {
        let len = hash::digest(alg, &[])?.len();
        let mut placeholder = Self::new(alg, vec![0; len]);
        placeholder.reserve_exclusions(exclusion_count);
        Some(placeholder)
    }

    /// Replace a placeholder's exclusions and hash with the real ones, keeping
    /// its encoded length so it can be updated in place in an embedded store.
    pub fn update(&mut self, exclusions: Vec<HashRange>, hash: Vec<u8>) -> Result<(), PadError> {
        let size = self.to_cbor()?.len();
        self.exclusions = Some(exclusions);
        self.hash = hash;
        self.pad_to_size(size)
    }

    /// Set `count` exclusions to the largest encodable values, so this
    /// placeholder's encoding is at least as long as any binding with `count`
    /// real exclusions and an equally long `hash`. Pass the placeholder's encoded
    /// length to [`pad_to_size`](Self::pad_to_size) once the real values are known.
    pub fn reserve_exclusions(&mut self, count: usize) {
        self.exclusions = Some(vec![
            HashRange {
                start: u64::MAX,
                length: u64::MAX,
            };
            count
        ]);
    }

    /// Set `pad` and, only when needed, `pad2` so that [`to_cbor`](Self::to_cbor)
    /// is exactly `size` bytes, replacing any existing padding.
    ///
    /// Deterministic CBOR has one encoding per value, so the padding is computed,
    /// not searched for. One byte string cannot reach every length: its length
    /// prefix grows at 24, 256, 2^16 and 2^32 bytes, skipping a few totals. An
    /// empty `pad2` covers those.
    pub fn pad_to_size(&mut self, size: usize) -> Result<(), PadError> {
        self.pad.clear();
        self.pad2 = None;
        let base = self.to_cbor()?.len();
        let extra = size.checked_sub(base).ok_or(PadError::TooLarge {
            minimum: base,
            target: size,
        })?;
        if let Some(n) = pad_len_for_growth(extra) {
            self.pad = vec![0; n];
        } else {
            // The few totals one byte string skips are hundreds of bytes apart, so
            // an empty `pad2` moves the remainder clear of them.
            self.pad2 = Some(ByteBuf::new());
            let pad2_cost = self.to_cbor()?.len() - base;
            let n = extra
                .checked_sub(pad2_cost)
                .and_then(pad_len_for_growth)
                .ok_or(PadError::Unreachable { target: size })?;
            self.pad = vec![0; n];
        }
        if self.to_cbor()?.len() != size {
            return Err(PadError::Unreachable { target: size });
        }
        Ok(())
    }
}

/// Why [`DataHash::pad_to_size`] failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum PadError {
    /// The assertion without padding is already longer than the target.
    TooLarge {
        /// Encoded length with no padding.
        minimum: usize,
        /// Requested length.
        target: usize,
    },
    /// No padding reaches the target exactly.
    Unreachable {
        /// Requested length.
        target: usize,
    },
    /// The assertion could not be encoded.
    Encode(c2pa_cbor::Error),
}

impl From<c2pa_cbor::Error> for PadError {
    fn from(e: c2pa_cbor::Error) -> Self {
        Self::Encode(e)
    }
}

impl core::fmt::Display for PadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge { minimum, target } => write!(
                f,
                "data hash needs {minimum} bytes, more than the {target} reserved"
            ),
            Self::Unreachable { target } => {
                write!(f, "no data-hash padding reaches exactly {target} bytes")
            }
            Self::Encode(e) => write!(f, "data hash encoding failed: {e}"),
        }
    }
}

impl core::error::Error for PadError {}

/// The byte-string length whose deterministic CBOR encoding is exactly `growth`
/// bytes longer than an empty string's (1 byte), if one is.
///
/// A string of `n` bytes encodes as a 1, 2, 3, 5 or 9 byte prefix plus `n`.
/// The gaps between the ranges are the totals no single string reaches.
fn pad_len_for_growth(growth: usize) -> Option<usize> {
    const MAX_U32: u64 = u32::MAX as u64;
    const LAST_HEAD5: u64 = MAX_U32 + 5;
    const FIRST_HEAD9: u64 = MAX_U32 + 10;
    let total = (growth as u64).checked_add(1)?;
    let n = match total {
        0..=24 => total - 1,
        26..=257 => total - 2,
        259..=65_538 => total - 3,
        65_541..=LAST_HEAD5 => total - 5,
        FIRST_HEAD9.. => total - 9,
        _ => return None,
    };
    usize::try_from(n).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_skips_exactly_the_lengths_whose_prefix_grows() {
        assert_eq!(pad_len_for_growth(0), Some(0));
        assert_eq!(pad_len_for_growth(23), Some(23));
        assert_eq!(pad_len_for_growth(24), None);
        assert_eq!(pad_len_for_growth(25), Some(24));
        assert_eq!(pad_len_for_growth(256), Some(255));
        assert_eq!(pad_len_for_growth(257), None);
        assert_eq!(pad_len_for_growth(258), Some(256));
        assert_eq!(pad_len_for_growth(65_537), Some(65_535));
        assert_eq!(pad_len_for_growth(65_538), None);
        assert_eq!(pad_len_for_growth(65_539), None);
        assert_eq!(pad_len_for_growth(65_540), Some(65_536));
    }
}
