//! The C2PA `c2pa.hash.boxes` hard-binding assertion (C2PA 2.4, 18.7): a hash of
//! each named box of an asset, for containers whose structure is made of
//! meaningful boxes. Validation follows C2PA 2.4, 15.12.3. See
//! `C2PA_SPEC_NOTES.md` in this crate for the rules and their 2.5 numbering.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::data_hash::HashRange;
use crate::hash;

/// The name a box hash lists the C2PA manifest store under, whatever the
/// container calls the element holding it. Its entry is never hashed.
pub const C2PA_BOX: &str = "C2PA";

/// Longest box name the CDDL allows.
#[cfg(feature = "std")]
const MAX_BOX_NAME: usize = 10;

/// A byte range within one of a [`BoxMap`]'s boxes that its hash leaves out
/// (`box-exclusions-map` in the CDDL).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxExclusion {
    /// Offset from the start of the box.
    pub start: u64,
    /// Number of bytes excluded.
    pub length: u64,
    /// Which of the entry's [`names`](BoxMap::names) the range is in; may be
    /// omitted when there is one.
    #[serde(rename = "boxIndex", skip_serializing_if = "Option::is_none", default)]
    pub box_index: Option<i64>,
}

/// One entry of a [`BoxHash`]: consecutive boxes, by name, and the hash of the
/// bytes they span (`box-hash-map` in the CDDL). Field names match `c2pa-rs`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BoxMap {
    /// The names of the boxes this entry covers, in file order.
    pub names: Vec<String>,

    /// The hash algorithm. When absent, the [`BoxHash`]'s, then the claim's.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alg: Option<String>,

    /// The digest of the bytes the boxes span, less any exclusions.
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,

    /// Whether a validator may skip the entry. The C2PA store's entry is skipped
    /// whether or not it says so.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub excluded: Option<bool>,

    /// Ranges of the boxes left out of the hash: only asset metadata may be.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exclusions: Option<Vec<BoxExclusion>>,

    /// Padding for multi-pass processing; ignored by validators.
    #[serde(with = "serde_bytes", default)]
    pub pad: Vec<u8>,

    /// Second padding; ignored by validators.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pad2: Option<ByteBuf>,
}

/// One box of an asset as its container lists it for a box hash: a name, the
/// bytes it spans, and which of them hold asset metadata (XMP, EXIF), the only
/// ranges besides the C2PA store a box hash may exclude. The boxes of an asset
/// are contiguous and cover every byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetBox<'a> {
    /// The box's name, such as `APP0` or `IDAT`, or [`C2PA_BOX`].
    pub name: &'a str,
    /// Where the box is.
    pub range: HashRange,
    /// Absolute ranges inside the box that hold asset metadata.
    pub metadata: Vec<HashRange>,
}

/// What [`BoxHash::verify`] found besides a match.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BoxHashReport {
    /// Something other than the C2PA store was excluded: a box marked
    /// `excluded`, or asset metadata in `exclusions`. Informational
    /// (`assertion.boxesHash.additionalExclusionsPresent`).
    pub additional_exclusions: bool,
}

/// The C2PA `c2pa.hash.boxes` hard binding (`box-map` in the CDDL).
///
/// Each box hash covers a box's bytes, not its position, so the hashes do not
/// depend on the manifest store's size. The C2PA store's own box is listed but
/// never hashed. Build a [`placeholder`](Self::placeholder) from the box names
/// of the planned output, embed it, then [`update`](Self::update) it from the
/// written asset: the hashes have a fixed length, so the assertion keeps its size.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BoxHash {
    /// The entries, in file order.
    pub boxes: Vec<BoxMap>,

    /// The hash algorithm for entries without their own; the claim's when absent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alg: Option<String>,
}

impl BoxHash {
    /// The assertion label for a box-hash hard binding.
    pub const LABEL: &'static str = "c2pa.hash.boxes";

    /// A placeholder listing each of `names` as its own entry with a zero hash of
    /// `alg`'s length; the [`C2PA_BOX`] entry's hash is the single byte `00` the
    /// specification asks for. Each entry names its algorithm, for validators
    /// that ignore the assertion's own. `None` if `alg` is not a supported hash
    /// algorithm.
    pub fn placeholder<'n>(alg: &str, names: impl IntoIterator<Item = &'n str>) -> Option<Self> {
        let len = hash::digest(alg, &[])?.len();
        let boxes = names
            .into_iter()
            .map(|name| {
                let store = name == C2PA_BOX;
                BoxMap {
                    names: vec![name.to_string()],
                    alg: (!store).then(|| alg.to_string()),
                    hash: vec![0; if store { 1 } else { len }],
                    excluded: None,
                    exclusions: None,
                    pad: Vec::new(),
                    pad2: None,
                }
            })
            .collect();
        Some(Self { boxes, alg: None })
    }

    /// Encode to deterministic (canonical) CBOR — the form that gets hashed
    /// and signed, as C2PA requires.
    pub fn to_cbor(&self) -> Result<Vec<u8>, c2pa_cbor::Error> {
        c2pa_cbor::to_vec_deterministic(self)
    }

    /// Decode a box-hash assertion from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, c2pa_cbor::Error> {
        c2pa_cbor::from_slice(bytes)
    }

    /// Hash each entry's boxes in `asset`, whose boxes are `boxes`, keeping the
    /// assertion's encoded length. The boxes must be exactly those the entries
    /// name, in order. `default_alg` is the claim's `alg`.
    #[cfg(feature = "std")]
    pub fn update<R>(
        &mut self,
        asset: &mut R,
        boxes: &[AssetBox<'_>],
        default_alg: Option<&str>,
    ) -> Result<(), BoxHashError>
    where
        R: std::io::Read + std::io::Seek,
    {
        let size = self.to_cbor()?.len();
        let plan = self.plan(asset, boxes, default_alg)?;
        for (entry, step) in self.boxes.iter_mut().zip(plan.entries) {
            if let Some((alg, ranges)) = step {
                entry.hash = digest_ranges(asset, &alg, &ranges)?;
            }
        }
        if self.to_cbor()?.len() != size {
            return Err(BoxHashError::SizeChanged);
        }
        Ok(())
    }

    /// Check the assertion against `asset`, whose boxes are `boxes`
    /// (C2PA 2.4, 15.12.3). Every box must be named, in order; every entry but
    /// the C2PA store's and those marked `excluded` must match. `default_alg` is
    /// the claim's `alg`.
    #[cfg(feature = "std")]
    pub fn verify<R>(
        &self,
        asset: &mut R,
        boxes: &[AssetBox<'_>],
        default_alg: Option<&str>,
    ) -> Result<BoxHashReport, BoxHashError>
    where
        R: std::io::Read + std::io::Seek,
    {
        let plan = self.plan(asset, boxes, default_alg)?;
        for (entry, step) in self.boxes.iter().zip(plan.entries) {
            let Some((alg, ranges)) = step else { continue };
            if digest_ranges(asset, &alg, &ranges)? != entry.hash {
                return Err(BoxHashError::Mismatch(entry.names.join(",")));
            }
        }
        Ok(plan.report)
    }

    /// Match the entries to `boxes` and work out, for each entry that is hashed,
    /// its algorithm and the ranges its hash covers.
    #[cfg(feature = "std")]
    fn plan<R: std::io::Seek>(
        &self,
        asset: &mut R,
        boxes: &[AssetBox<'_>],
        default_alg: Option<&str>,
    ) -> Result<Plan, BoxHashError> {
        use BoxHashError::{Malformed, Mismatch};
        if self.boxes.is_empty() {
            return Err(Malformed("no boxes"));
        }
        let total = asset.seek(std::io::SeekFrom::End(0))?;
        self.check_order(boxes)?;
        let mut next = boxes.iter();
        let mut plan = Plan {
            entries: Vec::with_capacity(self.boxes.len()),
            report: BoxHashReport::default(),
        };
        for entry in &self.boxes {
            let mut matched = Vec::with_capacity(entry.names.len());
            for name in &entry.names {
                if name.is_empty() || name.len() > MAX_BOX_NAME {
                    return Err(Malformed("box name length"));
                }
                let b = next.next().ok_or(BoxHashError::UnknownBox)?;
                b.range
                    .start
                    .checked_add(b.range.length)
                    .filter(|&end| end <= total)
                    .ok_or(Malformed("box outside the asset"))?;
                if let Some(prev) = matched.last().map(|p: &&AssetBox<'_>| p.range) {
                    if prev.start + prev.length != b.range.start {
                        return Err(Malformed("boxes are not contiguous"));
                    }
                }
                matched.push(b);
            }
            let first = matched
                .first()
                .ok_or(Malformed("entry names no boxes"))?
                .range;
            let last = matched[matched.len() - 1].range;
            let span = HashRange {
                start: first.start,
                length: last.start + last.length - first.start,
            };
            if matches!(&entry.exclusions, Some(e) if e.is_empty()) {
                return Err(Malformed("empty exclusions"));
            }
            if entry.names.iter().any(|n| n == C2PA_BOX) {
                if entry.names.len() != 1 {
                    return Err(Malformed("C2PA store shares an entry"));
                }
                plan.entries.push(None);
                continue;
            }
            if entry.excluded == Some(true) {
                plan.report.additional_exclusions = true;
                plan.entries.push(None);
                continue;
            }
            let alg = entry
                .alg
                .as_deref()
                .or(self.alg.as_deref())
                .or(default_alg)
                .ok_or(BoxHashError::UnsupportedAlg(None))?;
            if hash::digest(alg, &[]).is_none() {
                return Err(BoxHashError::UnsupportedAlg(Some(alg.to_string())));
            }
            let mut excluded = Vec::new();
            for exclusion in entry.exclusions.iter().flatten() {
                let index = match exclusion.box_index {
                    Some(i) => usize::try_from(i).map_err(|_| Malformed("negative boxIndex"))?,
                    None if matched.len() == 1 => 0,
                    None => return Err(Malformed("boxIndex missing")),
                };
                let b = matched
                    .get(index)
                    .ok_or(Malformed("boxIndex out of range"))?;
                let start = b
                    .range
                    .start
                    .checked_add(exclusion.start)
                    .ok_or(Malformed("exclusion overflows"))?;
                let end = start
                    .checked_add(exclusion.length)
                    .ok_or(Malformed("exclusion overflows"))?;
                if end > b.range.start + b.range.length {
                    return Err(Mismatch(entry.names.join(",")));
                }
                if excluded
                    .last()
                    .is_some_and(|&(_, prev_end)| prev_end > start)
                {
                    return Err(Malformed("exclusions overlap or are unordered"));
                }
                // Only asset metadata may be excluded besides the store.
                if !b
                    .metadata
                    .iter()
                    .any(|m| start >= m.start && end <= m.start + m.length)
                {
                    return Err(Mismatch(entry.names.join(",")));
                }
                excluded.push((start, end));
                plan.report.additional_exclusions = true;
            }
            let mut ranges = Vec::with_capacity(excluded.len() + 1);
            let mut cursor = span.start;
            for (start, end) in excluded {
                if start > cursor {
                    ranges.push(HashRange {
                        start: cursor,
                        length: start - cursor,
                    });
                }
                cursor = cursor.max(end);
            }
            let span_end = span.start + span.length;
            if cursor < span_end {
                ranges.push(HashRange {
                    start: cursor,
                    length: span_end - cursor,
                });
            }
            plan.entries.push(Some((alg.to_string(), ranges)));
        }
        if next.next().is_some() {
            return Err(BoxHashError::UnknownBox);
        }
        Ok(plan)
    }

    /// Distinguish boxes listed out of order (a mismatch) from boxes the
    /// assertion does not list (an unknown box).
    #[cfg(feature = "std")]
    fn check_order(&self, boxes: &[AssetBox<'_>]) -> Result<(), BoxHashError> {
        let listed = self
            .boxes
            .iter()
            .flat_map(|e| e.names.iter().map(String::as_str));
        if listed.clone().eq(boxes.iter().map(|b| b.name)) {
            return Ok(());
        }
        let mut listed: Vec<&str> = listed.collect();
        let mut present: Vec<&str> = boxes.iter().map(|b| b.name).collect();
        listed.sort_unstable();
        present.sort_unstable();
        Err(if listed == present {
            BoxHashError::OutOfOrder
        } else {
            BoxHashError::UnknownBox
        })
    }
}

/// For each entry, its algorithm and the ranges its hash covers, or `None` when
/// it is not hashed.
#[cfg(feature = "std")]
struct Plan {
    entries: Vec<Option<(String, Vec<HashRange>)>>,
    report: BoxHashReport,
}

/// The digest of `ranges` of `asset`, in order, as one stream.
#[cfg(feature = "std")]
fn digest_ranges<R>(asset: &mut R, alg: &str, ranges: &[HashRange]) -> Result<Vec<u8>, BoxHashError>
where
    R: std::io::Read + std::io::Seek,
{
    struct Ranges<'r, R> {
        asset: &'r mut R,
        ranges: std::slice::Iter<'r, HashRange>,
        left: u64,
    }
    impl<R: std::io::Read + std::io::Seek> std::io::Read for Ranges<'_, R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            while self.left == 0 {
                let Some(r) = self.ranges.next() else {
                    return Ok(0);
                };
                self.asset.seek(std::io::SeekFrom::Start(r.start))?;
                self.left = r.length;
            }
            let want = buf
                .len()
                .min(usize::try_from(self.left).unwrap_or(usize::MAX));
            let n = self.asset.read(&mut buf[..want])?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            self.left -= n as u64;
            Ok(n)
        }
    }
    let reader = Ranges {
        asset,
        ranges: ranges.iter(),
        left: 0,
    };
    Ok(hash::digest_reader(alg, reader)?)
}

/// Why building or checking a [`BoxHash`] failed. [`code`](Self::code) gives the
/// C2PA failure code.
#[derive(Debug)]
#[non_exhaustive]
pub enum BoxHashError {
    /// The asset has boxes the assertion does not list, or lacks some it lists.
    UnknownBox,
    /// The assertion lists the asset's boxes in another order.
    OutOfOrder,
    /// The assertion is not well formed.
    Malformed(&'static str),
    /// An entry's hash or exclusions do not match the asset; it names these boxes.
    Mismatch(String),
    /// No algorithm is given, or the one given is not supported.
    UnsupportedAlg(Option<String>),
    /// Hashing changed the assertion's encoded length.
    SizeChanged,
    /// The assertion could not be encoded.
    Encode(c2pa_cbor::Error),
    /// Reading the asset failed.
    #[cfg(feature = "std")]
    Io(std::io::Error),
}

impl BoxHashError {
    /// The C2PA validation failure code (C2PA 2.4, 15.12.3), where there is one.
    pub fn code(&self) -> Option<&'static str> {
        Some(match self {
            Self::UnknownBox => "assertion.boxesHash.unknownBox",
            Self::OutOfOrder | Self::Mismatch(_) => "assertion.boxesHash.mismatch",
            Self::Malformed(_) => "assertion.boxesHash.malformed",
            Self::UnsupportedAlg(_) => "algorithm.unsupported",
            _ => return None,
        })
    }
}

impl From<c2pa_cbor::Error> for BoxHashError {
    fn from(e: c2pa_cbor::Error) -> Self {
        Self::Encode(e)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for BoxHashError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl core::fmt::Display for BoxHashError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownBox => f.write_str("box hash does not list the asset's boxes"),
            Self::OutOfOrder => f.write_str("box hash lists the asset's boxes out of order"),
            Self::Malformed(why) => write!(f, "malformed box hash: {why}"),
            Self::Mismatch(names) => write!(f, "box hash mismatch for {names}"),
            Self::UnsupportedAlg(Some(alg)) => write!(f, "unsupported box hash algorithm {alg}"),
            Self::UnsupportedAlg(None) => f.write_str("box hash has no algorithm"),
            Self::SizeChanged => f.write_str("box hash changed length"),
            Self::Encode(e) => write!(f, "box hash encoding failed: {e}"),
            #[cfg(feature = "std")]
            Self::Io(e) => write!(f, "box hash: {e}"),
        }?;
        if let Some(code) = self.code() {
            write!(f, " ({code})")?;
        }
        Ok(())
    }
}

impl core::error::Error for BoxHashError {}
