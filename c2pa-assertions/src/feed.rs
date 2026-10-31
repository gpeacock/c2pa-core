//! Hashing an asset without doing its I/O (sans-I/O).
//!
//! A hard binding's hash covers byte ranges of the asset. A [`Feed`] says which
//! bytes it [`need`](Feed::need)s next and hashes whatever slice of them the
//! caller [`feed`](Feed::feed)s it, in place: it holds no buffer and sets no
//! chunk size. The caller reads however it likes (a file, an `async` stream, a
//! range request, a memory map) and decides how much to read at once; a caller
//! with the asset in memory hands over each range whole ([`feed_slice`]), so
//! nothing is copied.
//!
//! ```
//! # use c2pa_assertions::{feed_slice, Feed, HashRange, RangeDigest};
//! let asset = b"keep-SKIP-keep";
//! let skip = [HashRange { start: 5, length: 4 }];
//! let mut task = RangeDigest::excluding("sha256", asset.len() as u64, &skip).unwrap();
//! while let Some(need) = task.need() {
//!     // Read `need.len` bytes at `need.offset`, or any first part of them.
//!     let at = need.offset as usize;
//!     task.feed(&asset[at..at + need.len as usize]);
//! }
//! let digest = task.finish().unwrap();
//! # assert_eq!(digest, c2pa_claim::hash::digest("sha256", b"keep--keep").unwrap());
//! ```

use c2pa_claim::hash::Hasher;

use crate::HashRange;

/// The bytes a [`Feed`] wants next: `len` bytes from `offset` in the asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Need {
    /// Where in the asset the bytes start.
    pub offset: u64,
    /// How many bytes are wanted. Any non-empty first part of them may be fed.
    pub len: u64,
}

/// A computation over an asset's bytes that the caller drives.
pub trait Feed {
    /// The bytes wanted next, or `None` once everything has been fed.
    fn need(&self) -> Option<Need>;

    /// Feed bytes of the asset starting at [`need`](Self::need)`().offset`, and
    /// return how many were used: at most `need().len`, and nothing once done.
    fn feed(&mut self, data: &[u8]) -> usize;
}

/// The digest of byte ranges of an asset, hashed in order as one stream.
#[derive(Clone, Debug)]
pub struct RangeDigest {
    hasher: Hasher,
    /// The ranges still to hash; the first shrinks as it is fed.
    ranges: Vec<HashRange>,
    next: usize,
}

impl RangeDigest {
    /// Hash `ranges` in order under `alg`. Empty ranges are skipped. `None` if
    /// `alg` is not a supported algorithm.
    pub fn new(alg: &str, mut ranges: Vec<HashRange>) -> Option<Self> {
        ranges.retain(|r| r.length > 0);
        Some(Self {
            hasher: Hasher::new(alg)?,
            ranges,
            next: 0,
        })
    }

    /// Hash every byte of an asset of `total` bytes except `exclusions`, which
    /// must be in order, not overlap, and lie within the asset: the coverage of
    /// a `c2pa.hash.data`.
    pub fn excluding(alg: &str, total: u64, exclusions: &[HashRange]) -> Result<Self, RangeError> {
        let mut ranges = Vec::with_capacity(exclusions.len() + 1);
        let mut cursor = 0;
        for r in exclusions {
            let end = r
                .start
                .checked_add(r.length)
                .ok_or(RangeError::Exclusions)?;
            if r.start < cursor || end > total {
                return Err(RangeError::Exclusions);
            }
            ranges.push(HashRange {
                start: cursor,
                length: r.start - cursor,
            });
            cursor = end;
        }
        ranges.push(HashRange {
            start: cursor,
            length: total - cursor,
        });
        Self::new(alg, ranges).ok_or(RangeError::Alg)
    }

    /// The digest, or `None` if not everything has been fed.
    pub fn finish(self) -> Option<Vec<u8>> {
        self.need().is_none().then(|| self.hasher.finalize())
    }
}

impl Feed for RangeDigest {
    fn need(&self) -> Option<Need> {
        self.ranges.get(self.next).map(|r| Need {
            offset: r.start,
            len: r.length,
        })
    }

    fn feed(&mut self, data: &[u8]) -> usize {
        let Some(r) = self.ranges.get_mut(self.next) else {
            return 0;
        };
        let n = data
            .len()
            .min(usize::try_from(r.length).unwrap_or(usize::MAX));
        self.hasher.update(&data[..n]);
        r.start += n as u64;
        r.length -= n as u64;
        if r.length == 0 {
            self.next += 1;
        }
        n
    }
}

/// Why [`RangeDigest::excluding`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RangeError {
    /// The algorithm is not supported.
    Alg,
    /// The exclusions are out of order, overlap, or exceed the asset.
    Exclusions,
}

impl core::fmt::Display for RangeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Alg => "unsupported hash algorithm",
            Self::Exclusions => "exclusions are unordered, overlap, or exceed the asset",
        })
    }
}

impl core::error::Error for RangeError {}

/// Feed `task` from `asset`, the whole asset in memory, without copying.
/// Returns `false` if the task wants bytes past the end of `asset`.
pub fn feed_slice(task: &mut (impl Feed + ?Sized), asset: &[u8]) -> bool {
    while let Some(need) = task.need() {
        let range = usize::try_from(need.offset).ok().and_then(|start| {
            let end = start.checked_add(usize::try_from(need.len).ok()?)?;
            asset.get(start..end)
        });
        match range {
            Some(bytes) => task.feed(bytes),
            None => return false,
        };
    }
    true
}

/// Feed `task` from `src` with blocking reads through one 64 KiB buffer,
/// seeking only where the wanted bytes do not follow the last read.
#[cfg(feature = "std")]
pub fn feed_reader<R>(task: &mut (impl Feed + ?Sized), src: &mut R) -> std::io::Result<()>
where
    R: std::io::Read + std::io::Seek + ?Sized,
{
    let mut buf = [0u8; 64 * 1024];
    let mut pos = None;
    while let Some(need) = task.need() {
        if pos != Some(need.offset) {
            src.seek(std::io::SeekFrom::Start(need.offset))?;
        }
        let want = buf
            .len()
            .min(usize::try_from(need.len).unwrap_or(usize::MAX));
        let n = match src.read(&mut buf[..want]) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        task.feed(&buf[..n]);
        pos = Some(need.offset + n as u64);
    }
    Ok(())
}
