//! Layer 1 (write): a streaming JUMBF box emitter.
//!
//! This is the inverse of the [`crate::jumbf`] parser and shares the same
//! [`crate::format`] constants, so what it writes is exactly what the reader
//! expects. It knows nothing about C2PA semantics, hashing, or signing — those
//! belong in a higher write layer built on top.
//!
//! # Streaming model
//!
//! Boxes are written to a [`Sink`]. A superbox's size isn't known until its
//! children are written, so the emitter writes a placeholder size and patches it
//! on [`BoxWriter::end_box`] — which requires a [`SeekSink`]. This lets you emit
//! (and, in a higher layer, hash) large payloads as you go without buffering the
//! whole store. The [`Sink`]/[`SeekSink`] split is deliberate: a future
//! size-precompute (two-pass) emitter can target a plain [`Sink`] with no seek.

use alloc::vec::Vec;

use crate::error::Error;
use crate::format::{
    BOX_JUMB, BOX_JUMD, BOX_SALT, HDR_BASE, TOGGLE_LABEL, TOGGLE_PRIVATE, TOGGLE_REQUESTABLE,
};

/// A forward-only byte sink.
pub trait Sink {
    /// Append all of `buf` to the sink.
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Error>;
}

/// A sink that also supports reporting its position and patching earlier bytes,
/// used to backpatch box sizes once their contents are known.
pub trait SeekSink: Sink {
    /// The current write position (number of bytes written so far).
    fn position(&mut self) -> Result<u64, Error>;
    /// Overwrite `bytes` at absolute offset `pos` (which must already be within
    /// what has been written).
    fn patch_at(&mut self, pos: u64, bytes: &[u8]) -> Result<(), Error>;
}

impl Sink for Vec<u8> {
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.extend_from_slice(buf);
        Ok(())
    }
}

impl SeekSink for Vec<u8> {
    fn position(&mut self) -> Result<u64, Error> {
        Ok(self.len() as u64)
    }

    fn patch_at(&mut self, pos: u64, bytes: &[u8]) -> Result<(), Error> {
        let start = usize::try_from(pos).map_err(|_| Error::LengthOverflow)?;
        let end = start
            .checked_add(bytes.len())
            .ok_or(Error::LengthOverflow)?;
        let slot = self.get_mut(start..end).ok_or(Error::WriteFailed)?;
        slot.copy_from_slice(bytes);
        Ok(())
    }
}

/// Wraps a `std::io::Write` (+ `Seek`) so it can be used as a [`Sink`] /
/// [`SeekSink`]. A newtype avoids coherence conflicts with the `Vec` impls.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct IoSink<W>(pub W);

#[cfg(feature = "std")]
impl<W: std::io::Write> Sink for IoSink<W> {
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        std::io::Write::write_all(&mut self.0, buf).map_err(|_| Error::WriteFailed)
    }
}

#[cfg(feature = "std")]
impl<W: std::io::Write + std::io::Seek> SeekSink for IoSink<W> {
    fn position(&mut self) -> Result<u64, Error> {
        self.0.stream_position().map_err(|_| Error::WriteFailed)
    }

    fn patch_at(&mut self, pos: u64, bytes: &[u8]) -> Result<(), Error> {
        let here = self.0.stream_position().map_err(|_| Error::WriteFailed)?;
        self.0
            .seek(std::io::SeekFrom::Start(pos))
            .map_err(|_| Error::WriteFailed)?;
        std::io::Write::write_all(&mut self.0, bytes).map_err(|_| Error::WriteFailed)?;
        self.0
            .seek(std::io::SeekFrom::Start(here))
            .map_err(|_| Error::WriteFailed)?;
        Ok(())
    }
}

/// Checked `usize` addition returning a length-overflow error.
fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::LengthOverflow)
}

/// A streaming JUMBF box emitter over a [`SeekSink`].
///
/// Open boxes are tracked on a stack of size-field offsets; each [`end_box`]
/// backpatches the size of the most recently opened box.
///
/// [`end_box`]: BoxWriter::end_box
#[derive(Debug)]
pub struct BoxWriter<S: SeekSink> {
    sink: S,
    /// Offsets of the size field of each currently-open box (LIFO).
    open: Vec<u64>,
}

impl<S: SeekSink> BoxWriter<S> {
    /// Create a writer over `sink`.
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            open: Vec::new(),
        }
    }

    fn header(&mut self, tbox: &[u8; 4], size: u32) -> Result<(), Error> {
        self.sink.write_all(&size.to_be_bytes())?;
        self.sink.write_all(tbox)?;
        Ok(())
    }

    /// Open a box of type `tbox`, writing a placeholder size to be patched by
    /// the matching [`end_box`](BoxWriter::end_box).
    pub fn start_box(&mut self, tbox: &[u8; 4]) -> Result<(), Error> {
        let pos = self.sink.position()?;
        self.header(tbox, 0)?;
        self.open.push(pos);
        Ok(())
    }

    /// Close the most recently opened box, patching its size.
    pub fn end_box(&mut self) -> Result<(), Error> {
        let start = self.open.pop().ok_or(Error::WriteUnbalanced)?;
        let end = self.sink.position()?;
        let size = end.checked_sub(start).ok_or(Error::LengthOverflow)?;
        // A size that doesn't fit in LBox would need an XLBox, which changes the
        // header length and can't be backpatched in place. Not yet supported.
        let size = u32::try_from(size).map_err(|_| Error::LengthOverflow)?;
        self.sink.patch_at(start, &size.to_be_bytes())?;
        Ok(())
    }

    /// Write raw bytes into the currently-open box (e.g. a large streamed
    /// payload).
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), Error> {
        self.sink.write_all(chunk)
    }

    /// Write a complete content box (`tbox` + `data`) in one call.
    pub fn content_box(&mut self, tbox: &[u8; 4], data: &[u8]) -> Result<(), Error> {
        let total = u32::try_from(add(HDR_BASE, data.len())?).map_err(|_| Error::LengthOverflow)?;
        self.header(tbox, total)?;
        self.sink.write_all(data)?;
        Ok(())
    }

    /// Open a JUMBF superbox: writes the `jumb` header (placeholder size) and its
    /// `jumd` description box. Balance with [`end_box`](BoxWriter::end_box).
    pub fn start_superbox(
        &mut self,
        uuid: &[u8; 16],
        label: &str,
        salt: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.start_box(&BOX_JUMB)?;
        self.write_description(uuid, label, salt)?;
        Ok(())
    }

    fn write_description(
        &mut self,
        uuid: &[u8; 16],
        label: &str,
        salt: Option<&[u8]>,
    ) -> Result<(), Error> {
        let mut toggles = TOGGLE_REQUESTABLE | TOGGLE_LABEL;
        if salt.is_some() {
            toggles |= TOGGLE_PRIVATE;
        }

        let label_bytes = label.as_bytes();
        // payload = uuid(16) + toggles(1) + label + NUL [+ salt box]
        let mut payload = add(add(16, 1)?, add(label_bytes.len(), 1)?)?;
        if let Some(s) = salt {
            payload = add(payload, add(HDR_BASE, s.len())?)?;
        }
        let total = u32::try_from(add(HDR_BASE, payload)?).map_err(|_| Error::LengthOverflow)?;

        self.header(&BOX_JUMD, total)?;
        self.sink.write_all(uuid)?;
        self.sink.write_all(&[toggles])?;
        self.sink.write_all(label_bytes)?;
        self.sink.write_all(&[0])?;
        if let Some(s) = salt {
            let salt_total =
                u32::try_from(add(HDR_BASE, s.len())?).map_err(|_| Error::LengthOverflow)?;
            self.header(&BOX_SALT, salt_total)?;
            self.sink.write_all(s)?;
        }
        Ok(())
    }

    /// Finish writing and return the sink. Errors if any box is still open.
    pub fn finish(self) -> Result<S, Error> {
        if !self.open.is_empty() {
            return Err(Error::WriteUnfinished);
        }
        Ok(self.sink)
    }
}
