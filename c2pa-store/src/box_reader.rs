use crate::error::Error;

/// A bounds-checked, non-panicking cursor over a borrowed byte slice.
///
/// This is the **only** place raw byte access happens. Every read is checked
/// against the remaining length and every offset computation is overflow-checked,
/// so nothing downstream needs to index or slice directly.
pub(crate) struct BoxReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BoxReader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Consume exactly `n` bytes, returning a borrowed slice.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::LengthOverflow)?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }

    /// Consume a `NUL`-terminated string, returning the bytes before the `NUL`
    /// and advancing past the terminator. Fields may follow, so this must not be
    /// greedy.
    pub(crate) fn read_cstr(&mut self) -> Result<&'a [u8], Error> {
        let rest = self.buf.get(self.pos..).ok_or(Error::UnexpectedEof)?;
        let nul = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(Error::MissingLabelTerminator)?;
        let out = rest.get(..nul).ok_or(Error::UnexpectedEof)?;
        let past = nul.checked_add(1).ok_or(Error::LengthOverflow)?;
        self.pos = self.pos.checked_add(past).ok_or(Error::LengthOverflow)?;
        Ok(out)
    }

    /// Borrow an absolute sub-range of the underlying buffer without moving the
    /// cursor. Used to recover the full span of a box after its payload is read.
    pub(crate) fn slice(&self, start: usize, end: usize) -> Result<&'a [u8], Error> {
        self.buf.get(start..end).ok_or(Error::UnexpectedEof)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        self.take(1)?.first().copied().ok_or(Error::UnexpectedEof)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        let arr: [u8; 4] = self.take(4)?.try_into().map_err(|_| Error::UnexpectedEof)?;
        Ok(u32::from_be_bytes(arr))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        let arr: [u8; 8] = self.take(8)?.try_into().map_err(|_| Error::UnexpectedEof)?;
        Ok(u64::from_be_bytes(arr))
    }

    pub(crate) fn array16(&mut self) -> Result<[u8; 16], Error> {
        self.take(16)?.try_into().map_err(|_| Error::UnexpectedEof)
    }
}
