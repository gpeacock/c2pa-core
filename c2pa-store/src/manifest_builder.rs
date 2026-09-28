//! A higher-level, stateful wrapper around [`BoxWriter`] that knows the
//! specific JUMBF shape of a C2PA manifest: the store/manifest/assertion-store
//! nesting, which content-type UUID each reserved box needs, and the wire
//! layout of a CBOR assertion vs. an embedded-file assertion. Callers name
//! assertions and hand over bytes; they never touch box types or UUIDs.
//!
//! Unlike the rest of this crate, this module *does* hash: each
//! `add_*_assertion` method needs to hand back a usable reference to what it
//! just wrote immediately, not after the whole store is finished, because a
//! later assertion (an `ingredient` referencing its `thumbnail`, say) embeds
//! that hash in its own body before it can be serialized. The algorithm is
//! fixed to SHA-256 for now (see [`AssertionHash::alg`]); a configurable
//! algorithm is future work. Hashing happens inline as bytes are written, so
//! an assertion's content is never buffered separately just to hash it.
//!
//! The hashed span (per [`SuperBox::payload`](crate::SuperBox::payload)) is
//! everything after the assertion's own 8-byte `jumb` header -- which
//! includes every nested content box's *own* header, not just its data. That
//! matters for streaming: a box's header encodes its total size, so hashing
//! it means the size has to be known and written *before* any of its data --
//! unlike the outer JUMBF box sizes, which `BoxWriter` can backpatch after
//! the fact, a hash can't be corrected once the wrong bytes have already
//! been fed into it. See `add_embedded_file_assertion`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::format::{
    BOX_BFDB, BOX_BIDB, BOX_CBOR, BOX_JUMB, BOX_JUMD, BOX_SALT, TOGGLE_LABEL, TOGGLE_PRIVATE,
    TOGGLE_REQUESTABLE,
};
use crate::uuids;
use crate::box_writer::{BoxWriter, SeekSink};

const LABEL_STORE: &str = "c2pa";
const LABEL_ASSERTIONS: &str = "c2pa.assertions";
const ALG: &str = "sha256";

/// Enough to build a `HashedUri` (in a higher layer, which owns that type)
/// referencing the assertion just added: its JUMBF URI, the hash algorithm
/// used, and the digest of its hashable payload (the assertion box's bytes
/// after its 8-byte header, per the C2PA hashed-URI convention).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionHash {
    /// A relative JUMBF URI: `self#jumbf=c2pa.assertions/<label>`.
    pub url: String,
    /// The hash algorithm used, as a C2PA registry identifier. Currently
    /// always `"sha256"`.
    pub alg: &'static str,
    /// The digest of the assertion's hashable payload.
    pub hash: Vec<u8>,
}

/// Builds a single-manifest C2PA manifest store: `c2pa` > one manifest >
/// (`c2pa.assertions` > assertions) + claim.
///
/// Opens the store, manifest, and assertion-store superboxes on construction.
/// Add assertions with [`add_cbor_assertion`](Self::add_cbor_assertion),
/// [`add_embedded_file_assertion`](Self::add_embedded_file_assertion), or --
/// to supply the payload in chunks over time instead of all at once --
/// [`begin_embedded_file_assertion`](Self::begin_embedded_file_assertion).
/// Then call [`add_claim`](Self::add_claim) -- which finalizes the assertion
/// store, so no more assertions can be added after it -- and finally
/// [`finish`](Self::finish) to get the underlying sink back.
#[derive(Debug)]
pub struct ManifestStoreBuilder<S: SeekSink> {
    writer: BoxWriter<S>,
    assertions_open: bool,
}

impl<S: SeekSink> ManifestStoreBuilder<S> {
    /// Start a new manifest store over `sink`, with one manifest labeled
    /// `manifest_label`.
    pub fn new(sink: S, manifest_label: &str) -> Result<Self, Error> {
        let mut writer = BoxWriter::new(sink);
        writer.start_superbox(&uuids::MANIFEST_STORE, LABEL_STORE, None)?;
        writer.start_superbox(&uuids::MANIFEST, manifest_label, None)?;
        writer.start_superbox(&uuids::ASSERTION_STORE, LABEL_ASSERTIONS, None)?;
        Ok(Self {
            writer,
            assertions_open: true,
        })
    }

    /// Add a CBOR assertion (already-encoded `data`).
    pub fn add_cbor_assertion(
        &mut self,
        label: &str,
        salt: Option<&[u8]>,
        data: &[u8],
    ) -> Result<AssertionHash, Error> {
        let mut hasher = self.begin_assertion(label, salt, &uuids::CBOR)?;
        hash_and_write_content_box(&mut hasher, &mut self.writer, &BOX_CBOR, data)?;
        self.end_assertion(label, hasher)
    }

    /// Add an embedded-file (`c2pa.thumbnail.*`, `c2pa.icon`, ...) assertion
    /// from data already in memory: a `bfdb` description box (media type +
    /// optional file name) plus a `bidb` data box holding `data`. For a large
    /// asset you'd rather not fully buffer, see
    /// [`add_embedded_file_assertion_from_reader`](Self::add_embedded_file_assertion_from_reader).
    pub fn add_embedded_file_assertion(
        &mut self,
        label: &str,
        salt: Option<&[u8]>,
        media_type: &str,
        file_name: Option<&str>,
        data: &[u8],
    ) -> Result<AssertionHash, Error> {
        let mut hasher = self.begin_assertion(label, salt, &uuids::EMBEDDED_FILE)?;
        let bfdb = embedded_file_description(media_type, file_name);
        hash_and_write_content_box(&mut hasher, &mut self.writer, &BOX_BFDB, &bfdb)?;
        hash_and_write_content_box(&mut hasher, &mut self.writer, &BOX_BIDB, data)?;
        self.end_assertion(label, hasher)
    }

    /// Begin an embedded-file assertion whose payload will be supplied in
    /// chunks over time -- via repeated calls to
    /// [`write_chunk`](EmbeddedFileAssertionWriter::write_chunk) -- rather
    /// than all at once or via a blocking [`std::io::Read`]. Consumes this
    /// builder and hands it back inside the returned
    /// [`EmbeddedFileAssertionWriter`], which owns it until the assertion is
    /// [`finish`](EmbeddedFileAssertionWriter::finish)ed or
    /// [`cancel`](EmbeddedFileAssertionWriter::cancel)led. Because it's a
    /// plain owned value with no borrow back into this builder, it can be
    /// stored in a state machine or driven one chunk at a time from an async
    /// task, paused and resumed across suspension points, without ever
    /// blocking on the whole payload being available up front.
    ///
    /// `len` still has to be known upfront, for the same reason as
    /// [`add_embedded_file_assertion_from_reader`](Self::add_embedded_file_assertion_from_reader):
    /// the `bidb` box's header encodes its length and is hashed before any of
    /// its data.
    ///
    /// If this returns `Err`, the builder is dropped along with it rather
    /// than handed back -- the only ways this fails
    /// ([`Error::AssertionsAlreadyFinalized`] or a `len`/label that overflows
    /// a box header) indicate a programming error rather than a recoverable
    /// runtime condition, so there's no meaningful builder state left to
    /// resume with.
    pub fn begin_embedded_file_assertion(
        mut self,
        label: &str,
        salt: Option<&[u8]>,
        media_type: &str,
        file_name: Option<&str>,
        len: u64,
    ) -> Result<EmbeddedFileAssertionWriter<S>, Error> {
        let mut hasher = self.begin_assertion(label, salt, &uuids::EMBEDDED_FILE)?;
        let bfdb = embedded_file_description(media_type, file_name);
        hash_and_write_content_box(&mut hasher, &mut self.writer, &BOX_BFDB, &bfdb)?;

        let bidb_header = content_box_header(&BOX_BIDB, len)?;
        hasher.update(&bidb_header);
        self.writer.write(&bidb_header)?;

        Ok(EmbeddedFileAssertionWriter {
            builder: self,
            label: String::from(label),
            hasher,
            len,
            written: 0,
        })
    }

    /// Same as [`add_embedded_file_assertion`](Self::add_embedded_file_assertion),
    /// but reads `data` in chunks instead of requiring it all in memory at
    /// once -- useful for a large asset read from a file. `len` (its exact
    /// byte length) has to be known upfront regardless: the `bidb` box's
    /// header encodes that length and must be hashed *before* any of its
    /// data, unlike the outer JUMBF box sizes, which `BoxWriter` can
    /// backpatch after the fact -- a hash can't be corrected once the wrong
    /// bytes have already been fed into it. (A `Read + Seek` bound could
    /// derive `len` itself via seek-to-end-and-back; taking it as a plain
    /// parameter is simpler for now.) A short or long read against the
    /// declared `len` is reported as [`Error::LengthMismatch`] rather than
    /// silently hashing the wrong thing.
    #[cfg(feature = "std")]
    pub fn add_embedded_file_assertion_from_reader(
        &mut self,
        label: &str,
        salt: Option<&[u8]>,
        media_type: &str,
        file_name: Option<&str>,
        len: u64,
        mut data: impl std::io::Read,
    ) -> Result<AssertionHash, Error> {
        let mut hasher = self.begin_assertion(label, salt, &uuids::EMBEDDED_FILE)?;

        let bfdb = embedded_file_description(media_type, file_name);
        hash_and_write_content_box(&mut hasher, &mut self.writer, &BOX_BFDB, &bfdb)?;

        let bidb_header = content_box_header(&BOX_BIDB, len)?;
        hasher.update(&bidb_header);
        self.writer.write(&bidb_header)?;

        let mut buf = [0u8; 64 * 1024];
        let mut read_total: u64 = 0;
        loop {
            let n = data.read(&mut buf).map_err(|_| Error::ReadFailed)?;
            if n == 0 {
                break;
            }
            let chunk = buf.get(..n).ok_or(Error::LengthOverflow)?;
            hasher.update(chunk);
            self.writer.write(chunk)?;
            read_total = read_total
                .checked_add(u64::try_from(n).map_err(|_| Error::LengthOverflow)?)
                .ok_or(Error::LengthOverflow)?;
        }
        if read_total != len {
            return Err(Error::LengthMismatch);
        }

        self.end_assertion(label, hasher)
    }

    /// Open the assertion superbox and hash its `jumd` description (header
    /// included), leaving the box open for the caller to write and hash its
    /// content box(es).
    fn begin_assertion(
        &mut self,
        label: &str,
        salt: Option<&[u8]>,
        content_uuid: &[u8; 16],
    ) -> Result<Sha256, Error> {
        if !self.assertions_open {
            return Err(Error::AssertionsAlreadyFinalized);
        }
        self.writer.start_box(&BOX_JUMB)?;
        let jumd = jumd_payload(content_uuid, label, salt)?;
        let mut hasher = Sha256::new();
        hash_and_write_content_box(&mut hasher, &mut self.writer, &BOX_JUMD, &jumd)?;
        Ok(hasher)
    }

    /// Close the assertion superbox opened by `begin_assertion` and turn the
    /// finished hasher into an `AssertionHash`.
    fn end_assertion(&mut self, label: &str, hasher: Sha256) -> Result<AssertionHash, Error> {
        self.writer.end_box()?;
        Ok(AssertionHash {
            url: format!("self#jumbf=c2pa.assertions/{label}"),
            alg: ALG,
            hash: hasher.finalize().to_vec(),
        })
    }

    /// Finalize the assertion store (if not already done) and add the claim:
    /// a superbox labeled `claim_label` (e.g. `c2pa.claim.v2`) holding
    /// `claim_cbor` in a `cbor` content box. No more assertions can be added
    /// after this.
    pub fn add_claim(&mut self, claim_label: &str, claim_cbor: &[u8]) -> Result<(), Error> {
        self.finalize_assertions()?;
        self.writer
            .start_superbox(&uuids::CLAIM, claim_label, None)?;
        self.writer.content_box(&BOX_CBOR, claim_cbor)?;
        self.writer.end_box()?;
        Ok(())
    }

    fn finalize_assertions(&mut self) -> Result<(), Error> {
        if self.assertions_open {
            self.writer.end_box()?;
            self.assertions_open = false;
        }
        Ok(())
    }

    /// Close the manifest and store superboxes and return the underlying
    /// sink. Errs if a box was left open in a way `BoxWriter` can't balance
    /// (see [`BoxWriter::finish`]).
    pub fn finish(mut self) -> Result<S, Error> {
        self.finalize_assertions()?;
        self.writer.end_box()?; // manifest
        self.writer.end_box()?; // c2pa (store)
        self.writer.finish()
    }
}

/// An embedded-file assertion opened by
/// [`ManifestStoreBuilder::begin_embedded_file_assertion`], with its `bidb`
/// header already written but not yet all of its data. Owns the
/// `ManifestStoreBuilder` for as long as it's open, so it's a plain movable
/// value -- no borrow back into the builder -- suitable for storing in a
/// state machine or driving from an async task one [`write_chunk`](Self::write_chunk)
/// at a time, pausing and resuming across suspension points freely.
///
/// Cancelling ([`cancel`](Self::cancel)) can't undo bytes already handed to
/// the sink -- `BoxWriter` backpatches box *sizes* after the fact, but never
/// retracts data already written -- so there's no way to leave the builder in
/// a usable state afterward; it discards the builder (and with it, the whole
/// in-progress store). Start a new [`ManifestStoreBuilder`] to try again.
#[derive(Debug)]
pub struct EmbeddedFileAssertionWriter<S: SeekSink> {
    builder: ManifestStoreBuilder<S>,
    label: String,
    hasher: Sha256,
    len: u64,
    written: u64,
}

impl<S: SeekSink> EmbeddedFileAssertionWriter<S> {
    /// Bytes written so far, for progress reporting.
    pub fn bytes_written(&self) -> u64 {
        self.written
    }

    /// The total length declared in
    /// [`begin_embedded_file_assertion`](ManifestStoreBuilder::begin_embedded_file_assertion).
    pub fn total_len(&self) -> u64 {
        self.len
    }

    /// Write the next chunk of the embedded file's data. Chunks can be any
    /// size and arrive over any number of calls; each call does exactly one
    /// hash update and one sink write, so it never blocks on more data than
    /// what's handed to it in `chunk`. Errs with [`Error::LengthMismatch`] if
    /// this or a prior call would write more bytes than `total_len()`.
    pub fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), Error> {
        let new_total = self
            .written
            .checked_add(chunk.len() as u64)
            .ok_or(Error::LengthOverflow)?;
        if new_total > self.len {
            return Err(Error::LengthMismatch);
        }
        self.hasher.update(chunk);
        self.builder.writer.write(chunk)?;
        self.written = new_total;
        Ok(())
    }

    /// Close the assertion once exactly `total_len()` bytes have been
    /// written via [`write_chunk`](Self::write_chunk) -- erring with
    /// [`Error::LengthMismatch`] otherwise -- and return the builder (so more
    /// assertions or the claim can be added) along with the finished
    /// assertion's hash.
    pub fn finish(self) -> Result<(ManifestStoreBuilder<S>, AssertionHash), Error> {
        if self.written != self.len {
            return Err(Error::LengthMismatch);
        }
        let EmbeddedFileAssertionWriter {
            mut builder,
            label,
            hasher,
            ..
        } = self;
        let hash = builder.end_assertion(&label, hasher)?;
        Ok((builder, hash))
    }

    /// Abandon the assertion, discarding the builder (and with it the whole
    /// in-progress store) since bytes already written to the sink can't be
    /// retracted. Start a new [`ManifestStoreBuilder`] to try again.
    pub fn cancel(self) {}
}

/// Build a complete content box's header (`size` + `tbox`, matching what
/// [`BoxWriter::content_box`] writes), feed it plus `data` to `hasher`, and
/// write the box (header + `data`) via `writer.content_box`. Keeps the
/// hashed bytes and the written bytes for a box provably identical.
fn hash_and_write_content_box<S: SeekSink>(
    hasher: &mut Sha256,
    writer: &mut BoxWriter<S>,
    tbox: &[u8; 4],
    data: &[u8],
) -> Result<(), Error> {
    let header = content_box_header(tbox, data.len() as u64)?;
    hasher.update(&header);
    hasher.update(data);
    writer.content_box(tbox, data)
}

/// The 8-byte header (`size` + `tbox`) a content box of `data_len` bytes of
/// payload would have on the wire.
fn content_box_header(tbox: &[u8; 4], data_len: u64) -> Result<Vec<u8>, Error> {
    let total = data_len.checked_add(8).ok_or(Error::LengthOverflow)?;
    let total = u32::try_from(total).map_err(|_| Error::LengthOverflow)?;
    let mut header = Vec::with_capacity(8);
    header.extend_from_slice(&total.to_be_bytes());
    header.extend_from_slice(tbox);
    Ok(header)
}

/// Build a `jumd` description box *payload* (not yet wrapped in its own
/// header): `uuid(16) + toggles(1) + label + NUL [+ salt content box]`.
/// Deliberately mirrors `box_writer::BoxWriter::write_description` rather than
/// reusing it: that method writes straight to the sink with no way to also
/// feed the same bytes to a hasher, and the format itself (spec-fixed JUMBF
/// description-box layout) is tiny and stable.
fn jumd_payload(uuid: &[u8; 16], label: &str, salt: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    let mut toggles = TOGGLE_REQUESTABLE | TOGGLE_LABEL;
    if salt.is_some() {
        toggles |= TOGGLE_PRIVATE;
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(uuid);
    payload.push(toggles);
    payload.extend_from_slice(label.as_bytes());
    payload.push(0);
    if let Some(s) = salt {
        let salt_box_len = u32::try_from(s.len().checked_add(8).ok_or(Error::LengthOverflow)?)
            .map_err(|_| Error::LengthOverflow)?;
        payload.extend_from_slice(&salt_box_len.to_be_bytes());
        payload.extend_from_slice(&BOX_SALT);
        payload.extend_from_slice(s);
    }
    Ok(payload)
}

/// Encode a `bfdb` embedded-file description box payload: a 1-byte toggle, a
/// `NUL`-terminated media type, and -- when a file name is given -- the
/// toggle set to `1` followed by a `NUL`-terminated file name. Mirrors
/// `c2pa_store`'s own read side (`store::parse_embedded_desc`) exactly.
fn embedded_file_description(media_type: &str, file_name: Option<&str>) -> Vec<u8> {
    let mut v = Vec::new();
    match file_name {
        Some(name) => {
            v.push(1);
            v.extend_from_slice(media_type.as_bytes());
            v.push(0);
            v.extend_from_slice(name.as_bytes());
            v.push(0);
        }
        None => {
            v.push(0);
            v.extend_from_slice(media_type.as_bytes());
        }
    }
    v
}
