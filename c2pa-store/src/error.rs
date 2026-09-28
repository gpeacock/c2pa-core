use core::fmt;

/// Errors produced while parsing a manifest store.
///
/// All variants are non-fatal in the sense that the parser returns them instead
/// of panicking or allocating unboundedly. The enum is `#[non_exhaustive]` so
/// new structural checks can be added without a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input ended before a required field could be read.
    UnexpectedEof,
    /// A length or offset computation overflowed `usize`.
    LengthOverflow,
    /// A box declared a length smaller than its own header.
    InvalidBoxLength,
    /// The input did not start with a JUMBF superbox (`jumb`).
    NotASuperbox,
    /// A superbox payload did not begin with a description box (`jumd`).
    MissingDescription,
    /// A label toggle was set but no `NUL` terminator was found.
    MissingLabelTerminator,
    /// A label was not valid UTF-8.
    InvalidUtf8,
    /// Bytes remained after the top-level superbox.
    TrailingBytes,
    /// Nesting exceeded [`crate::Limits::max_depth`].
    DepthExceeded,
    /// A single superbox exceeded [`crate::Limits::max_boxes_per_super`].
    TooManyBoxes,
    /// The tree exceeded [`crate::Limits::max_total_boxes`].
    BoxBudgetExceeded,
    /// The input exceeded [`crate::Limits::max_total_len`].
    InputTooLarge,
    /// The root superbox was not labeled `c2pa`.
    NotAManifestStore,
    /// The manifest had no claim, or the claim had no CBOR content box.
    MissingClaim,
    /// The manifest had no signature, or it had no CBOR content box.
    MissingSignature,
    /// The manifest had no assertion store.
    MissingAssertionStore,
    /// An assertion superbox contained no content box.
    MalformedAssertion,
    /// A box's label is inconsistent with its content-type UUID (e.g. a box
    /// labeled `c2pa.claim` whose UUID is not the claim UUID).
    LabelUuidMismatch,
    /// A string did not start with the `self#jumbf=` JUMBF URI prefix.
    NotAJumbfUri,
    /// A JUMBF URI had an empty path, or a path segment of `..`.
    InvalidJumbfUri,
    /// A JUMBF URI could not be resolved to a box in the store.
    UnresolvedUri,
    /// (write) A box was ended without a matching start.
    WriteUnbalanced,
    /// (write) A box was left open when the writer was finished.
    WriteUnfinished,
    /// (write) The output sink failed.
    WriteFailed,
    /// (write) An assertion was added after the assertion store was
    /// finalized (i.e. after the claim was added).
    AssertionsAlreadyFinalized,
    /// (write, `std`) Reading from a caller-supplied `std::io::Read` source
    /// failed.
    ReadFailed,
    /// (write) A declared embedded-file length didn't match the number of
    /// bytes actually written for it, whether read from a `std::io::Read`
    /// source or supplied chunk-by-chunk via
    /// `EmbeddedFileAssertionWriter::write_chunk`.
    LengthMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::UnexpectedEof => "unexpected end of input",
            Error::LengthOverflow => "length computation overflowed",
            Error::InvalidBoxLength => "box length smaller than its header",
            Error::NotASuperbox => "input is not a JUMBF superbox",
            Error::MissingDescription => "superbox missing description box (jumd)",
            Error::MissingLabelTerminator => "label missing NUL terminator",
            Error::InvalidUtf8 => "label is not valid UTF-8",
            Error::TrailingBytes => "trailing bytes after top-level superbox",
            Error::DepthExceeded => "nesting depth limit exceeded",
            Error::TooManyBoxes => "too many boxes in a superbox",
            Error::BoxBudgetExceeded => "total box budget exceeded",
            Error::InputTooLarge => "input exceeds maximum length",
            Error::NotAManifestStore => "root superbox is not a c2pa manifest store",
            Error::MissingClaim => "manifest has no claim",
            Error::MissingSignature => "manifest has no signature",
            Error::MissingAssertionStore => "manifest has no assertion store",
            Error::MalformedAssertion => "assertion has no content box",
            Error::LabelUuidMismatch => "box label is inconsistent with its content-type UUID",
            Error::NotAJumbfUri => "string does not start with the self#jumbf= prefix",
            Error::InvalidJumbfUri => "JUMBF URI has an empty path or a `..` segment",
            Error::UnresolvedUri => "JUMBF URI did not resolve to a box in the store",
            Error::WriteUnbalanced => "box ended without a matching start",
            Error::WriteUnfinished => "a box was left open when the writer finished",
            Error::WriteFailed => "output sink write failed",
            Error::AssertionsAlreadyFinalized => {
                "assertion added after the assertion store was finalized"
            }
            Error::ReadFailed => "input reader failed",
            Error::LengthMismatch => "declared embedded-file length didn't match bytes written",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for Error {}
