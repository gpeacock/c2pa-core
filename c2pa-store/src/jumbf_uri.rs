//! JUMBF URI syntax: the `self#jumbf=` path-addressing scheme used to
//! reference a box by its label path (C2PA `Architecture/Unique_Identifiers`).
//!
//! This layer knows only the path grammar — the `self#jumbf=` prefix, absolute
//! (`/c2pa/...`) vs relative paths, and segment splitting. It knows nothing
//! about what any segment means (e.g. that `c2pa.assertions` is reserved);
//! resolving a [`JumbfUri`] against a parsed tree uses that C2PA-specific
//! knowledge and lives on [`crate::ManifestStore`].

use crate::error::Error;

const PREFIX: &str = "self#jumbf=";

/// A parsed JUMBF URI: a `self#jumbf=` path, either absolute (anchored at the
/// manifest store root, e.g. `/c2pa/urn:c2pa:.../c2pa.assertions/...`) or
/// relative to whichever manifest contains the reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JumbfUri<'a> {
    path: &'a str,
}

impl<'a> JumbfUri<'a> {
    /// Parse a `self#jumbf=` URI.
    ///
    /// Rejects strings that don't carry the `self#jumbf=` prefix, have an
    /// empty path, or contain a `..` segment (per spec, a JUMBF URI must never
    /// contain `..`).
    pub fn parse(s: &'a str) -> Result<Self, Error> {
        let path = s.strip_prefix(PREFIX).ok_or(Error::NotAJumbfUri)?;
        if path.is_empty() {
            return Err(Error::InvalidJumbfUri);
        }
        if path.split('/').any(|seg| seg == "..") {
            return Err(Error::InvalidJumbfUri);
        }
        Ok(Self { path })
    }

    /// True if this URI is absolute (its path starts with `/`), anchored at
    /// the manifest store root rather than resolved relative to the
    /// referencing manifest.
    pub fn is_absolute(&self) -> bool {
        self.path.starts_with('/')
    }

    /// The path segments, in order, with any leading `/` and empty segments
    /// removed.
    pub fn segments(&self) -> impl Iterator<Item = &'a str> {
        self.path.split('/').filter(|s| !s.is_empty())
    }
}
