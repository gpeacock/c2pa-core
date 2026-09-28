//! Layer 2: C2PA semantic view over the JUMBF box tree.
//!
//! Interprets the tree produced by [`crate::jumbf`] using C2PA content-type
//! UUIDs (labels are for identity, not type). Every accessor returns borrowed
//! bytes; nothing here decodes CBOR/JSON.

use crate::error::Error;
use crate::jumbf::{parse_root, ContentBox, SuperBox};
use crate::jumbf_uri::JumbfUri;
use crate::limits::Limits;
use crate::uuids::ContentType;

/// Length of the UUID prefix inside a `uuid` content box (signature / UUID
/// assertion), which precedes the actual payload.
const UUID_PREFIX_LEN: usize = 16;

// Reserved C2PA labels whose boxes must carry a specific content-type UUID.
const LABEL_STORE: &str = "c2pa";
const LABEL_CLAIM_PREFIX: &str = "c2pa.claim";
const LABEL_ASSERTIONS: &str = "c2pa.assertions";
const LABEL_SIGNATURE: &str = "c2pa.signature";

/// A parsed C2PA manifest store: the structural root plus its manifests.
///
/// Holds the box tree; all byte accessors borrow from the original input slice
/// (`'a`).
#[derive(Debug)]
pub struct ManifestStore<'a> {
    root: SuperBox<'a>,
}

impl<'a> ManifestStore<'a> {
    /// Parse a manifest store from `bytes` using [`Limits::DEFAULT`].
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::parse_with_limits(bytes, &Limits::DEFAULT)
    }

    /// Parse a manifest store from `bytes` with explicit resource limits.
    ///
    /// The root superbox is validated against the manifest-store content-type
    /// UUID (`c2pa`), not merely its label.
    pub fn parse_with_limits(bytes: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        let root = parse_root(bytes, limits)?;
        if root.content_type() != ContentType::ManifestStore {
            return Err(Error::NotAManifestStore);
        }
        Ok(Self { root })
    }

    /// The full span of the manifest store in the input.
    pub fn raw(&self) -> &'a [u8] {
        self.root.raw
    }

    /// Iterate over the manifests in the store (boxes whose content type is a
    /// manifest type), in order.
    pub fn manifests(&self) -> impl Iterator<Item = Manifest<'_, 'a>> {
        self.root
            .super_children()
            .filter(|s| ManifestKind::from_content_type(s.content_type()).is_some())
            .map(Manifest::new)
    }

    /// Look up a manifest by its label (URN).
    pub fn manifest(&self, label: &str) -> Option<Manifest<'_, 'a>> {
        self.manifests().find(|m| m.label() == Some(label))
    }

    /// The active manifest (the last one in the store), if any.
    pub fn active_manifest(&self) -> Option<Manifest<'_, 'a>> {
        self.manifests().last()
    }

    /// Verify that every box's label is consistent with its content-type UUID.
    ///
    /// Parsing is UUID-authoritative and lenient by default; this opt-in check
    /// rejects stores where a reserved label (`c2pa`, `c2pa.claim*`,
    /// `c2pa.assertions`, `c2pa.signature`) is paired with the wrong UUID, or a
    /// box of a reserved type carries the wrong label — a cheap defense against
    /// boxes that masquerade as something they are not.
    pub fn verify_label_consistency(&self) -> Result<(), Error> {
        check_box_consistency(&self.root)
    }

    /// Resolve a JUMBF URI (e.g. from a `HashedUri`'s `url` field) to its
    /// target box.
    ///
    /// `context` is the manifest containing the reference: a relative URI is
    /// always resolved against it, never against some other manifest in the
    /// store. An absolute URI names its own manifest label and is resolved
    /// against the store root instead. Callers who already decoded a
    /// `HashedUri`'s `alg`/`hash` (this crate does no CBOR decoding or
    /// hashing) can hash the returned box's [`raw`](SuperBox::raw) bytes,
    /// salted with [`salt`](SuperBox::salt) as the format requires, and
    /// compare.
    pub fn resolve<'m>(
        &'m self,
        uri: &JumbfUri<'_>,
        context: &Manifest<'m, 'a>,
    ) -> Result<&'m SuperBox<'a>, Error> {
        let mut segments = uri.segments();
        let mut current: &'m SuperBox<'a> = if uri.is_absolute() {
            if segments.next() != Some(LABEL_STORE) {
                return Err(Error::UnresolvedUri);
            }
            let manifest_label = segments.next().ok_or(Error::UnresolvedUri)?;
            self.manifest(manifest_label)
                .ok_or(Error::UnresolvedUri)?
                .sb
        } else {
            context.sb
        };

        for segment in segments {
            current = current.find_super(segment).ok_or(Error::UnresolvedUri)?;
        }

        Ok(current)
    }
}

/// Recursively check label/UUID consistency for a superbox and its descendants.
fn check_box_consistency(sb: &SuperBox<'_>) -> Result<(), Error> {
    let ct = sb.content_type();
    let label = sb.label();
    if !label_matches_type(ct, label) || !type_matches_label(label, ct) {
        return Err(Error::LabelUuidMismatch);
    }
    for child in sb.super_children() {
        check_box_consistency(child)?;
    }
    Ok(())
}

/// For a box of a reserved content type, does the label match?
fn label_matches_type(ct: ContentType, label: Option<&str>) -> bool {
    match ct {
        ContentType::ManifestStore => label == Some(LABEL_STORE),
        ContentType::Claim => label.is_some_and(|l| l.starts_with(LABEL_CLAIM_PREFIX)),
        ContentType::AssertionStore => label == Some(LABEL_ASSERTIONS),
        ContentType::Signature => label == Some(LABEL_SIGNATURE),
        // Manifests (URN labels), assertions, and other boxes have free labels.
        _ => true,
    }
}

/// For a box carrying a reserved label, does the content type match?
fn type_matches_label(label: Option<&str>, ct: ContentType) -> bool {
    match label {
        Some(l) if l == LABEL_STORE => ct == ContentType::ManifestStore,
        Some(l) if l == LABEL_ASSERTIONS => ct == ContentType::AssertionStore,
        Some(l) if l == LABEL_SIGNATURE => ct == ContentType::Signature,
        Some(l) if l.starts_with(LABEL_CLAIM_PREFIX) => ct == ContentType::Claim,
        _ => true,
    }
}

/// The kind of a C2PA manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestKind {
    /// A standard manifest (`c2ma`).
    Standard,
    /// An update manifest (`c2um`).
    Update,
    /// A `c2md` manifest variant.
    C2md,
    /// A Brotli-compressed manifest (`c2cm`). Its contents are not decompressed
    /// by this crate; use [`Manifest::compressed_box`] to get the raw Brotli
    /// bytes.
    Compressed,
}

impl ManifestKind {
    fn from_content_type(ct: ContentType) -> Option<Self> {
        match ct {
            ContentType::Manifest => Some(ManifestKind::Standard),
            ContentType::UpdateManifest => Some(ManifestKind::Update),
            ContentType::ManifestC2md => Some(ManifestKind::C2md),
            ContentType::CompressedManifest => Some(ManifestKind::Compressed),
            _ => None,
        }
    }
}

/// A single manifest within a [`ManifestStore`].
///
/// `'m` is the borrow of the store's tree; `'a` is the input buffer. Byte
/// accessors return `&'a` data so they outlive this handle.
#[derive(Debug)]
pub struct Manifest<'m, 'a> {
    sb: &'m SuperBox<'a>,
}

impl<'m, 'a> Manifest<'m, 'a> {
    fn new(sb: &'m SuperBox<'a>) -> Self {
        Self { sb }
    }

    /// The manifest label (its URN), if present.
    pub fn label(&self) -> Option<&'a str> {
        self.sb.label()
    }

    /// The kind of this manifest.
    pub fn kind(&self) -> ManifestKind {
        // Safe: only manifest-typed boxes are yielded as `Manifest`.
        ManifestKind::from_content_type(self.sb.content_type()).unwrap_or(ManifestKind::Standard)
    }

    /// The full span of this manifest in the input.
    pub fn raw(&self) -> &'a [u8] {
        self.sb.raw
    }

    /// The manifest's salt, if present in its description box.
    pub fn salt(&self) -> Option<&'a [u8]> {
        self.sb.salt()
    }

    /// For a [`ManifestKind::Compressed`] manifest, the raw Brotli content box
    /// bytes (undecompressed).
    pub fn compressed_box(&self) -> Option<&'a [u8]> {
        self.sb
            .content_children()
            .find(|c| &c.tbox == b"brob")
            .map(|c| c.data)
    }

    /// The raw claim CBOR bytes (undecoded).
    pub fn claim_cbor(&self) -> Result<&'a [u8], Error> {
        let claim = self
            .sb
            .find_super_by_type(ContentType::Claim)
            .ok_or(Error::MissingClaim)?;
        // Select the CBOR content box by type so a `free`/padding box or
        // reordering cannot be mistaken for the claim.
        let content = claim.find_content(b"cbor").ok_or(Error::MissingClaim)?;
        Ok(content.data)
    }

    /// The raw claim-signature bytes (a `COSE_Sign1`, undecoded).
    ///
    /// Modern manifests store the `COSE_Sign1` directly in a `cbor` content box.
    /// A legacy form uses a `uuid` content box with a 16-byte UUID prefix before
    /// the COSE bytes; that prefix is stripped.
    pub fn signature_cose(&self) -> Result<&'a [u8], Error> {
        let sig = self
            .sb
            .find_super_by_type(ContentType::Signature)
            .ok_or(Error::MissingSignature)?;
        if let Some(content) = sig.find_content(b"cbor") {
            return Ok(content.data);
        }
        if let Some(content) = sig.find_content(b"uuid") {
            return content
                .data
                .get(UUID_PREFIX_LEN..)
                .ok_or(Error::MissingSignature);
        }
        Err(Error::MissingSignature)
    }

    /// Iterate over the assertions in this manifest's assertion store.
    pub fn assertions(&self) -> Result<impl Iterator<Item = Assertion<'m, 'a>>, Error> {
        let store = self
            .sb
            .find_super_by_type(ContentType::AssertionStore)
            .ok_or(Error::MissingAssertionStore)?;
        Ok(store.super_children().map(Assertion::new))
    }
}

/// A single assertion within a manifest's assertion store.
#[derive(Debug)]
pub struct Assertion<'m, 'a> {
    sb: &'m SuperBox<'a>,
}

/// The typed content of an assertion.
#[derive(Debug, Clone, Copy)]
pub struct AssertionData<'a> {
    /// The classified content type (from the assertion's description UUID).
    pub content_type: ContentType,
    /// The semantic payload: for CBOR/JSON the raw content bytes; for a UUID
    /// assertion the bytes after the 16-byte UUID prefix; for an embedded file
    /// the `bidb` data-box bytes.
    pub data: &'a [u8],
    /// For a UUID assertion, the 16-byte type UUID.
    pub uuid: Option<[u8; 16]>,
    /// For an embedded-file assertion, the media type, if it could be parsed.
    pub media_type: Option<&'a str>,
    /// For an embedded-file assertion, the file name, if present.
    pub file_name: Option<&'a str>,
    /// The assertion's salt, if present in its description box.
    pub salt: Option<&'a [u8]>,
}

impl<'m, 'a> Assertion<'m, 'a> {
    fn new(sb: &'m SuperBox<'a>) -> Self {
        Self { sb }
    }

    /// The assertion label, if present.
    pub fn label(&self) -> Option<&'a str> {
        self.sb.label()
    }

    /// The assertion's content type.
    pub fn content_type(&self) -> ContentType {
        self.sb.content_type()
    }

    /// The assertion's salt, if present in its description box.
    pub fn salt(&self) -> Option<&'a [u8]> {
        self.sb.salt()
    }

    /// The assertion's typed content.
    ///
    /// The content box is selected by its expected type where the assertion's
    /// content type is known, so a `free`/padding box or reordering can't be
    /// mistaken for the payload.
    pub fn payload(&self) -> Result<AssertionData<'a>, Error> {
        let content_type = self.sb.content_type();
        let salt = self.sb.salt();
        let mut uuid = None;
        let mut media_type = None;
        let mut file_name = None;

        let data = match content_type {
            ContentType::Uuid => {
                let content = self.typed_content(b"uuid")?;
                let raw = content.data;
                let u = raw
                    .get(..UUID_PREFIX_LEN)
                    .ok_or(Error::MalformedAssertion)?;
                let mut arr = [0u8; 16];
                arr.copy_from_slice(u);
                uuid = Some(arr);
                raw.get(UUID_PREFIX_LEN..)
                    .ok_or(Error::MalformedAssertion)?
            }
            ContentType::EmbeddedFile => {
                // The file bytes live in the `bidb` data box; the `bfdb`
                // description box carries the media type (and optional file name).
                let d = self
                    .sb
                    .find_content(b"bidb")
                    .ok_or(Error::MalformedAssertion)?
                    .data;
                if let Some(c) = self.sb.find_content(b"bfdb") {
                    let (m, f) = parse_embedded_desc(c.data);
                    media_type = m;
                    file_name = f;
                }
                d
            }
            ContentType::Cbor => self.typed_content(b"cbor")?.data,
            ContentType::Json => self.typed_content(b"json")?.data,
            ContentType::Codestream => self.typed_content(b"jp2c")?.data,
            ContentType::Brotli => self.typed_content(b"brob")?.data,
            // Unknown assertion type: fall back to the first content box.
            _ => {
                self.sb
                    .first_content()
                    .ok_or(Error::MalformedAssertion)?
                    .data
            }
        };

        Ok(AssertionData {
            content_type,
            data,
            uuid,
            media_type,
            file_name,
            salt,
        })
    }

    /// Find a content box by its expected type, falling back to the first
    /// content box if that exact type isn't present.
    fn typed_content(&self, tbox: &[u8; 4]) -> Result<&ContentBox<'a>, Error> {
        self.sb
            .find_content(tbox)
            .or_else(|| self.sb.first_content())
            .ok_or(Error::MalformedAssertion)
    }
}

/// Parse an embedded-file description (`bfdb`) box payload: a 1-byte toggle,
/// a `NUL`-terminated media type, and — when the toggle is 1 — an optional
/// `NUL`-terminated file name. Best-effort: returns `None` for fields it can't
/// read rather than failing the whole assertion.
fn parse_embedded_desc(bfdb: &[u8]) -> (Option<&str>, Option<&str>) {
    let Some((&toggles, rest)) = bfdb.split_first() else {
        return (None, None);
    };
    if rest.is_empty() {
        return (None, None);
    }

    if toggles == 1 {
        match rest.iter().position(|&b| b == 0) {
            Some(pos) => {
                let media = rest.get(..pos).and_then(|b| core::str::from_utf8(b).ok());
                let file = pos
                    .checked_add(1)
                    .and_then(|start| rest.get(start..))
                    .filter(|after| !after.is_empty())
                    .and_then(|after| {
                        let end = after.iter().position(|&b| b == 0).unwrap_or(after.len());
                        after.get(..end)
                    })
                    .and_then(|b| core::str::from_utf8(b).ok());
                (media, file)
            }
            None => (core::str::from_utf8(rest).ok(), None),
        }
    } else {
        // Single media type; drop a trailing NUL if present.
        let bytes = match rest.split_last() {
            Some((&0, head)) => head,
            _ => rest,
        };
        (core::str::from_utf8(bytes).ok(), None)
    }
}
