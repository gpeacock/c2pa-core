use c2pa_store::{Manifest, ManifestStore};
use serde::{Deserialize, Serialize};

/// Why a [`HashedUri`] failed to verify against a manifest store.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// The `url` was not a valid JUMBF URI.
    Uri(c2pa_store::Error),
    /// The URI did not resolve to a box in the store.
    Unresolved(c2pa_store::Error),
    /// No hash algorithm was available: the URI omitted `alg` and the caller
    /// supplied no default (a claim provides one for its hashed URIs).
    MissingAlg,
    /// The `alg` identifier is not a supported C2PA hash algorithm.
    UnknownAlg(String),
    /// The referenced box's payload did not hash to the stored value.
    HashMismatch,
}

/// A reference to content elsewhere in a manifest store: a JUMBF URI plus the
/// hash of the referenced box's content.
///
/// Wire-compatible with the C2PA `hashed-uri` CDDL — a CBOR map with `url`
/// (text), optional `alg` (text), and `hash` (byte string). `salt` is *not*
/// part of the CBOR: it lives in the referenced JUMBF box's private `c2sh`
/// field (exposed by [`c2pa_store`]'s `SuperBox::salt`), so it is tracked here
/// separately and never (de)serialized.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashedUri {
    url: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    alg: Option<String>,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
    #[serde(skip_serializing, skip_deserializing, default)]
    salt: Option<Vec<u8>>,
}

impl HashedUri {
    /// Create a hashed URI from a JUMBF URI, an optional algorithm identifier,
    /// and the hash digest bytes.
    pub fn new(url: impl Into<String>, alg: Option<String>, hash: &[u8]) -> Self {
        Self {
            url: url.into(),
            alg,
            hash: hash.to_vec(),
            salt: None,
        }
    }

    /// The JUMBF URI string (e.g. `self#jumbf=/c2pa/.../c2pa.assertions/...`).
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Parse the `url` as a [`c2pa_store::JumbfUri`] for structural resolution
    /// against a manifest store.
    pub fn jumbf_uri(&self) -> Result<c2pa_store::JumbfUri<'_>, c2pa_store::Error> {
        c2pa_store::JumbfUri::parse(&self.url)
    }

    /// The hash algorithm identifier, if present (e.g. `sha256`).
    pub fn alg(&self) -> Option<&str> {
        self.alg.as_deref()
    }

    /// The hash digest bytes.
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    /// Replace the hash digest — used while building a claim, once the
    /// referenced box's bytes are known and hashed.
    pub fn set_hash(&mut self, hash: Vec<u8>) {
        self.hash = hash;
    }

    /// The salt associated with the referenced box, if tracked. Not serialized.
    pub fn salt(&self) -> Option<&[u8]> {
        self.salt.as_deref()
    }

    /// Set the salt associated with the referenced box. Not serialized.
    pub fn set_salt(&mut self, salt: Option<Vec<u8>>) {
        self.salt = salt;
    }

    /// Encode to deterministic (canonical) CBOR, as C2PA requires for the
    /// structures that get hashed and signed.
    pub fn to_cbor(&self) -> Result<Vec<u8>, c2pa_cbor::Error> {
        c2pa_cbor::to_vec_deterministic(self)
    }

    /// Decode from CBOR bytes, as found inside a claim.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, c2pa_cbor::Error> {
        c2pa_cbor::from_slice(bytes)
    }

    /// Verify this reference against a manifest store: resolve the URI, hash the
    /// referenced box's payload under the effective algorithm, and compare it to
    /// the stored [`hash`](Self::hash).
    ///
    /// `context` is the manifest containing the reference (used to resolve a
    /// relative URI). `default_alg` supplies the algorithm when this URI omits
    /// `alg` — a claim sets a single default for all of its hashed URIs.
    ///
    /// The referenced box's salt, when present, is already embedded in its
    /// `jumd` description and therefore part of the hashed payload; no separate
    /// salt handling is needed here.
    pub fn verify<'a>(
        &self,
        store: &ManifestStore<'a>,
        context: &Manifest<'_, 'a>,
        default_alg: Option<&str>,
    ) -> Result<(), VerifyError> {
        let uri = self.jumbf_uri().map_err(VerifyError::Uri)?;
        let target = store
            .resolve(&uri, context)
            .map_err(VerifyError::Unresolved)?;
        let alg = self.alg().or(default_alg).ok_or(VerifyError::MissingAlg)?;
        let computed = crate::hash::digest(alg, target.payload())
            .ok_or_else(|| VerifyError::UnknownAlg(alg.to_string()))?;
        if computed == self.hash {
            Ok(())
        } else {
            Err(VerifyError::HashMismatch)
        }
    }
}
