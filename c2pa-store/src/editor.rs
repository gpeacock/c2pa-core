//! Same-size, in-place edits to a manifest store that has already been written.
//!
//! A manifest embedded in an asset is written once as a placeholder, so the
//! asset's layout around it can be fixed and hashed, then completed without
//! moving anything: the hard-binding assertion gets its real values, the claim
//! the assertion's new hash, and the signature the signed claim. Each edit
//! replaces one box's content with bytes of exactly the same length. The
//! values themselves (what a binding hashes, how a claim is signed) belong to
//! higher layers; this only finds the box and writes it.

use alloc::format;

use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::manifest_builder::AssertionHash;
use crate::store::{Manifest, ManifestStore};

/// Edits a written manifest store in place. Every edit keeps every box the same
/// size, so the store, and any asset that embeds it, keeps its layout.
#[derive(Debug)]
pub struct ManifestStoreEditor<'a> {
    bytes: &'a mut [u8],
}

impl<'a> ManifestStoreEditor<'a> {
    /// Edit the manifest store in `bytes`.
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }

    /// Replace the content of assertion `assertion_label` in manifest
    /// `manifest_label` with `data` (for a CBOR assertion, its CBOR), which must be
    /// exactly as long as what it replaces. Returns the assertion's new hash, as
    /// [`ManifestStoreBuilder`](crate::ManifestStoreBuilder) would have computed
    /// it, for the claim's reference to it.
    pub fn update_assertion(
        &mut self,
        manifest_label: &str,
        assertion_label: &str,
        data: &[u8],
    ) -> Result<AssertionHash, Error> {
        self.replace(manifest_label, Target::Assertion(assertion_label), data)?;

        let store = ManifestStore::parse(self.bytes)?;
        let manifest = store.manifest(manifest_label).ok_or(Error::UnresolvedUri)?;
        let assertion = manifest
            .assertions()?
            .find(|a| a.label() == Some(assertion_label))
            .ok_or(Error::UnresolvedUri)?;
        Ok(AssertionHash {
            url: format!("self#jumbf=c2pa.assertions/{assertion_label}"),
            alg: "sha256",
            hash: Sha256::digest(assertion.hashed_bytes()).to_vec(),
        })
    }

    /// Replace the claim CBOR of manifest `manifest_label`; `claim_cbor` must be
    /// exactly as long as the claim it replaces.
    pub fn update_claim(&mut self, manifest_label: &str, claim_cbor: &[u8]) -> Result<(), Error> {
        self.replace(manifest_label, Target::Claim, claim_cbor)
    }

    /// Replace the claim signature (`COSE_Sign1`) of manifest `manifest_label`;
    /// `signature_cbor` must be exactly as long as the signature it replaces.
    pub fn update_signature(
        &mut self,
        manifest_label: &str,
        signature_cbor: &[u8],
    ) -> Result<(), Error> {
        self.replace(manifest_label, Target::Signature, signature_cbor)
    }

    /// Overwrite `target` in manifest `manifest_label` with `data`.
    fn replace(
        &mut self,
        manifest_label: &str,
        target: Target<'_>,
        data: &[u8],
    ) -> Result<(), Error> {
        let (start, len) = {
            let store = ManifestStore::parse(self.bytes)?;
            let manifest = store.manifest(manifest_label).ok_or(Error::UnresolvedUri)?;
            let target = target.locate(&manifest)?;
            let start = (target.as_ptr() as usize)
                .checked_sub(self.bytes.as_ptr() as usize)
                .ok_or(Error::LengthOverflow)?;
            (start, target.len())
        };
        if data.len() != len {
            return Err(Error::SizeChanged);
        }
        let end = start.checked_add(len).ok_or(Error::LengthOverflow)?;
        self.bytes
            .get_mut(start..end)
            .ok_or(Error::UnexpectedEof)?
            .copy_from_slice(data);
        Ok(())
    }
}

/// Which content of a manifest an edit replaces.
#[derive(Clone, Copy)]
enum Target<'l> {
    Assertion(&'l str),
    Claim,
    Signature,
}

impl Target<'_> {
    fn locate<'b>(self, manifest: &Manifest<'_, 'b>) -> Result<&'b [u8], Error> {
        match self {
            Target::Assertion(label) => {
                let assertion = manifest
                    .assertions()?
                    .find(|a| a.label() == Some(label))
                    .ok_or(Error::UnresolvedUri)?;
                Ok(assertion.payload()?.data)
            }
            Target::Claim => manifest.claim_cbor(),
            Target::Signature => manifest.signature_cose(),
        }
    }
}
