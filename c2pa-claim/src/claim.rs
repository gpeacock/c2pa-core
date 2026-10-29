use serde::{Deserialize, Serialize};

use crate::{GeneratorInfo, HashedUri};

/// Build the absolute JUMBF URI a claim uses to reference its sibling
/// signature box within the manifest identified by `manifest_label`.
///
/// Per spec, the claim's `signature` field "shall contain an absolute URI
/// reference to the claim signature in the same C2PA Manifest" — a plain
/// `self#jumbf=c2pa.signature` (resolved relative to the referencing
/// manifest) is not conformant.
fn signature_uri(manifest_label: &str) -> String {
    format!("self#jumbf=/c2pa/{manifest_label}/c2pa.signature")
}

/// A C2PA v2 claim (`claim-map-v2` in the CDDL): the signed statement that binds
/// a manifest's assertions together.
///
/// This models the current (v2) claim only. The deprecated v1 `claim-map`
/// (`claim_generator` string + `claim_generator_info` array + `assertions` +
/// `dc:format`) is not yet handled.
///
/// `signature` is a plain JUMBF URI string referencing the claim-signature box,
/// not a [`HashedUri`]. The assertion lists are [`HashedUri`]s; redactions are
/// plain JUMBF URI strings.
///
/// Decoding ignores unknown map keys (forward compatibility). To hash or verify
/// a parsed claim, hash its *original* CBOR bytes — do not re-encode a decoded
/// `Claim`, since unknown fields are dropped.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    /// Uniquely identifies a specific version of an asset.
    #[serde(rename = "instanceID")]
    pub instance_id: String,

    /// The generator that produced this claim.
    pub claim_generator_info: GeneratorInfo,

    /// Absolute JUMBF URI reference to this claim's signature box, in the
    /// same manifest (see [`signature_uri`]). Retained as a field because it
    /// is part of the wire format and is read back when parsing.
    pub signature: String,

    /// Assertions created by this claim's generator (`[1* hashed-uri]`).
    pub created_assertions: Vec<HashedUri>,

    /// Assertions gathered from elsewhere, if any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub gathered_assertions: Option<Vec<HashedUri>>,

    /// Human-readable asset title.
    #[serde(rename = "dc:title", skip_serializing_if = "Option::is_none", default)]
    pub title: Option<String>,

    /// JUMBF URIs of ingredient-manifest assertions being redacted.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub redacted_assertions: Option<Vec<String>>,

    /// Default cryptographic hash algorithm for data-hash assertions in this
    /// claim.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alg: Option<String>,

    /// Default soft-binding algorithm for this claim.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alg_soft: Option<String>,
}

impl Claim {
    /// Create a claim with the required v2 fields and no assertions yet.
    ///
    /// `manifest_label` is this claim's enclosing manifest's label, needed to
    /// build the absolute `signature` URI (see [`signature_uri`]). Add
    /// assertions with [`add_created_assertion`](Self::add_created_assertion)
    /// and set optional fields directly. Note that a valid v2 claim requires
    /// at least one created assertion.
    pub fn new(
        manifest_label: &str,
        instance_id: impl Into<String>,
        claim_generator_info: GeneratorInfo,
    ) -> Self {
        Self {
            instance_id: instance_id.into(),
            claim_generator_info,
            signature: signature_uri(manifest_label),
            created_assertions: Vec::new(),
            gathered_assertions: None,
            title: None,
            redacted_assertions: None,
            alg: None,
            alg_soft: None,
        }
    }

    /// Append a created-assertion reference.
    pub fn add_created_assertion(&mut self, assertion: HashedUri) {
        self.created_assertions.push(assertion);
    }

    /// Set the hash of the assertion reference whose `url` is `url`, after the
    /// assertion it refers to was updated in place. Returns `false` if the claim
    /// has no such reference.
    pub fn update_assertion_hash(&mut self, url: &str, hash: &[u8]) -> bool {
        let gathered = self.gathered_assertions.iter_mut().flatten();
        match self
            .created_assertions
            .iter_mut()
            .chain(gathered)
            .find(|a| a.url() == url)
        {
            Some(reference) => {
                reference.set_hash(hash.to_vec());
                true
            }
            None => false,
        }
    }

    /// Encode to deterministic (canonical) CBOR — the form that gets hashed and
    /// signed, as C2PA requires.
    pub fn to_cbor(&self) -> Result<Vec<u8>, c2pa_cbor::Error> {
        c2pa_cbor::to_vec_deterministic(self)
    }

    /// Decode a claim from CBOR bytes (e.g. the `c2pa.claim` box's `cbor`
    /// content from `c2pa_store`).
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, c2pa_cbor::Error> {
        c2pa_cbor::from_slice(bytes)
    }
}
