//! Integrity checks, deliberately separate from certificate trust evaluation.

use std::fs::File;

use asset_io::Structure;
use c2pa_cbor::Value;
use c2pa_cbor::cose::{CoseSign1, Label};
use c2pa_claim::{BoxHash, DataHash, HashedUri};
use c2pa_store::{ContentType, JumbfUri, ManifestStore};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use x509_parser::prelude::parse_x509_certificate;

use crate::{Result, asset};

#[derive(Deserialize)]
struct AnyClaim {
    signature: String,
    #[serde(default)]
    created_assertions: Vec<HashedUri>,
    #[serde(default)]
    gathered_assertions: Vec<HashedUri>,
    #[serde(default)]
    assertions: Vec<HashedUri>,
    #[serde(default)]
    alg: Option<String>,
}

#[derive(Debug)]
pub struct ValidationReport {
    pub manifests: usize,
    pub assertions: usize,
    pub signatures: usize,
    /// The label of the active hard binding that was checked.
    pub binding: &'static str,
    /// The binding excludes something besides the C2PA store (informational,
    /// `assertion.boxesHash.additionalExclusionsPresent`).
    pub additional_exclusions: bool,
}

/// The active manifest's hard binding.
enum ActiveBinding {
    Data(DataHash),
    Boxes(BoxHash),
}

fn verify_signature(bytes: &[u8], claim: &[u8]) -> Result<()> {
    let mut signature = CoseSign1::from_tagged_slice(bytes)?;
    if signature.protected.header.alg != Some(-8) {
        return Err(
            "unsupported signature algorithm: only protected EdDSA/Ed25519 is implemented".into(),
        );
    }
    if signature
        .protected
        .header
        .rest
        .iter()
        .chain(&signature.unprotected.rest)
        .any(|(label, _)| *label == Label::Int(2))
    {
        return Err("critical COSE headers are not supported by this experimental verifier".into());
    }
    if signature
        .payload
        .as_deref()
        .is_some_and(|payload| payload != claim)
    {
        return Err("COSE payload does not match the manifest's claim".into());
    }
    let chain = signature
        .protected
        .header
        .rest
        .iter()
        .chain(&signature.unprotected.rest)
        .filter(|(label, _)| *label == Label::Int(33))
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    if chain.len() != 1 {
        return Err("signature must contain exactly one x5chain header".into());
    }
    let der = match chain[0] {
        Value::Bytes(der) => der,
        Value::Array(certs) => match certs.first() {
            Some(Value::Bytes(der)) => der,
            _ => return Err("x5chain has no end-entity certificate".into()),
        },
        _ => return Err("invalid x5chain header".into()),
    };
    let (remaining, certificate) =
        parse_x509_certificate(der).map_err(|e| format!("parse signing certificate: {e}"))?;
    if !remaining.is_empty() {
        return Err("trailing data in signing certificate".into());
    }
    let spki = certificate.public_key();
    if spki.algorithm.algorithm.to_id_string() != "1.3.101.112"
        || spki.subject_public_key.unused_bits != 0
    {
        return Err("unsupported certificate public key: expected Ed25519".into());
    }
    let key: &[u8; 32] = spki
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| "invalid Ed25519 public key length")?;
    let key = VerifyingKey::from_bytes(key)?;
    signature.payload = Some(claim.to_vec());
    key.verify_strict(
        &signature.tbs_data(&[])?,
        &Signature::from_slice(&signature.signature)?,
    )?;
    Ok(())
}

/// Verify structure, all claims' assertion references and Ed25519 signatures,
/// then the active manifest's data hash against the current asset.
/// Historical manifests' asset hashes describe older versions, not this file.
/// Certificate paths, trust, revocation, timestamps and ingredients are NOT verified.
pub fn validate(
    bytes: &[u8],
    file: &mut File,
    structure: &Structure,
    embedded: bool,
) -> Result<ValidationReport> {
    let store = ManifestStore::parse(bytes)?;
    store.verify_label_consistency()?;
    let manifests: Vec<_> = store.manifests().collect();
    if manifests.is_empty() {
        return Err("manifest store is empty".into());
    }
    let mut report = ValidationReport {
        manifests: manifests.len(),
        assertions: 0,
        signatures: 0,
        binding: "",
        additional_exclusions: false,
    };
    let mut active_binding = None;
    for (index, manifest) in manifests.iter().enumerate() {
        let claim_bytes = manifest.claim_cbor()?;
        let claim: AnyClaim = c2pa_cbor::from_slice(claim_bytes)?;
        let target = store.resolve(&JumbfUri::parse(&claim.signature)?, manifest)?;
        let offset = (target.raw.as_ptr() as usize)
            .checked_sub(manifest.raw().as_ptr() as usize)
            .and_then(|offset| offset.checked_add(target.raw.len()));
        if target.content_type() != ContentType::Signature
            || !offset.is_some_and(|end| end <= manifest.raw().len())
        {
            return Err("claim signature URI does not point inside its own manifest".into());
        }
        let signature = if let Some(content) = target.find_content(b"cbor") {
            content.data
        } else {
            target
                .find_content(b"uuid")
                .and_then(|content| content.data.get(16..))
                .ok_or("referenced signature has no COSE payload")?
        };
        verify_signature(signature, claim_bytes)?;
        report.signatures += 1;
        let refs = claim
            .created_assertions
            .iter()
            .chain(&claim.gathered_assertions)
            .chain(&claim.assertions);
        let mut count = 0;
        for href in refs {
            href.verify(&store, manifest, claim.alg.as_deref())
                .map_err(|e| format!("assertion {}: {e:?}", href.url()))?;
            count += 1;
            if index + 1 == manifests.len() {
                let target = store.resolve(&href.jumbf_uri()?, manifest)?;
                let label = target.label();
                if label == Some(DataHash::LABEL) || label == Some(BoxHash::LABEL) {
                    if target.content_type() != ContentType::Cbor {
                        return Err("hard-binding assertion has the wrong content-type UUID".into());
                    }
                    if active_binding.is_some() {
                        return Err("multiple active hard bindings are unsupported".into());
                    }
                    let content = target
                        .find_content(b"cbor")
                        .ok_or("hard binding is not CBOR")?;
                    let binding = if label == Some(DataHash::LABEL) {
                        ActiveBinding::Data(DataHash::from_cbor(content.data)?)
                    } else {
                        ActiveBinding::Boxes(BoxHash::from_cbor(content.data)?)
                    };
                    active_binding = Some((binding, claim.alg.clone()));
                } else if target
                    .label()
                    .is_some_and(|label| label.starts_with("c2pa.hash."))
                {
                    return Err(format!("unsupported hard binding: {:?}", target.label()).into());
                }
            }
        }
        if count == 0 {
            return Err("claim has no assertion references".into());
        }
        report.assertions += count;
    }
    let (binding, default_alg) = active_binding.ok_or(
        "active manifest has no supported, signed c2pa.hash.data or c2pa.hash.boxes binding",
    )?;
    let binding = match binding {
        ActiveBinding::Data(binding) => binding,
        ActiveBinding::Boxes(binding) => {
            if !embedded {
                return Err(
                    "a box hash binds an embedded manifest; detached validation needs a data hash"
                        .into(),
                );
            }
            let boxes = structure.c2pa_boxes(file)?;
            let found =
                binding.verify(file, &asset::asset_boxes(&boxes), default_alg.as_deref())?;
            report.additional_exclusions = found.additional_exclusions;
            report.binding = BoxHash::LABEL;
            return Ok(report);
        }
    };
    report.binding = DataHash::LABEL;
    let expected = if embedded {
        asset::exclusions(structure, file)?
    } else {
        Vec::new()
    };
    let ranges = binding.exclusions.as_deref().unwrap_or_default();
    if ranges != expected {
        return Err(
            "data-hash exclusions differ from the supported container's manifest ranges".into(),
        );
    }
    let alg = binding
        .alg
        .as_deref()
        .or(default_alg.as_deref())
        .ok_or("data hash has no algorithm")?;
    let actual = asset::hash_asset(file, structure.total_size(), alg, ranges)?;
    if actual != binding.hash {
        return Err("asset data-hash mismatch".into());
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use c2pa_cbor::cose::{CoseSign1Builder, HeaderBuilder};

    #[test]
    fn unsupported_signature_algorithms_fail_explicitly() {
        let signature = CoseSign1Builder::new()
            .protected(HeaderBuilder::new().algorithm(-7).build())
            .payload(vec![0xa0])
            .build()
            .to_tagged_vec()
            .unwrap();
        let error = verify_signature(&signature, &[0xa0]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported signature algorithm")
        );
    }
}
