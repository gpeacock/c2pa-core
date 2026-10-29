//! Experimental manifest construction shared by the sidecar and asset CLIs.
//! Certificates are ephemeral and untrusted; this is not a production signer.

pub mod asset;
pub mod dump;
mod ephemeral_cert;
pub mod validation;

use c2pa_cbor::Value;
use c2pa_cbor::cose::{CoseSign1Builder, HeaderBuilder};
use c2pa_claim::{Action, Actions, Claim, GeneratorInfo, HardBinding, HashedUri};
use c2pa_store::{ManifestStoreBuilder, ManifestStoreEditor};
use ed25519_dalek::Signer;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// One test identity, reused while sizing and filling an embedded manifest.
pub struct TestSigner {
    chain: ephemeral_cert::EphemeralChain,
    label: String,
    instance_id: String,
}

impl TestSigner {
    pub fn new() -> Result<Self> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes)?;
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let uuid = format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        );
        Ok(Self {
            chain: ephemeral_cert::generate_ephemeral_chain("c2pa-sign-sample-ephemeral.local")?,
            label: format!("urn:c2pa:{uuid}"),
            instance_id: format!("xmp:iid:{uuid}"),
        })
    }

    pub fn ca_pem(&self) -> &str {
        &self.chain.ca_pem
    }

    /// Build a signed manifest, optionally retaining an existing store's children.
    pub fn build_store(
        &self,
        binding: &dyn HardBinding,
        previous: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Ok(self.placeholder(binding, previous)?.store)
    }

    /// Build a signed manifest whose hard binding is a placeholder, optionally
    /// retaining an existing store's children. [`complete`](Self::complete) fills
    /// in the real binding later without changing the store's size.
    pub fn placeholder(
        &self,
        binding: &dyn HardBinding,
        previous: Option<&[u8]>,
    ) -> Result<Placeholder> {
        let mut builder = ManifestStoreBuilder::new(Vec::new(), &self.label)?;
        let mut info = GeneratorInfo::new("c2pa-sign-sample");
        info.version = Some(env!("CARGO_PKG_VERSION").to_string());
        let mut claim = Claim::new(&self.label, &self.instance_id, info);
        claim.alg = Some("sha256".to_string());

        let hash = builder.add_cbor_assertion(binding.label(), None, &binding.to_cbor()?)?;
        claim.add_created_assertion(HashedUri::new(hash.url, Some(hash.alg.into()), &hash.hash));

        let mut actions = Actions::new();
        actions.add_action(
            Action::new(Action::CREATED)
                .with_digital_source_type(Action::DIGITAL_SOURCE_TYPE_EMPTY),
        );
        let hash = builder.add_cbor_assertion(Actions::LABEL, None, &actions.to_cbor()?)?;
        claim.add_created_assertion(HashedUri::new(hash.url, Some(hash.alg.into()), &hash.hash));
        let claim_cbor = claim.to_cbor()?;
        builder.add_claim("c2pa.claim.v2", &claim_cbor)?;
        builder.add_signature(&self.sign(&claim_cbor)?)?;
        let store = builder.finish()?;
        let store = match previous {
            Some(previous) => asset_io::jumbf::extend(previous, &store)?,
            None => store,
        };
        Ok(Placeholder { store, claim })
    }

    /// Replace the placeholder's hard binding with `binding`, which the binding
    /// has kept the same length, then update the claim's reference to it and
    /// re-sign. Each box is rewritten in place, so nothing in the store moves.
    pub fn complete(&self, placeholder: &mut Placeholder, binding: &dyn HardBinding) -> Result<()> {
        let mut editor = ManifestStoreEditor::new(&mut placeholder.store);
        let hash = editor.update_assertion(&self.label, binding.label(), &binding.to_cbor()?)?;
        if !placeholder
            .claim
            .update_assertion_hash(&hash.url, &hash.hash)
        {
            return Err("claim does not reference the hard binding".into());
        }
        let claim_cbor = placeholder.claim.to_cbor()?;
        editor.update_claim(&self.label, &claim_cbor)?;
        editor.update_signature(&self.label, &self.sign(&claim_cbor)?)?;
        Ok(())
    }

    /// A detached `COSE_Sign1` over `claim_cbor`. Ed25519 signatures and these
    /// headers have a fixed length, so re-signing a same-length claim keeps the
    /// signature box the same size.
    fn sign(&self, claim_cbor: &[u8]) -> Result<Vec<u8>> {
        let protected = HeaderBuilder::new()
            .algorithm(-8) // EdDSA
            .value(
                33,
                Value::Array(vec![
                    Value::Bytes(self.chain.ee_der.clone()),
                    Value::Bytes(self.chain.ca_der.clone()),
                ]),
            )
            .build();
        let mut signature = CoseSign1Builder::new()
            .protected(protected)
            .payload(claim_cbor.to_vec())
            .build();
        signature.signature = self
            .chain
            .ee_signing_key
            .sign(&signature.tbs_data(&[])?)
            .to_bytes()
            .to_vec();
        signature.payload = None;
        Ok(signature.to_tagged_vec()?)
    }
}

/// A manifest store whose hard binding is a placeholder, and the claim it was
/// signed with, ready for [`TestSigner::complete`].
pub struct Placeholder {
    /// The whole store, including any retained manifests.
    pub store: Vec<u8>,
    claim: Claim,
}
