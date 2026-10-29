//! Minimal ephemeral self-signed CA + end-entity X.509 chain for Ed25519,
//! built entirely on `rcgen`'s DER-writing (no `ring`/`aws-lc-rs`, no OpenSSL):
//! `rcgen`'s `PublicKeyData`/`SigningKey` traits let it write a correctly
//! shaped, spec-compliant certificate around any signer we hand it, so all we
//! provide is the Ed25519 key material and signing calls.
//!
//! **WARNING:** For local testing only. Nothing anchors this CA to a trust
//! store; a verifier has to be told to trust it explicitly (e.g.
//! `c2patool trust --trust_anchors <ca.pem>`).

use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Issuer,
    KeyUsagePurpose, PKCS_ED25519, PublicKeyData, SerialNumber, SignatureAlgorithm,
    SigningKey as RcgenSigningKey,
};
use time::{Duration, OffsetDateTime};

/// Adapts an `ed25519_dalek::SigningKey` to `rcgen`'s key traits, so `rcgen`
/// can write the certificate's `SubjectPublicKeyInfo` and sign its
/// `TBSCertificate` without knowing anything about Ed25519 itself.
struct Ed25519KeyPair {
    signing_key: Ed25519SigningKey,
    public_key_bytes: [u8; 32],
}

impl Ed25519KeyPair {
    fn generate() -> crate::Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)?;
        let signing_key = Ed25519SigningKey::from_bytes(&seed);
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        Ok(Self {
            signing_key,
            public_key_bytes,
        })
    }
}

impl PublicKeyData for Ed25519KeyPair {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ED25519
    }
}

impl RcgenSigningKey for Ed25519KeyPair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.signing_key.sign(msg).to_bytes().to_vec())
    }
}

/// A generated CA + end-entity chain: DER bytes for both certificates (in
/// leaf-then-issuer order, as COSE's `x5chain` expects), the CA's PEM (to
/// hand a verifier as a trust anchor), and the end-entity's Ed25519 signing
/// key (to actually sign the claim).
pub struct EphemeralChain {
    pub ee_der: Vec<u8>,
    pub ca_der: Vec<u8>,
    pub ca_pem: String,
    pub ee_signing_key: Ed25519SigningKey,
}

fn common_name(name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    dn
}

/// Without the `crypto` feature, `rcgen` has no RNG of its own to generate a
/// serial number, so callers must supply one. A DER INTEGER's sign is its
/// high bit, so it's cleared to keep this unambiguously positive.
fn random_serial_number() -> crate::Result<SerialNumber> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)?;
    bytes[0] &= 0x7f;
    Ok(SerialNumber::from_slice(&bytes))
}

/// Generate a fresh, throwaway self-signed CA and an end-entity certificate
/// it signs -- both Ed25519, both good for one process's lifetime only.
pub fn generate_ephemeral_chain(ee_common_name: &str) -> crate::Result<EphemeralChain> {
    let now = OffsetDateTime::now_utc();
    let not_before = now - Duration::days(1);
    let not_after = now + Duration::days(365);

    let ca_key = Ed25519KeyPair::generate()?;
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = common_name("c2pa-sign-sample ephemeral CA (local use only)");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.serial_number = Some(random_serial_number()?);
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    let ca_cert: Certificate = ca_params.self_signed(&ca_key)?;

    let ee_key = Ed25519KeyPair::generate()?;
    let mut ee_params = CertificateParams::default();
    ee_params.distinguished_name = common_name(ee_common_name);
    ee_params.is_ca = rcgen::IsCa::ExplicitNoCa;
    ee_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    ee_params.serial_number = Some(random_serial_number()?);
    ee_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    ee_params.not_before = not_before;
    ee_params.not_after = not_after;
    // C2PA's certificate profile check requires an Authority Key Identifier on
    // the end-entity cert; rcgen only writes it when asked (default is off).
    ee_params.use_authority_key_identifier_extension = true;
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let ee_cert: Certificate = ee_params.signed_by(&ee_key, &issuer)?;

    Ok(EphemeralChain {
        ee_der: ee_cert.der().to_vec(),
        ca_der: ca_cert.der().to_vec(),
        ca_pem: ca_cert.pem(),
        ee_signing_key: ee_key.signing_key,
    })
}
