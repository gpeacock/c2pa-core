//! The API every assertion shares.

/// An assertion: content stored in a manifest's assertion store under its label,
/// which the claim references by hashed URI.
///
/// This is what the claim and store layers need from any assertion, so code that
/// writes or updates assertions, such as a signer, works on `&dyn Assertion`
/// without knowing the type. An assertion that is completed after the asset is
/// written, such as a hard binding, builds its own same-size placeholder and fills
/// itself in (see [`DataHash::placeholder`](crate::DataHash::placeholder) and
/// [`BoxHash::placeholder`](crate::BoxHash::placeholder)); the store then
/// updates its bytes in place and the claim its hash.
pub trait Assertion {
    /// The label the assertion is stored under, such as `c2pa.actions.v2`.
    fn label(&self) -> &str;

    /// Encode to deterministic (canonical) CBOR, the form that is hashed and
    /// signed, as C2PA requires.
    fn to_cbor(&self) -> Result<Vec<u8>, c2pa_cbor::Error>;

    /// Decode from the CBOR content of the assertion's box. Map keys the type does
    /// not model are ignored, so decoding a real manifest's assertion never fails
    /// only because it uses fields this crate does not support.
    fn from_cbor(bytes: &[u8]) -> Result<Self, c2pa_cbor::Error>
    where
        Self: Sized;
}
