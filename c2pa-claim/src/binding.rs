//! What hard-binding assertions have in common.

use crate::{BoxHash, DataHash};

/// A hard-binding assertion, which binds a manifest to its asset's bytes.
///
/// Each binding builds its own placeholder and fills in its real values (see
/// [`DataHash::placeholder`] and [`BoxHash::placeholder`]); the claim only
/// references it, and the store only writes or updates its bytes. This is what
/// those layers need from any binding.
pub trait HardBinding {
    /// The assertion label, such as `c2pa.hash.data`.
    fn label(&self) -> &'static str;

    /// The assertion's deterministic CBOR.
    fn to_cbor(&self) -> Result<Vec<u8>, c2pa_cbor::Error>;
}

impl HardBinding for DataHash {
    fn label(&self) -> &'static str {
        Self::LABEL
    }

    fn to_cbor(&self) -> Result<Vec<u8>, c2pa_cbor::Error> {
        DataHash::to_cbor(self)
    }
}

impl HardBinding for BoxHash {
    fn label(&self) -> &'static str {
        Self::LABEL
    }

    fn to_cbor(&self) -> Result<Vec<u8>, c2pa_cbor::Error> {
        BoxHash::to_cbor(self)
    }
}
