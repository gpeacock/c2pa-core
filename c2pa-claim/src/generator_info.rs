use serde::{Deserialize, Serialize};

use crate::HashedUri;

/// Describes the tool that produced a claim (`generator-info-map` in the C2PA
/// CDDL). `name` is required; the rest are optional.
///
/// The spec allows arbitrary additional `tstr => any` members; those are not
/// modeled here and are ignored on decode.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GeneratorInfo {
    /// Human-readable name of the claim generator.
    pub name: String,

    /// Human-readable product version.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version: Option<String>,

    /// Hashed URI to the generator's icon (embedded or remote).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub icon: Option<HashedUri>,

    /// The operating system the generator ran on.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub operating_system: Option<String>,

    /// The spec version used to produce the manifest (SemVer).
    #[serde(
        rename = "specVersion",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub spec_version: Option<String>,
}

impl GeneratorInfo {
    /// Create a generator info with just a name; set optional fields directly.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: None,
            icon: None,
            operating_system: None,
            spec_version: None,
        }
    }
}
