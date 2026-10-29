use serde::{Deserialize, Serialize};

use crate::Assertion;

/// A single action taken on the asset (`action-map` in the CDDL).
///
/// Wire-compatible with `c2pa-rs`'s `Action`: field names match exactly.
/// `c2pa-rs` models many more optional fields (`when`, `actors`, `changes`,
/// `parameters`, ...); this only carries what's needed to produce a valid
/// [`Action::CREATED`] action, and decoding ignores unknown map keys, so it
/// still round-trips assertions that use those other fields without losing
/// them from a signature-verification standpoint (they're just not exposed
/// here).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Action {
    /// The action identifier (e.g. [`Action::CREATED`]).
    pub action: String,

    /// The IPTC digital-source-type URI for this action. Required by C2PA
    /// validators when `action` is [`Action::CREATED`].
    #[serde(
        rename = "digitalSourceType",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub digital_source_type: Option<String>,
}

impl Action {
    /// The asset was created (as opposed to edited, opened, etc.).
    pub const CREATED: &'static str = "c2pa.created";

    /// No particular digital source type is claimed -- a reasonable default
    /// for placeholder or synthetic content with nothing more specific to
    /// report.
    pub const DIGITAL_SOURCE_TYPE_EMPTY: &'static str = "http://c2pa.org/digitalsourcetype/empty";

    /// Create an action with no digital source type set yet.
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            digital_source_type: None,
        }
    }

    /// Set the digital source type.
    pub fn with_digital_source_type(mut self, source_type: impl Into<String>) -> Self {
        self.digital_source_type = Some(source_type.into());
        self
    }
}

/// The C2PA `c2pa.actions.v2` assertion (`actions-map-v2` in the CDDL): the
/// list of actions performed to produce this version of the asset.
///
/// Wire-compatible with `c2pa-rs`'s `Actions`: the `actions` field name
/// matches exactly. `c2pa-rs` also models `softwareAgents`,
/// `allActionsIncluded`, `templates`, and `metadata`, all optional; this
/// doesn't carry them, for the same reason [`Action`] doesn't carry every
/// optional field.
///
/// A valid actions assertion needs at least one action; validators also
/// require a [`Action::CREATED`] action to carry a `digitalSourceType`. This
/// type doesn't enforce either -- construction mirrors [`c2pa_claim::Claim`],
/// which is likewise permissive and leaves validation to the caller.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Actions {
    /// The actions, in the order they were performed.
    pub actions: Vec<Action>,
}

impl Actions {
    /// The assertion label for actions v2.
    pub const LABEL: &'static str = "c2pa.actions.v2";

    /// Create an actions assertion with no actions yet.
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
        }
    }

    /// Append an action.
    pub fn add_action(&mut self, action: Action) {
        self.actions.push(action);
    }
}

impl Assertion for Actions {
    fn label(&self) -> &str {
        Self::LABEL
    }

    fn to_cbor(&self) -> Result<Vec<u8>, c2pa_cbor::Error> {
        c2pa_cbor::to_vec_deterministic(self)
    }

    fn from_cbor(bytes: &[u8]) -> Result<Self, c2pa_cbor::Error> {
        c2pa_cbor::from_slice(bytes)
    }
}

impl Default for Actions {
    fn default() -> Self {
        Self::new()
    }
}
