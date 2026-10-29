//! Tests for the `c2pa.actions.v2` assertion: CBOR field names and how it
//! plugs into a real manifest via `c2pa_store::ManifestStoreBuilder`.

use c2pa_assertions::{Action, Actions, Assertion};
use c2pa_cbor::Value;
use c2pa_claim::{Claim, GeneratorInfo, HashedUri};
use c2pa_store::ManifestStore;

/// The top-level keys of a CBOR map, as strings.
fn map_keys(bytes: &[u8]) -> Vec<String> {
    let value: Value = c2pa_cbor::from_slice(bytes).unwrap();
    match value {
        Value::Map(m) => m
            .into_keys()
            .filter_map(|k| match k {
                Value::Text(s) => Some(s),
                _ => None,
            })
            .collect(),
        other => panic!("expected a CBOR map, got {other:?}"),
    }
}

fn created_action() -> Actions {
    let mut actions = Actions::new();
    actions.add_action(
        Action::new(Action::CREATED).with_digital_source_type(Action::DIGITAL_SOURCE_TYPE_EMPTY),
    );
    actions
}

#[test]
fn round_trips_through_cbor() {
    let actions = created_action();
    let bytes = actions.to_cbor().unwrap();
    assert_eq!(Actions::from_cbor(&bytes).unwrap(), actions);
}

#[test]
fn uses_spec_field_names() {
    let actions = created_action();
    let keys = map_keys(&actions.to_cbor().unwrap());
    assert_eq!(keys, vec!["actions".to_string()]);

    let action_cbor = c2pa_cbor::to_vec_deterministic(&actions.actions[0]).unwrap();
    let action_keys = map_keys(&action_cbor);
    assert!(action_keys.contains(&"action".to_string()));
    assert!(action_keys.contains(&"digitalSourceType".to_string()));
}

#[test]
fn digital_source_type_is_omitted_when_unset() {
    let mut actions = Actions::new();
    actions.add_action(Action::new(Action::CREATED));
    let bytes = c2pa_cbor::to_vec_deterministic(&actions.actions[0]).unwrap();
    assert!(!map_keys(&bytes).contains(&"digitalSourceType".to_string()));
}

#[test]
fn decode_ignores_unknown_fields() {
    // A superset struct mirroring c2pa-rs's fuller `Action`/`Actions`, with
    // extra fields our type doesn't model.
    #[derive(serde::Serialize)]
    struct BiggerAction<'a> {
        action: &'a str,
        #[serde(rename = "digitalSourceType")]
        digital_source_type: &'a str,
        when: &'a str,
    }
    #[derive(serde::Serialize)]
    struct BiggerActions<'a> {
        actions: Vec<BiggerAction<'a>>,
        #[serde(rename = "allActionsIncluded")]
        all_actions_included: bool,
    }
    let extended = BiggerActions {
        actions: vec![BiggerAction {
            action: Action::CREATED,
            digital_source_type: Action::DIGITAL_SOURCE_TYPE_EMPTY,
            when: "2024-01-01T00:00:00Z",
        }],
        all_actions_included: true,
    };
    let bytes = c2pa_cbor::to_vec_deterministic(&extended).unwrap();

    let actions = Actions::from_cbor(&bytes).expect("unknown fields should be ignored");
    assert_eq!(actions.actions.len(), 1);
    assert_eq!(actions.actions[0].action, Action::CREATED);
    assert_eq!(
        actions.actions[0].digital_source_type.as_deref(),
        Some(Action::DIGITAL_SOURCE_TYPE_EMPTY)
    );
}

#[test]
fn plugs_into_a_real_manifest_and_verifies() {
    let actions = created_action();
    let actions_cbor = actions.to_cbor().unwrap();

    let mut builder =
        c2pa_store::ManifestStoreBuilder::new(Vec::<u8>::new(), "urn:c2pa:test").unwrap();
    let actions_href = builder
        .add_cbor_assertion(Actions::LABEL, Some(&[3u8; 16]), &actions_cbor)
        .unwrap();

    let mut claim = Claim::new(
        "urn:c2pa:test",
        "xmp:iid:test-instance",
        GeneratorInfo::new("test_generator"),
    );
    claim.alg = Some("sha256".to_string());
    claim.add_created_assertion(HashedUri::new(
        actions_href.url,
        Some(actions_href.alg.to_string()),
        &actions_href.hash,
    ));
    let claim_cbor = claim.to_cbor().unwrap();

    builder.add_claim("c2pa.claim.v2", &claim_cbor).unwrap();
    let bytes = builder.finish().unwrap();

    let store = ManifestStore::parse(&bytes).unwrap();
    let manifest = store.active_manifest().unwrap();
    let decoded = Claim::from_cbor(manifest.claim_cbor().unwrap()).unwrap();

    let href = &decoded.created_assertions[0];
    assert_eq!(
        href.verify(&store, &manifest, decoded.alg.as_deref()),
        Ok(())
    );

    let assertion = manifest.assertions().unwrap().next().unwrap();
    assert_eq!(assertion.label(), Some(Actions::LABEL));
    let decoded_actions = Actions::from_cbor(assertion.payload().unwrap().data).unwrap();
    assert_eq!(decoded_actions, actions);
}
