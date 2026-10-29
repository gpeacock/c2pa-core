//! Every assertion works through the common `Assertion` API, so code that writes
//! assertions need not know their types.

use c2pa_assertions::{Action, Actions, Assertion, BoxHash, DataHash};

fn round_trip<A: Assertion + PartialEq + std::fmt::Debug>(assertion: &A) {
    let bytes = assertion.to_cbor().unwrap();
    assert_eq!(&A::from_cbor(&bytes).unwrap(), assertion);
}

#[test]
fn assertions_share_one_api() {
    let mut actions = Actions::new();
    actions.add_action(Action::new(Action::CREATED));
    let data = DataHash::placeholder("sha256", 1).unwrap();
    let boxes = BoxHash::placeholder("sha256", ["SOI", "C2PA", "EOI"]).unwrap();

    let all: [&dyn Assertion; 3] = [&actions, &data, &boxes];
    let labels: Vec<_> = all.iter().map(|a| a.label()).collect();
    assert_eq!(
        labels,
        ["c2pa.actions.v2", "c2pa.hash.data", "c2pa.hash.boxes"]
    );
    for assertion in all {
        assert!(!assertion.to_cbor().unwrap().is_empty());
    }

    round_trip(&actions);
    round_trip(&data);
    round_trip(&boxes);
}
