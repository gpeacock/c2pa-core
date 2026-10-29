//! Tests for the `c2pa.hash.boxes` hard binding (C2PA 2.4, 18.7 and 15.12.3):
//! placeholder sizing, hashing named boxes, and validation rules.

use std::io::Cursor;

use c2pa_cbor::Value;
use c2pa_claim::{AssetBox, BoxExclusion, BoxHash, BoxHashError, HashRange, C2PA_BOX};

/// `SOI` (2 bytes), the store (6), `SOS` (10, bytes 10..14 being metadata), `EOI` (2).
const ASSET: &[u8] = b"\xff\xd8STORE!scan-data!\xff\xd9";

fn boxes() -> Vec<AssetBox<'static>> {
    [
        ("SOI", 0, 2),
        (C2PA_BOX, 2, 6),
        ("SOS", 8, 10),
        ("EOI", 18, 2),
    ]
    .into_iter()
    .map(|(name, start, length)| AssetBox {
        name,
        range: HashRange { start, length },
        metadata: if name == "SOS" {
            vec![HashRange {
                start: 10,
                length: 4,
            }]
        } else {
            Vec::new()
        },
    })
    .collect()
}

fn placeholder() -> BoxHash {
    let names = boxes().iter().map(|b| b.name).collect::<Vec<_>>();
    BoxHash::placeholder("sha256", names).unwrap()
}

fn signed(mut binding: BoxHash) -> BoxHash {
    binding
        .update(&mut Cursor::new(ASSET), &boxes(), None)
        .unwrap();
    binding
}

fn verify(binding: &BoxHash, asset: &[u8]) -> Result<bool, BoxHashError> {
    binding
        .verify(&mut Cursor::new(asset), &boxes(), Some("sha256"))
        .map(|r| r.additional_exclusions)
}

fn code(result: Result<bool, BoxHashError>) -> &'static str {
    result.unwrap_err().code().unwrap()
}

#[test]
fn placeholder_updates_to_the_same_length_and_verifies() {
    let placeholder = placeholder();
    let binding = signed(placeholder.clone());
    assert_eq!(
        binding.to_cbor().unwrap().len(),
        placeholder.to_cbor().unwrap().len()
    );
    assert_eq!(binding.boxes[1].hash, [0], "the store's hash is 00");
    assert_ne!(binding.boxes[2].hash, placeholder.boxes[2].hash);
    assert!(!verify(&binding, ASSET).unwrap());
    assert_eq!(
        BoxHash::from_cbor(&binding.to_cbor().unwrap()).unwrap(),
        binding
    );
    assert!(BoxHash::placeholder("md5", ["SOI"]).is_none());
}

#[test]
fn only_the_store_box_may_change() {
    let binding = signed(placeholder());
    let mut asset = ASSET.to_vec();
    asset[4] ^= 1; // inside the C2PA store
    verify(&binding, &asset).unwrap();
    asset[9] ^= 1; // inside SOS
    assert!(matches!(
        binding.verify(&mut Cursor::new(&asset), &boxes(), None),
        Err(BoxHashError::Mismatch(names)) if names == "SOS"
    ));
}

#[test]
fn unlisted_and_reordered_boxes_have_their_own_codes() {
    let binding = signed(placeholder());
    let check = |list: Vec<AssetBox<'static>>| {
        binding
            .verify(&mut Cursor::new(ASSET), &list, None)
            .unwrap_err()
            .code()
            .unwrap()
    };
    let mut renamed = boxes();
    renamed[2].name = "APP1";
    let mut extra = boxes();
    extra.push(AssetBox {
        name: "c2pa.after",
        range: HashRange {
            start: 20,
            length: 0,
        },
        metadata: Vec::new(),
    });
    let mut missing = boxes();
    missing.pop();
    for list in [renamed, extra, missing] {
        assert_eq!(check(list), "assertion.boxesHash.unknownBox");
    }
    let mut swapped = boxes();
    swapped.swap(2, 3);
    assert_eq!(check(swapped), "assertion.boxesHash.mismatch");
}

/// The algorithm is the entry's, else the assertion's, else the claim's; there is
/// no other default.
#[test]
fn algorithm_precedence() {
    let names = boxes().iter().map(|b| b.name).collect::<Vec<_>>();
    let mut binding = BoxHash::placeholder("sha384", names).unwrap();
    for entry in &mut binding.boxes {
        entry.alg = None;
    }
    binding.alg = Some("sha384".into());
    let binding = signed(binding);
    assert_eq!(binding.boxes[2].hash.len(), 48);
    // The assertion's algorithm wins over the claim's.
    assert!(!verify(&binding, ASSET).unwrap());

    let mut no_alg = binding.clone();
    no_alg.alg = None;
    assert_eq!(
        no_alg
            .verify(&mut Cursor::new(ASSET), &boxes(), None)
            .unwrap_err()
            .code(),
        Some("algorithm.unsupported")
    );
    let mut unknown = binding.clone();
    unknown.boxes[0].alg = Some("md5".into());
    assert_eq!(code(verify(&unknown, ASSET)), "algorithm.unsupported");
}

fn with_exclusion(start: u64, length: u64, box_index: Option<i64>) -> BoxHash {
    let mut binding = placeholder();
    binding.boxes[2].exclusions = Some(vec![BoxExclusion {
        start,
        length,
        box_index,
    }]);
    binding
}

/// Asset metadata inside a box may be excluded; nothing else may.
#[test]
fn exclusions_cover_only_asset_metadata() {
    let binding = signed(with_exclusion(2, 4, None));
    let mut asset = ASSET.to_vec();
    asset[11] ^= 1; // excluded metadata
    assert!(verify(&binding, &asset).unwrap(), "additional exclusions");
    asset[9] ^= 1; // the rest of SOS
    assert_eq!(
        code(verify(&binding, &asset)),
        "assertion.boxesHash.mismatch"
    );

    // Outside the metadata, or past the end of the box.
    let mut outside = with_exclusion(2, 4, None);
    outside.boxes[2].exclusions.as_mut().unwrap()[0].start = 0;
    assert_eq!(
        code(verify(&outside, ASSET)),
        "assertion.boxesHash.mismatch"
    );
    let mut past = with_exclusion(2, 4, None);
    past.boxes[2].exclusions.as_mut().unwrap()[0].length = 20;
    assert_eq!(code(verify(&past, ASSET)), "assertion.boxesHash.mismatch");

    for malformed in [
        with_exclusion(2, 4, Some(-1)),
        with_exclusion(2, 4, Some(1)),
        {
            let mut b = with_exclusion(2, 2, None);
            b.boxes[2].exclusions.as_mut().unwrap().push(BoxExclusion {
                start: 3,
                length: 1,
                box_index: None,
            });
            b
        },
        {
            let mut b = placeholder();
            b.boxes[2].exclusions = Some(Vec::new());
            b
        },
    ] {
        assert_eq!(
            code(verify(&malformed, ASSET)),
            "assertion.boxesHash.malformed"
        );
    }
}

#[test]
fn any_box_may_be_marked_excluded() {
    let mut binding = signed(placeholder());
    binding.boxes[2].excluded = Some(true);
    let mut asset = ASSET.to_vec();
    asset[9] ^= 1;
    assert!(verify(&binding, &asset).unwrap());
}

/// An entry may name several boxes; its hash spans from the first to the last.
#[test]
fn entries_may_group_boxes() {
    let mut binding = placeholder();
    let eoi = binding.boxes.pop().unwrap();
    binding.boxes[2].names.push(eoi.names[0].clone());
    let binding = signed(binding);
    assert!(!verify(&binding, ASSET).unwrap());
    let mut asset = ASSET.to_vec();
    asset[19] ^= 1;
    assert_eq!(
        code(verify(&binding, &asset)),
        "assertion.boxesHash.mismatch"
    );
}

#[test]
fn padding_is_ignored_and_round_trips() {
    let mut binding = signed(placeholder());
    binding.boxes[0].pad = vec![0; 3];
    binding.boxes[0].pad2 = Some(vec![0; 2].into());
    assert_eq!(
        BoxHash::from_cbor(&binding.to_cbor().unwrap()).unwrap(),
        binding
    );
    assert!(!verify(&binding, ASSET).unwrap());
}

#[test]
fn uses_c2pa_rs_field_names() {
    let bytes = signed(placeholder()).to_cbor().unwrap();
    let Value::Map(map) = c2pa_cbor::from_slice::<Value>(&bytes).unwrap() else {
        panic!("not a map")
    };
    let Some(Value::Array(entries)) = map.get(&Value::Text("boxes".into())) else {
        panic!("no boxes array")
    };
    let Value::Map(entry) = &entries[0] else {
        panic!("entry is not a map")
    };
    let mut keys: Vec<_> = entry
        .keys()
        .filter_map(|k| match k {
            Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
        .collect();
    keys.sort();
    assert_eq!(keys, ["alg", "hash", "names", "pad"]);
}
