//! Tests for hashing an asset through a caller-driven [`Feed`].

use std::io::Cursor;

use c2pa_assertions::{
    feed_reader, feed_slice, AssetBox, BoxHash, BoxHashError, DataHash, DataHashError, Feed,
    HashRange, RangeDigest, RangeError, C2PA_BOX,
};
use c2pa_claim::hash::digest;

const ASSET: &[u8] = b"\xff\xd8STORE!scan-data!\xff\xd9";

fn range(start: u64, length: u64) -> HashRange {
    HashRange { start, length }
}

/// Feed `task` at most `chunk` bytes at a time, as a streaming caller would.
fn feed_chunks(task: &mut impl Feed, asset: &[u8], chunk: usize) {
    while let Some(need) = task.need() {
        let start = need.offset as usize;
        let end = asset.len().min(start + chunk.min(need.len as usize));
        assert_eq!(task.feed(&asset[start..end]), end - start);
    }
}

#[test]
fn a_range_digest_hashes_what_the_exclusions_leave_however_it_is_fed() {
    let want = digest("sha256", b"\xff\xd8scan-data!\xff\xd9").unwrap();
    for chunk in [1, 3, 64, usize::MAX / 2] {
        let mut task =
            RangeDigest::excluding("sha256", ASSET.len() as u64, &[range(2, 6)]).unwrap();
        feed_chunks(&mut task, ASSET, chunk);
        assert_eq!(task.finish().unwrap(), want, "chunk {chunk}");
    }
    let mut task = RangeDigest::excluding("sha256", ASSET.len() as u64, &[range(2, 6)]).unwrap();
    feed_reader(&mut task, &mut Cursor::new(ASSET)).unwrap();
    assert_eq!(task.finish().unwrap(), want);
}

#[test]
fn feeding_uses_only_what_is_needed_and_nothing_once_done() {
    let mut task = RangeDigest::new("sha256", vec![range(0, 2), range(4, 0), range(5, 1)]).unwrap();
    assert_eq!(task.feed(&ASSET[..10]), 2, "only the first range");
    let need = task.need().unwrap();
    assert_eq!((need.offset, need.len), (5, 1), "empty ranges are skipped");
    assert_eq!(task.feed(&ASSET[5..]), 1);
    assert!(task.need().is_none());
    assert_eq!(task.feed(ASSET), 0);
    let want = digest("sha256", &[ASSET[0], ASSET[1], ASSET[5]]).unwrap();
    assert_eq!(task.finish().unwrap(), want);
}

#[test]
fn an_unfinished_or_unfed_task_has_no_digest() {
    let mut task = RangeDigest::new("sha256", vec![range(0, 4)]).unwrap();
    task.feed(&ASSET[..3]);
    assert!(task.clone().finish().is_none());
    assert!(!feed_slice(&mut task, &ASSET[..3]), "asset too short");
    assert!(feed_reader(&mut task, &mut Cursor::new(&ASSET[..3])).is_err());
}

#[test]
fn bad_exclusions_and_algorithms_are_rejected() {
    let total = ASSET.len() as u64;
    for exclusions in [
        vec![range(4, 2), range(2, 1)],
        vec![range(2, 4), range(5, 1)],
        vec![range(18, 3)],
        vec![range(u64::MAX, 2)],
    ] {
        assert_eq!(
            RangeDigest::excluding("sha256", total, &exclusions).unwrap_err(),
            RangeError::Exclusions,
            "{exclusions:?}"
        );
    }
    assert!(RangeDigest::excluding("sha256", total, &[range(0, 2), range(2, 3)]).is_ok());
    assert_eq!(
        RangeDigest::excluding("md5", total, &[]).unwrap_err(),
        RangeError::Alg
    );
}

#[test]
fn a_data_hash_checks_through_a_task() {
    let mut binding = DataHash::new("sha256", Vec::new());
    binding.exclusions = Some(vec![range(2, 6)]);
    let mut task = binding.task(ASSET.len() as u64, None).unwrap();
    assert!(feed_slice(&mut task, ASSET));
    binding.hash = task.finish().unwrap();

    let mut task = binding.task(ASSET.len() as u64, None).unwrap();
    assert_eq!(binding.check(task.clone()), Err(DataHashError::Incomplete));
    let mut other = ASSET.to_vec();
    other[3] = b'X';
    assert!(feed_slice(&mut task, &other), "the store may change");
    binding.check(task).unwrap();

    other[10] = b'X';
    let mut task = binding.task(ASSET.len() as u64, None).unwrap();
    assert!(feed_slice(&mut task, &other));
    let err = binding.check(task).unwrap_err();
    assert_eq!(err.code(), Some("assertion.dataHash.mismatch"));

    binding.exclusions = Some(vec![range(19, 4)]);
    let err = binding.task(ASSET.len() as u64, None).unwrap_err();
    assert_eq!(err.code(), Some("assertion.dataHash.malformed"));
    binding.exclusions = None;
    binding.alg = None;
    assert_eq!(
        binding.task(ASSET.len() as u64, None).unwrap_err(),
        DataHashError::UnsupportedAlg
    );
}

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
        range: range(start, length),
        metadata: Vec::new(),
    })
    .collect()
}

#[test]
fn a_box_hash_task_matches_the_blocking_update_and_verify() {
    let names = boxes().iter().map(|b| b.name).collect::<Vec<_>>();
    let placeholder = BoxHash::placeholder("sha256", names).unwrap();
    let mut blocking = placeholder.clone();
    blocking
        .update(&mut Cursor::new(ASSET), &boxes(), None)
        .unwrap();

    for chunk in [1, 5, 4096] {
        let mut fed = placeholder.clone();
        let mut task = fed.task(ASSET.len() as u64, &boxes(), None).unwrap();
        feed_chunks(&mut task, ASSET, chunk);
        fed.apply(task).unwrap();
        assert_eq!(fed, blocking, "chunk {chunk}");

        let mut task = fed.task(ASSET.len() as u64, &boxes(), None).unwrap();
        feed_chunks(&mut task, ASSET, chunk);
        fed.check(task).unwrap();
    }

    // The store's box is never wanted.
    let task = blocking.task(ASSET.len() as u64, &boxes(), None).unwrap();
    assert_eq!(task.need().unwrap().offset, 0);
    let mut task = task;
    task.feed(&ASSET[..2]);
    assert_eq!(task.need().unwrap().offset, 8);

    let mut other = ASSET.to_vec();
    other[9] = b'X';
    let mut task = blocking.task(ASSET.len() as u64, &boxes(), None).unwrap();
    assert!(feed_slice(&mut task, &other));
    assert!(matches!(blocking.check(task), Err(BoxHashError::Mismatch(n)) if n == "SOS"));

    let task = blocking.task(ASSET.len() as u64, &boxes(), None).unwrap();
    assert!(matches!(
        blocking.check(task.clone()),
        Err(BoxHashError::Incomplete)
    ));
    assert!(matches!(
        blocking.apply(task),
        Err(BoxHashError::Incomplete)
    ));
}

#[test]
fn box_hash_structure_fails_before_any_byte_is_read() {
    let binding = BoxHash::placeholder("sha256", ["SOI", C2PA_BOX, "SOS"]).unwrap();
    let err = binding
        .task(ASSET.len() as u64, &boxes(), None)
        .unwrap_err();
    assert_eq!(err.code(), Some("assertion.boxesHash.unknownBox"));
    let names = boxes().iter().map(|b| b.name).collect::<Vec<_>>();
    let binding = BoxHash::placeholder("sha256", names).unwrap();
    let err = binding.task(10, &boxes(), None).unwrap_err();
    assert_eq!(err.code(), Some("assertion.boxesHash.malformed"));
}
