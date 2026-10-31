use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output};

use asset_io::{HandlerRegistry, ItemKind, NullSink, Updates};
use c2pa_assertions::{Assertion, DataHash, HashRange};
use c2pa_cbor::cose::CoseSign1;
use c2pa_sign_sample::{TestSigner, asset};
use c2pa_store::ManifestStore;

fn cli(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_c2pa-asset"))
        .args(args)
        .output()
        .unwrap()
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).unwrap()
}

fn failure(output: Output, expected: &str) {
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(expected),
        "expected {expected:?} in {stderr}"
    );
}

fn sign(input: &Path, output: &Path) {
    sign_with(input, output, &[]);
}

fn sign_with(input: &Path, output: &Path, flags: &[&str]) {
    let mut args = vec![
        "sign".as_ref(),
        input.as_os_str(),
        "-o".as_ref(),
        output.as_os_str(),
    ];
    args.extend(flags.iter().map(std::ffi::OsStr::new));
    success(cli(&args));
}

fn validate(input: &Path) -> String {
    success(cli(&["validate".as_ref(), input.as_os_str()]))
}

fn svg() -> Vec<u8> {
    br#"<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>"#.to_vec()
}

fn png() -> Vec<u8> {
    let hex = "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000b49444154789c636000020000050001a5f645400000000049454e44ae426082";
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn wav() -> Vec<u8> {
    let mut bytes = b"RIFF".to_vec();
    bytes.extend_from_slice(&40u32.to_le_bytes());
    bytes.extend_from_slice(b"WAVEfmt ");
    bytes.extend_from_slice(&16u32.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&8000u32.to_le_bytes());
    bytes.extend_from_slice(&16000u32.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&16u16.to_le_bytes());
    bytes.extend_from_slice(b"data");
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(&[0, 0, 1, 1]);
    bytes
}

#[test]
fn sign_validate_dump_and_append_across_container_families() {
    let directory = tempfile::tempdir().unwrap();
    // Containers with meaningful boxes get a box hash unless a data hash is asked
    // for; SVG has none, so it always gets a data hash.
    for (extension, bytes, flags, binding) in [
        (
            "jpg",
            vec![0xff, 0xd8, 0xff, 0xd9],
            &[][..],
            "c2pa.hash.boxes",
        ),
        (
            "jpg",
            vec![0xff, 0xd8, 0xff, 0xd9],
            &["--data-hash"][..],
            "c2pa.hash.data",
        ),
        ("png", png(), &[], "c2pa.hash.boxes"),
        ("png", png(), &["--data-hash"], "c2pa.hash.data"),
        ("wav", wav(), &[], "c2pa.hash.boxes"),
        ("wav", wav(), &["--data-hash"], "c2pa.hash.data"),
        ("svg", svg(), &[], "c2pa.hash.data"),
    ] {
        let tag = format!("{}{extension}", flags.len());
        let input = directory.path().join(format!("input{tag}.{extension}"));
        let output = directory.path().join(format!("signed{tag}.{extension}"));
        let appended = directory.path().join(format!("appended{tag}.{extension}"));
        fs::write(&input, &bytes).unwrap();
        sign_with(&input, &output, flags);
        assert_eq!(fs::read(&input).unwrap(), bytes);
        assert!(
            fs::read_to_string(asset::ca_path(&output))
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
        let report = validate(&output);
        assert!(report.contains("1 manifest(s), 2 assertion hash(es), 1 Ed25519 signature(s)"));
        assert!(
            report.contains(&format!("active {binding} binding")),
            "{report}"
        );
        let dump = success(cli(&["dump".as_ref(), output.as_os_str()]));
        assert!(dump.contains(&format!("\"{binding}\"")));
        assert!(dump.contains("CBOR: map["));
        assert!(dump.contains("CBOR: tag(18)"));
        assert!(dump.contains("bytes[32]:"));
        assert!(
            dump.lines().filter(|l| l.contains("bytes[64]:")).all(|l| l
                .split(": ")
                .last()
                .unwrap()
                .trim_end_matches("...")
                .len()
                == 64)
        );

        let (mut original_file, original_structure) = asset::open(&output).unwrap();
        let original = asset::read_store(&original_structure, &mut original_file).unwrap();
        let original_store = ManifestStore::parse(&original).unwrap();
        let original_manifest = original_store.active_manifest().unwrap();
        sign_with(&output, &appended, flags);
        assert!(
            validate(&appended)
                .contains("2 manifest(s), 4 assertion hash(es), 2 Ed25519 signature(s)")
        );
        let (mut file, structure) = asset::open(&appended).unwrap();
        let bytes = asset::read_store(&structure, &mut file).unwrap();
        let store = ManifestStore::parse(&bytes).unwrap();
        assert_eq!(
            store
                .manifest(original_manifest.label().unwrap())
                .unwrap()
                .raw(),
            original_manifest.raw()
        );
    }
}

#[test]
fn detects_asset_signature_and_assertion_tampering() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.svg");
    let signed = directory.path().join("signed.svg");
    fs::write(&input, svg()).unwrap();
    sign(&input, &signed);
    let original = fs::read(&signed).unwrap();

    let mut changed = original.clone();
    let needle = b"width=\"1\"";
    let at = changed
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    changed[at + 7] = b'2';
    fs::write(&signed, changed).unwrap();
    failure(
        cli(&["validate".as_ref(), signed.as_os_str()]),
        "assertion.dataHash.mismatch",
    );
    fs::write(&signed, &original).unwrap();

    for change_signature in [true, false] {
        let (mut file, structure) = asset::open(&signed).unwrap();
        let mut bytes = asset::read_store(&structure, &mut file).unwrap();
        let store = ManifestStore::parse(&bytes).unwrap();
        let manifest = store.active_manifest().unwrap();
        let (offset, replacement) = if change_signature {
            let old = manifest.signature_cose().unwrap();
            let mut cose = CoseSign1::from_tagged_slice(old).unwrap();
            cose.signature[0] ^= 1;
            (
                old.as_ptr() as usize - bytes.as_ptr() as usize,
                cose.to_tagged_vec().unwrap(),
            )
        } else {
            let assertion = manifest
                .assertions()
                .unwrap()
                .find(|a| a.label() == Some(DataHash::LABEL))
                .unwrap();
            let old = assertion.payload().unwrap().data;
            let mut binding = DataHash::from_cbor(old).unwrap();
            binding.hash[0] ^= 1;
            (
                old.as_ptr() as usize - bytes.as_ptr() as usize,
                binding.to_cbor().unwrap(),
            )
        };
        bytes[offset..offset + replacement.len()].copy_from_slice(&replacement);
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&signed)
            .unwrap();
        let item = structure.require_item(ItemKind::Jumbf).unwrap();
        structure.patch_exact(&mut file, item, &bytes).unwrap();
        failure(
            cli(&["validate".as_ref(), signed.as_os_str()]),
            if change_signature {
                "signature"
            } else {
                "HashMismatch"
            },
        );
        fs::write(&signed, &original).unwrap();
    }
}

#[test]
fn rejects_overbroad_exclusions_even_with_a_valid_signature() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.svg");
    let signed = directory.path().join("signed.svg");
    fs::write(&input, svg()).unwrap();
    let mut binding = DataHash::new("sha256", vec![0; 32]);
    binding.exclusions = Some(vec![HashRange {
        start: 0,
        length: 1,
    }]);
    let bytes = TestSigner::new()
        .unwrap()
        .build_store(&binding, None)
        .unwrap();
    let (mut source, structure) = asset::open(&input).unwrap();
    structure
        .write(
            &mut source,
            &mut fs::File::create(&signed).unwrap(),
            &Updates::new().set_jumbf(bytes),
            &mut NullSink,
        )
        .unwrap();
    failure(
        cli(&["validate".as_ref(), signed.as_os_str()]),
        "exclusions differ",
    );
}

#[test]
fn sidecar_validation_requires_original_asset_and_preserves_legacy_signer() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.svg");
    fs::write(&input, svg()).unwrap();
    success(
        Command::new(env!("CARGO_BIN_EXE_c2pa-sign-sample"))
            .arg(&input)
            .output()
            .unwrap(),
    );
    let sidecar = input.with_extension("c2pa");
    failure(
        cli(&["validate".as_ref(), sidecar.as_os_str()]),
        "requires --asset",
    );
    success(cli(&[
        "validate".as_ref(),
        sidecar.as_os_str(),
        "--asset".as_ref(),
        input.as_os_str(),
    ]));
    assert!(success(cli(&["dump".as_ref(), sidecar.as_os_str()])).contains("CBOR: tag(18)"));
}

#[test]
fn appending_a_large_store_handles_multipart_jpeg_transport() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.jpg");
    let existing = directory.path().join("existing.jpg");
    let output = directory.path().join("output.jpg");
    let jpeg = [0xff, 0xd8, 0xff, 0xd9];
    fs::write(&input, jpeg).unwrap();
    let mut binding = DataHash::from_reader("sha256", std::io::Cursor::new(jpeg)).unwrap();
    binding.pad = vec![0; 160_000];
    let bytes = TestSigner::new()
        .unwrap()
        .build_store(&binding, None)
        .unwrap();
    let (mut file, structure) = asset::open(&input).unwrap();
    structure
        .write(
            &mut file,
            &mut fs::File::create(&existing).unwrap(),
            &Updates::new().set_jumbf(bytes),
            &mut NullSink,
        )
        .unwrap();
    let (mut file, structure) = asset::open(&existing).unwrap();
    let item = structure.require_item(ItemKind::Jumbf).unwrap();
    assert!(item.extent_count() > 1);
    let previous = asset::read_store(&structure, &mut file).unwrap();
    sign(&existing, &output);
    assert!(validate(&output).contains("2 manifest(s)"));
    let (mut file, structure) = asset::open(&output).unwrap();
    let current = asset::read_store(&structure, &mut file).unwrap();
    let old_store = ManifestStore::parse(&previous).unwrap();
    let new_store = ManifestStore::parse(&current).unwrap();
    assert_eq!(
        old_store.manifests().next().unwrap().raw(),
        new_store.manifests().next().unwrap().raw(),
    );
}

#[test]
fn riff_excludes_chunk_header_and_payload_but_hashes_alignment_padding() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.wav");
    let output = directory.path().join("output.wav");
    fs::write(&input, wav()).unwrap();
    let signer = TestSigner::new().unwrap();
    let mut binding = DataHash::new("sha256", vec![0; 32]);
    let mut bytes = signer.build_store(&binding, None).unwrap();
    if bytes.len().is_multiple_of(2) {
        binding.pad.push(0);
        bytes = signer.build_store(&binding, None).unwrap();
    }
    assert_eq!(bytes.len() % 2, 1);
    let (mut file, structure) = asset::open(&input).unwrap();
    let written = structure
        .write(
            &mut file,
            &mut fs::File::create(&output).unwrap(),
            &Updates::new().set_jumbf(bytes.clone()),
            &mut NullSink,
        )
        .unwrap();
    let mut file = fs::File::open(&output).unwrap();
    let ranges = asset::exclusions(&written, &mut file).unwrap();
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].length, bytes.len() as u64 + 8);
    let item = written.require_item(ItemKind::Jumbf).unwrap();
    let segment = written
        .segment(item.extents().next().unwrap().segment())
        .unwrap();
    assert_eq!(segment.trailer().len(), 1);
    assert_eq!(
        ranges[0].start + ranges[0].length,
        segment.trailer().offset()
    );
    let before = asset::hash_asset(&mut file, written.total_size(), "sha256", &ranges).unwrap();
    let mut changed = fs::read(&output).unwrap();
    changed[segment.trailer().offset() as usize] ^= 1;
    fs::write(&output, changed).unwrap();
    let mut file = fs::File::open(&output).unwrap();
    let after = asset::hash_asset(&mut file, written.total_size(), "sha256", &ranges).unwrap();
    assert_ne!(before, after);
}

#[test]
fn failures_never_overwrite_existing_files_or_publish_partial_output() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.svg");
    let output = directory.path().join("output.svg");
    fs::write(&input, svg()).unwrap();
    fs::write(&output, b"existing output").unwrap();
    failure(
        cli(&[
            "sign".as_ref(),
            input.as_os_str(),
            "-o".as_ref(),
            output.as_os_str(),
        ]),
        "already exists",
    );
    assert_eq!(fs::read(&output).unwrap(), b"existing output");
    fs::remove_file(&output).unwrap();
    fs::write(asset::ca_path(&output), b"existing CA").unwrap();
    failure(
        cli(&[
            "sign".as_ref(),
            input.as_os_str(),
            "-o".as_ref(),
            output.as_os_str(),
        ]),
        "already exists",
    );
    assert_eq!(fs::read(asset::ca_path(&output)).unwrap(), b"existing CA");
    assert!(!output.exists());

    let bmff = directory.path().join("input.mp4");
    fs::write(&bmff, b"\0\0\0\x18ftypisom\0\0\0\0isommp42").unwrap();
    fs::remove_file(asset::ca_path(&output)).unwrap();
    failure(
        cli(&[
            "sign".as_ref(),
            bmff.as_os_str(),
            "-o".as_ref(),
            output.as_os_str(),
        ]),
        "not implemented",
    );
    assert!(!output.exists());
    assert!(!asset::ca_path(&output).exists());
    failure(
        cli(&["dump".as_ref(), input.as_os_str()]),
        "no C2PA manifest store",
    );

    // A BMFF's store can still be inspected even though its binding is unsupported.
    let output = directory.path().join("output.mp4");
    let bytes = TestSigner::new()
        .unwrap()
        .build_store(&DataHash::new("sha256", vec![0; 32]), None)
        .unwrap();
    let mut source = fs::File::open(&bmff).unwrap();
    let structure = HandlerRegistry::builtin()
        .parse_detect(&mut source)
        .unwrap();
    let mut destination = fs::File::create(&output).unwrap();
    structure
        .write(
            &mut source,
            &mut destination,
            &Updates::new().set_jumbf(bytes),
            &mut NullSink,
        )
        .unwrap();
    destination.flush().unwrap();
    assert!(success(cli(&["dump".as_ref(), output.as_os_str()])).contains("CBOR: tag(18)"));
    failure(
        cli(&["validate".as_ref(), output.as_os_str()]),
        "not implemented",
    );
}

#[test]
fn box_hash_detects_changes_outside_the_store_only() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.png");
    let signed = directory.path().join("signed.png");
    fs::write(&input, png()).unwrap();
    sign(&input, &signed);
    assert!(validate(&signed).contains("active c2pa.hash.boxes binding"));
    let original = fs::read(&signed).unwrap();

    // Any byte of a hashed box: here the IDAT chunk's compressed data. The
    // manifest, which comes first, also names IDAT, so search from the end.
    let mut changed = original.clone();
    let at = changed.windows(4).rposition(|w| w == b"IDAT").unwrap() + 4;
    changed[at] ^= 1;
    fs::write(&signed, &changed).unwrap();
    failure(
        cli(&["validate".as_ref(), signed.as_os_str()]),
        "box hash mismatch for IDAT",
    );

    // Adding a box that the hash does not list.
    let mut extra = original.clone();
    let iend = extra.windows(4).rposition(|w| w == b"IEND").unwrap() - 4;
    let chunk = b"\0\0\0\0teXt\x2b\x6b\x2e\x0e";
    extra.splice(iend..iend, chunk.iter().copied());
    fs::write(&signed, &extra).unwrap();
    failure(
        cli(&["validate".as_ref(), signed.as_os_str()]),
        "box hash does not list the asset's boxes",
    );
}

/// C2PA 2.4, 18.7.3: restart markers, every image of a multi-picture JPEG, and
/// RIFF LIST types are boxes of their own.
#[test]
fn box_hash_lists_restart_markers_images_and_riff_lists() {
    let directory = tempfile::tempdir().unwrap();
    let restart = [
        &[0xff, 0xd8][..],
        &[0xff, 0xdd, 0x00, 0x04, 0x00, 0x01],
        &[0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00],
        &[0x12, 0x34, 0xff, 0xd0, 0x56, 0xff, 0xd1, 0x78],
        &[0xff, 0xd9],
    ]
    .concat();
    let mpf = [[0xff, 0xd8, 0xff, 0xd9], [0xff, 0xd8, 0xff, 0xd9]].concat();
    let mut list = b"LIST".to_vec();
    list.extend_from_slice(&12u32.to_le_bytes());
    list.extend_from_slice(b"INFOINAM");
    list.extend_from_slice(&0u32.to_le_bytes());
    let mut wav = wav();
    wav.extend_from_slice(&list);
    let size = (wav.len() - 8) as u32;
    wav[4..8].copy_from_slice(&size.to_le_bytes());
    for (name, bytes, expected) in [
        ("restart.jpg", restart, &["\"RST0\"", "\"RST1\""][..]),
        ("mpf.jpg", mpf, &["\"SOI\""][..]),
        ("list.wav", wav, &["\"WAVE\"", "\"INFO\""][..]),
    ] {
        let input = directory.path().join(name);
        let output = directory.path().join(format!("signed-{name}"));
        fs::write(&input, &bytes).unwrap();
        sign(&input, &output);
        assert!(validate(&output).contains("active c2pa.hash.boxes binding"));
        let dump = success(cli(&["dump".as_ref(), output.as_os_str()]));
        for text in expected {
            assert!(dump.contains(text), "{name}: {text}");
        }
        if name == "mpf.jpg" {
            assert_eq!(dump.matches("\"SOI\"").count(), 2);
            assert!(!dump.contains("c2pa.after"));
        }
    }
}
