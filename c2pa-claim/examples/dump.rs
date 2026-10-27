//! Read a raw `.c2pa` manifest store, display its complete JUMBF tree with
//! decoded CBOR/JSON, and validate claims' assertion hashed-URI references.
//!
//! Usage: `cargo run -p c2pa-claim --example dump -- <path-to.c2pa>`
//!
//! Binary values show their length and up to 32 bytes of hex. Unknown boxes
//! (including compressed payloads) are displayed as binary, not interpreted.
//!
//! Claims decode as the typed (v2-only) [`Claim`] when possible, for full
//! display of `instanceID`, generator info, and title. A claim that doesn't
//! fit that shape (e.g. a v1 `claim-map`) falls back to a permissive decode
//! that only recovers the assertion references and default algorithm, so
//! verification still runs.

use std::io::{self, Write};
use std::process::ExitCode;

use c2pa_cbor::Value;
use c2pa_claim::{Claim, HashedUri};
use c2pa_store::{ContentType, ManifestStore, Node, SuperBox};
use serde::Deserialize;

/// Version-agnostic view of the assertion references and default algorithm in
/// a claim. Used as a fallback when a claim doesn't decode as [`Claim`].
#[derive(Deserialize, Default)]
struct AnyClaim {
    #[serde(default)]
    created_assertions: Vec<HashedUri>,
    #[serde(default)]
    gathered_assertions: Vec<HashedUri>,
    #[serde(default)]
    assertions: Vec<HashedUri>,
    #[serde(default)]
    alg: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn dump_binary(out: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    let preview = &bytes[..bytes.len().min(32)];
    writeln!(
        out,
        "bytes[{}]: {}{}",
        bytes.len(),
        hex(preview),
        if preview.len() < bytes.len() {
            "..."
        } else {
            ""
        }
    )
}

fn dump_cbor_value(
    out: &mut impl Write,
    value: &Value,
    depth: usize,
    name: &str,
) -> io::Result<()> {
    write!(out, "{}{name}: ", "  ".repeat(depth))?;
    match value {
        Value::Array(values) => {
            writeln!(out, "array[{}]", values.len())?;
            for (i, value) in values.iter().enumerate() {
                dump_cbor_value(out, value, depth + 1, &format!("[{i}]"))?;
            }
        }
        Value::Map(values) => {
            writeln!(out, "map[{}]", values.len())?;
            for (key, value) in values {
                let key = match key {
                    Value::Text(text) => format!("{text:?}"),
                    _ => format!("{key:?}"),
                };
                dump_cbor_value(out, value, depth + 1, &key)?;
            }
        }
        Value::Tag(tag, value) => {
            writeln!(out, "tag({tag})")?;
            dump_cbor_value(out, value, depth + 1, "value")?;
        }
        Value::Bytes(bytes) => dump_binary(out, bytes)?,
        Value::Text(text) => writeln!(out, "{text:?}")?,
        Value::Integer(value) => writeln!(out, "{value}")?,
        Value::Float(value) => writeln!(out, "{value:?}")?,
        Value::Bool(value) => writeln!(out, "{value}")?,
        Value::Null => writeln!(out, "null")?,
    }
    Ok(())
}

fn dump_cbor(out: &mut impl Write, bytes: &[u8], depth: usize) -> io::Result<usize> {
    match c2pa_cbor::from_slice::<Value>(bytes) {
        Ok(value) => {
            dump_cbor_value(out, &value, depth, "CBOR")?;
            Ok(0)
        }
        Err(e) => {
            writeln!(out, "{}CBOR decode error: {e}", "  ".repeat(depth))?;
            Ok(1)
        }
    }
}

fn dump_json_value(
    out: &mut impl Write,
    value: &serde_json::Value,
    depth: usize,
    name: &str,
) -> io::Result<()> {
    write!(out, "{}{name}: ", "  ".repeat(depth))?;
    match value {
        serde_json::Value::Object(values) => {
            writeln!(out, "object[{}]", values.len())?;
            for (key, value) in values {
                dump_json_value(out, value, depth + 1, &format!("{key:?}"))?;
            }
        }
        serde_json::Value::Array(values) => {
            writeln!(out, "array[{}]", values.len())?;
            for (i, value) in values.iter().enumerate() {
                dump_json_value(out, value, depth + 1, &format!("[{i}]"))?;
            }
        }
        _ => writeln!(out, "{value}")?,
    }
    Ok(())
}

fn dump_tree(
    out: &mut impl Write,
    sb: &SuperBox<'_>,
    depth: usize,
    index: usize,
) -> io::Result<usize> {
    let indent = "  ".repeat(depth);
    writeln!(
        out,
        "{indent}{index}: jumb ({:?}) - {} bytes",
        sb.label().unwrap_or("<no label>"),
        sb.raw.len()
    )?;
    writeln!(
        out,
        "{indent}  0: jumd - {} bytes",
        sb.description.raw.len()
    )?;
    writeln!(
        out,
        "{indent}    type: {:?} ({})",
        sb.content_type(),
        hex(&sb.description.uuid)
    )?;
    writeln!(
        out,
        "{indent}    label: {:?}",
        sb.label().unwrap_or("<no label>")
    )?;
    writeln!(out, "{indent}    toggles: 0x{:02x}", sb.description.toggles)?;
    if let Some(salt) = sb.salt() {
        write!(out, "{indent}    salt: ")?;
        dump_binary(out, salt)?;
    }

    let mut errors = 0;
    for (i, child) in sb.children.iter().enumerate() {
        let content = match child {
            Node::Super(child) => {
                errors += dump_tree(out, child, depth + 1, i + 1)?;
                continue;
            }
            Node::Content(content) => content,
        };
        writeln!(
            out,
            "{indent}  {}: {} - {} bytes ({} payload bytes)",
            i + 1,
            String::from_utf8_lossy(&content.tbox).escape_debug(),
            content.raw.len(),
            content.data.len()
        )?;
        match &content.tbox {
            b"cbor" => errors += dump_cbor(out, content.data, depth + 2)?,
            b"json" => match serde_json::from_slice::<serde_json::Value>(content.data) {
                Ok(value) => dump_json_value(out, &value, depth + 2, "JSON")?,
                Err(e) => {
                    writeln!(out, "{indent}    JSON decode error: {e}")?;
                    errors += 1;
                }
            },
            b"uuid" if sb.content_type() == ContentType::Signature => {
                if content.data.len() < 16 {
                    writeln!(out, "{indent}    signature UUID error: fewer than 16 bytes")?;
                    errors += 1;
                } else {
                    writeln!(out, "{indent}    UUID: {}", hex(&content.data[..16]))?;
                    errors += dump_cbor(out, &content.data[16..], depth + 2)?;
                }
            }
            _ => {
                write!(out, "{indent}    ")?;
                dump_binary(out, content.data)?;
            }
        }
    }
    Ok(errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use c2pa_store::{uuids, BoxWriter};

    fn render_content(tbox: &[u8; 4], bytes: &[u8], signature: bool) -> (String, usize) {
        let mut writer = BoxWriter::new(Vec::new());
        writer
            .start_superbox(&uuids::MANIFEST_STORE, "c2pa", Some(&[1, 2]))
            .unwrap();
        if signature {
            writer
                .start_superbox(&uuids::SIGNATURE, "c2pa.signature", None)
                .unwrap();
        }
        writer.content_box(tbox, bytes).unwrap();
        if signature {
            writer.end_box().unwrap();
        }
        writer.end_box().unwrap();
        let bytes = writer.finish().unwrap();
        let store = ManifestStore::parse(&bytes).unwrap();
        let mut output = Vec::new();
        let errors = dump_tree(&mut output, store.root(), 0, 0).unwrap();
        (String::from_utf8(output).unwrap(), errors)
    }

    #[test]
    fn expands_cbor_maps_arrays_tags_and_binary() {
        let value = Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(vec![0xab; 32]),
                Value::Map(
                    [
                        (Value::Integer(1), Value::Integer(-7)),
                        (
                            Value::Text("nested".into()),
                            Value::Array(vec![
                                Value::Text("hello\nworld".into()),
                                Value::Bool(true),
                                Value::Null,
                                Value::Float(1.5),
                            ]),
                        ),
                    ]
                    .into(),
                ),
                Value::Bytes(vec![0; 100]),
            ])),
        );
        let bytes = c2pa_cbor::to_vec(&value).unwrap();
        let (output, errors) = render_content(b"cbor", &bytes, false);
        assert_eq!(errors, 0);
        for expected in [
            "0: jumb (\"c2pa\")",
            "0: jumd - ",
            "type: ManifestStore (6332706100110010800000aa00389b71)",
            "salt: bytes[2]: 0102",
            "1: cbor - ",
            "CBOR: tag(18)",
            "value: array[3]",
            "[1]: map[2]",
            "Integer(1): -7",
            "\"nested\": array[4]",
            "[0]: \"hello\\nworld\"",
            "[1]: true",
            "[2]: null",
            "[3]: 1.5",
            &format!("bytes[32]: {}", "ab".repeat(32)),
            &format!("bytes[100]: {}...", "00".repeat(32)),
        ] {
            assert!(output.contains(expected), "missing {expected:?}:\n{output}");
        }
    }

    #[test]
    fn expands_json_and_legacy_uuid_signatures() {
        let (output, errors) = render_content(
            b"json",
            br#"{"actions":[{"action":"c2pa.created"}],"empty":{},"number":42}"#,
            false,
        );
        assert_eq!(errors, 0);
        assert!(output.contains("JSON: object[3]"));
        assert!(output.contains("\"actions\": array[1]"));
        assert!(output.contains("\"action\": \"c2pa.created\""));
        assert!(output.contains("\"empty\": object[0]"));
        assert!(output.contains("\"number\": 42"));

        let mut bytes = uuids::SIGNATURE.to_vec();
        bytes.extend_from_slice(&[0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x40]);
        let (output, errors) = render_content(b"uuid", &bytes, true);
        assert_eq!(errors, 0);
        assert!(output.contains("1: jumb (\"c2pa.signature\")"));
        assert!(output.contains("UUID: 6332637300110010800000aa00389b71"));
        assert!(output.contains("CBOR: tag(18)"));
        assert!(output.contains("value: array[4]"));
    }

    #[test]
    fn reports_payload_errors_and_retains_unknown_data() {
        for (tbox, bytes, signature, message) in [
            (b"cbor", &b"\xff"[..], false, "CBOR decode error:"),
            (b"cbor", &b"\xa0\xa0"[..], false, "CBOR decode error:"),
            (b"json", &b"{"[..], false, "JSON decode error:"),
            (b"uuid", &b"short"[..], true, "signature UUID error:"),
        ] {
            let (output, errors) = render_content(tbox, bytes, signature);
            assert_eq!(errors, 1);
            assert!(output.contains(message), "{output}");
        }
        let (output, errors) = render_content(b"zzzz", &[0, 1, 2], false);
        assert_eq!(errors, 0);
        assert!(output.contains("1: zzzz - "));
        assert!(output.contains("bytes[3]: 000102"));
    }

    #[test]
    fn propagates_output_errors() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("test write failure"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let bytes = include_bytes!("../tests/fixtures/nested-firefly.c2pa");
        let store = ManifestStore::parse(bytes).unwrap();
        assert!(dump_tree(&mut FailingWriter, store.root(), 0, 0).is_err());
    }
}

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: dump <path-to.c2pa>");
        return ExitCode::FAILURE;
    };

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("file: {path} ({} bytes)", bytes.len());

    let store = match ManifestStore::parse(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("parse error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let manifests: Vec<_> = store.manifests().collect();
    println!("manifests: {}", manifests.len());

    println!("\nJUMBF tree:");
    let decode_failures = match dump_tree(&mut io::stdout().lock(), store.root(), 0, 0) {
        Ok(errors) => errors,
        Err(e) => {
            eprintln!("write dump: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut verified = 0usize;
    let mut failures = 0usize;

    for manifest in &manifests {
        let label = manifest.label().unwrap_or("<no label>");
        let active = store
            .active_manifest()
            .and_then(|a| a.label())
            .zip(manifest.label())
            .is_some_and(|(a, l)| a == l);
        println!("\n[{label}]{}", if active { "  (active)" } else { "" });

        let claim_bytes = match manifest.claim_cbor() {
            Ok(c) => c,
            Err(e) => {
                println!("  no claim: {e}");
                failures += 1;
                continue;
            }
        };

        let (default_alg, refs): (Option<String>, Vec<(&str, HashedUri)>) =
            match Claim::from_cbor(claim_bytes) {
                Ok(claim) => {
                    println!("  instanceID: {}", claim.instance_id);
                    let version = claim
                        .claim_generator_info
                        .version
                        .as_deref()
                        .map(|v| format!(" {v}"))
                        .unwrap_or_default();
                    println!("  generator: {}{version}", claim.claim_generator_info.name);
                    if let Some(title) = &claim.title {
                        println!("  title: {title}");
                    }
                    println!(
                        "  default alg: {}",
                        claim.alg.as_deref().unwrap_or("<none>")
                    );

                    let mut refs: Vec<(&str, HashedUri)> = claim
                        .created_assertions
                        .into_iter()
                        .map(|h| ("created", h))
                        .collect();
                    if let Some(gathered) = claim.gathered_assertions {
                        refs.extend(gathered.into_iter().map(|h| ("gathered", h)));
                    }
                    (claim.alg, refs)
                }
                Err(e) => {
                    println!("  claim: not a v2 claim ({e}); using permissive decode");
                    match c2pa_cbor::from_slice::<AnyClaim>(claim_bytes) {
                        Ok(any) => {
                            println!("  default alg: {}", any.alg.as_deref().unwrap_or("<none>"));
                            let refs = any
                                .created_assertions
                                .into_iter()
                                .map(|h| ("created", h))
                                .chain(any.gathered_assertions.into_iter().map(|h| ("gathered", h)))
                                .chain(any.assertions.into_iter().map(|h| ("assertion", h)))
                                .collect();
                            (any.alg, refs)
                        }
                        Err(e) => {
                            println!("  claim decode error: {e}");
                            failures += 1;
                            continue;
                        }
                    }
                }
            };

        println!("  assertions:");
        for (kind, href) in &refs {
            match href.verify(&store, manifest, default_alg.as_deref()) {
                Ok(()) => {
                    println!("    ok   [{kind}] {}", href.url());
                    verified += 1;
                }
                Err(e) => {
                    println!("    FAIL [{kind}] {} -> {e:?}", href.url());
                    failures += 1;
                }
            }
        }
    }

    println!("\n{verified} hashed URI(s) verified, {failures} failure(s)");
    if decode_failures > 0 {
        eprintln!("{decode_failures} payload decode failure(s)");
    }
    if failures == 0 && decode_failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
