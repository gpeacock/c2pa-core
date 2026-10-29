//! Expanded structural/content display; binary previews are capped at 32 bytes.

use std::io::{self, Write};

use c2pa_cbor::Value;
use c2pa_store::{ContentType, ManifestStore, Node, SuperBox};

use crate::Result;

fn binary(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().take(32).map(|b| format!("{b:02x}")).collect();
    format!(
        "bytes[{}]: {hex}{}",
        bytes.len(),
        if bytes.len() > 32 { "..." } else { "" }
    )
}

fn value(out: &mut impl Write, item: &Value, depth: usize, name: &str) -> io::Result<()> {
    write!(out, "{}{name}: ", "  ".repeat(depth))?;
    match item {
        Value::Map(values) => {
            writeln!(out, "map[{}]", values.len())?;
            for (key, item) in values {
                let key = match key {
                    Value::Text(key) => format!("{key:?}"),
                    _ => format!("{key:?}"),
                };
                value(out, item, depth + 1, &key)?;
            }
        }
        Value::Array(values) => {
            writeln!(out, "array[{}]", values.len())?;
            for (i, item) in values.iter().enumerate() {
                value(out, item, depth + 1, &format!("[{i}]"))?;
            }
        }
        Value::Tag(tag, item) => {
            writeln!(out, "tag({tag})")?;
            value(out, item, depth + 1, "value")?;
        }
        Value::Bytes(bytes) => writeln!(out, "{}", binary(bytes))?,
        Value::Text(text) => writeln!(out, "{text:?}")?,
        Value::Integer(number) => writeln!(out, "{number}")?,
        Value::Float(number) => writeln!(out, "{number:?}")?,
        Value::Bool(boolean) => writeln!(out, "{boolean}")?,
        Value::Null => writeln!(out, "null")?,
    }
    Ok(())
}

fn tree(out: &mut impl Write, sb: &SuperBox<'_>, depth: usize) -> Result<usize> {
    let indent = "  ".repeat(depth);
    writeln!(
        out,
        "{indent}jumb ({:?}) - {} bytes",
        sb.label().unwrap_or("<no label>"),
        sb.raw.len()
    )?;
    let uuid: String = sb
        .description
        .uuid
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    writeln!(out, "{indent}  jumd: {:?} ({uuid})", sb.content_type())?;
    writeln!(
        out,
        "{indent}    label: {:?}",
        sb.label().unwrap_or("<no label>")
    )?;
    if let Some(salt) = sb.salt() {
        writeln!(out, "{indent}    salt: {}", binary(salt))?;
    }
    let mut errors = 0;
    for child in &sb.children {
        let content = match child {
            Node::Super(child) => {
                errors += tree(out, child, depth + 1)?;
                continue;
            }
            Node::Content(content) => content,
        };
        writeln!(
            out,
            "{indent}  {} - {} payload bytes",
            String::from_utf8_lossy(&content.tbox).escape_debug(),
            content.data.len(),
        )?;
        let cbor = match &content.tbox {
            b"cbor" => Some(content.data),
            b"uuid" if sb.content_type() == ContentType::Signature => {
                Some(content.data.get(16..).ok_or("truncated signature UUID")?)
            }
            _ => None,
        };
        if let Some(bytes) = cbor {
            match c2pa_cbor::from_slice::<Value>(bytes) {
                Ok(item) => value(out, &item, depth + 2, "CBOR")?,
                Err(e) => {
                    writeln!(out, "{indent}    CBOR decode error: {e}")?;
                    errors += 1;
                }
            }
        } else if content.tbox == *b"json" {
            match serde_json::from_slice::<serde_json::Value>(content.data) {
                Ok(item) => {
                    for line in serde_json::to_string_pretty(&item)?.lines() {
                        writeln!(out, "{indent}    {line}")?;
                    }
                }
                Err(e) => {
                    writeln!(out, "{indent}    JSON decode error: {e}")?;
                    errors += 1;
                }
            }
        } else {
            writeln!(out, "{indent}    {}", binary(content.data))?;
        }
    }
    Ok(errors)
}

pub fn dump(out: &mut impl Write, bytes: &[u8]) -> Result<()> {
    let store = ManifestStore::parse(bytes)?;
    let errors = tree(out, store.root(), 0)?;
    if errors != 0 {
        return Err(format!("{errors} payload decode error(s)").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use c2pa_store::{BoxWriter, uuids};

    fn render(tbox: &[u8; 4], bytes: &[u8]) -> (String, bool) {
        let mut writer = BoxWriter::new(Vec::new());
        writer
            .start_superbox(&uuids::MANIFEST_STORE, "c2pa", None)
            .unwrap();
        writer.content_box(tbox, bytes).unwrap();
        writer.end_box().unwrap();
        let bytes = writer.finish().unwrap();
        let mut output = Vec::new();
        let ok = dump(&mut output, &bytes).is_ok();
        (String::from_utf8(output).unwrap(), ok)
    }

    #[test]
    fn binary_preview_is_at_most_32_bytes() {
        for length in [0, 1, 31, 32, 33, 100] {
            let result = binary(&vec![0xab; length]);
            assert_eq!(
                result,
                format!(
                    "bytes[{length}]: {}{}",
                    "ab".repeat(length.min(32)),
                    if length > 32 { "..." } else { "" },
                )
            );
        }
    }

    #[test]
    fn displays_json_and_unknown_content_and_reports_decode_errors() {
        let (output, ok) = render(b"json", br#"{"nested":[true,null,{"key":"hello"}]}"#);
        assert!(ok);
        assert!(output.contains("\"nested\": ["));
        assert!(output.contains("\"key\": \"hello\""));
        let (output, ok) = render(b"zzzz", &[0xab; 100]);
        assert!(ok);
        assert!(output.contains(&binary(&[0xab; 100])));
        for (tbox, bytes, message) in [
            (b"json", &b"{"[..], "JSON decode error"),
            (b"cbor", &b"\xff"[..], "CBOR decode error"),
        ] {
            let (output, ok) = render(tbox, bytes);
            assert!(!ok);
            assert!(output.contains(message));
        }
    }
}
