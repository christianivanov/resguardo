//! RFC 8785 (JSON Canonicalization Scheme) for the values the audit log holds: strings,
//! integers, booleans, null, lists and objects (ADR 0003). Floats are refused, so the number
//! formatting of ECMAScript is never needed: an integer within ±(2^53 − 1) is written in
//! decimal, which is what ECMAScript produces for it.

use serde_json::Value;

/// The largest integer ECMAScript represents exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    #[error("audit values must be integers, not floating-point numbers")]
    NotAnInteger,
    #[error("audit integers must be within ±(2^53 - 1)")]
    IntegerTooLarge,
}

/// The canonical serialization of `value`.
pub fn canonicalize(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write(value, &mut out)?;
    Ok(out)
}

fn write(value: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => {
            if let Some(n) = number.as_u64() {
                if n > MAX_SAFE_INTEGER {
                    return Err(CanonicalError::IntegerTooLarge);
                }
                out.push_str(&n.to_string());
            } else if let Some(n) = number.as_i64() {
                if n.unsigned_abs() > MAX_SAFE_INTEGER {
                    return Err(CanonicalError::IntegerTooLarge);
                }
                out.push_str(&n.to_string());
            } else {
                return Err(CanonicalError::NotAnInteger);
            }
        }
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out)?;
            }
            out.push(']');
        }
        Value::Object(object) => {
            // Section 3.2.3: names sorted by their UTF-16 code units, unsigned.
            let mut members: Vec<(&String, &Value)> = object.iter().collect();
            members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (name, item)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(name, out);
                out.push(':');
                write(item, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Section 3.2.2.2: `"` and `\` escaped, the five short escapes for their controls, other
/// controls as lowercase `\u00hh`, everything else as it is. Rust strings cannot hold lone
/// surrogates, which the RFC requires to be refused.
fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}
