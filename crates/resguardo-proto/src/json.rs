//! Strict JSON parsing (ADR 0007).
//!
//! The scanner reads the parsed body while the provider receives the original bytes, so any
//! difference in how two parsers read the same bytes is a way to send data out unscanned.
//! This parser rejects what could be read two ways:
//!
//! - duplicate object keys, compared after unescaping;
//! - invalid UTF-8, unpaired surrogates, trailing data and numbers out of range
//!   (`serde_json` already rejects these);
//! - nesting deeper than 128 levels (`serde_json`'s recursion limit).
//!
//! Errors carry a position, never body content: a key or value could be the secret itself.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::error::Category;
use serde_json::{Map, Value};

/// Why a request was not accepted. Messages are fixed text: no body content, ever.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtoError {
    #[error("request body is not valid JSON (line {line}, column {column})")]
    InvalidJson { line: usize, column: usize },
    #[error("request body has a duplicate object key (line {line}, column {column})")]
    DuplicateKey { line: usize, column: usize },
    #[error("request body must be a JSON object")]
    NotAnObject,
    /// The name is chosen by Resguardo (`"model"`, `"messages"`…), never taken from the body.
    #[error("field '{0}' is missing or has the wrong type")]
    InvalidField(&'static str),
    #[error("query parameters other than the ones this route accepts are not allowed")]
    QueryNotAllowed,
}

/// Parses `body` into a [`Value`], rejecting duplicate keys.
pub fn parse_strict(body: &[u8]) -> Result<Value, ProtoError> {
    match serde_json::from_slice::<Strict>(body) {
        Ok(Strict(value)) => Ok(value),
        // `Data` errors come only from `StrictVisitor`, whose one custom error is a duplicate
        // key: a plain JSON value has no type to mismatch.
        Err(e) if e.classify() == Category::Data => Err(ProtoError::DuplicateKey {
            line: e.line(),
            column: e.column(),
        }),
        // The message of a serde_json syntax error is dropped on purpose; only the position
        // is kept, so no fragment of the body can reach a log or a response.
        Err(e) => Err(ProtoError::InvalidJson {
            line: e.line(),
            column: e.column(),
        }),
    }
}

/// A [`Value`] whose objects were checked for duplicate keys while parsing.
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    /// JSON has no NaN or infinity, so every parsed float is finite.
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(item)) = access.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if map.contains_key(&key) {
                // Fixed text: the key itself is never part of the error.
                return Err(de::Error::custom("duplicate object key"));
            }
            let Strict(value) = access.next_value()?;
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected(body: &[u8]) -> ProtoError {
        parse_strict(body).expect_err("must be rejected")
    }

    #[test]
    fn plain_json_is_parsed_unchanged() {
        let body = br#"{"a":[1,-2,3.5,true,null,"x"],"b":{"c":"\u00e9"}}"#;
        let expected: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(parse_strict(body).unwrap(), expected);
    }

    #[test]
    fn duplicate_keys_are_rejected_at_any_depth() {
        for body in [
            br#"{"content":"a","content":"b"}"#.as_slice(),
            br#"{"messages":[{"role":"user","role":"system"}]}"#,
            // Same key after unescaping.
            br#"{"content":"a","con\u0074ent":"b"}"#,
        ] {
            assert!(
                matches!(rejected(body), ProtoError::DuplicateKey { .. }),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn ambiguous_or_broken_input_is_rejected() {
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        let cases: [&[u8]; 8] = [
            b"",
            b"{\"a\":\"\xff\"}",  // invalid UTF-8
            br#"{"a":"\ud800"}"#, // unpaired surrogate
            b"\xef\xbb\xbf{}",    // byte order mark
            b"{} {}",             // trailing data
            br#"{"a":1e400}"#,    // number out of range
            br#"{"a":1,}"#,       // trailing comma
            deep.as_bytes(),      // nesting beyond 128 levels
        ];
        for body in cases {
            assert!(
                matches!(rejected(body), ProtoError::InvalidJson { .. }),
                "{:?}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn errors_never_contain_body_content() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        for body in [
            format!(r#"{{"{secret}":1,"{secret}":2}}"#),
            format!(r#"{{"a":"{secret}" "b"}}"#),
            format!(r#"{{"a":{secret}}}"#),
        ] {
            let message = rejected(body.as_bytes()).to_string();
            assert!(!message.contains(secret), "{message}");
            assert!(!message.contains("AKIA"), "{message}");
        }
    }
}
