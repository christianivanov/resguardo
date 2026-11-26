//! RFC 8785 (JSON Canonicalization Scheme) for the subset the audit log uses: strings,
//! integers, booleans, null, lists and objects (ADR 0003, ADR 0015). The expected values are
//! copied from the RFC.
#![allow(clippy::unwrap_used)]

use resguardo_audit::{CanonicalError, canonicalize};
use serde_json::{Value, json};

#[test]
fn g5_rfc8785_sorting_example() {
    // Section 3.2.3: names sorted by their UTF-16 code units.
    let input = json!({
        "\u{20ac}": "Euro Sign",
        "\r": "Carriage Return",
        "\u{fb33}": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\u{1f600}": "Emoji: Grinning Face",
        "\u{80}": "Control",
        "\u{f6}": "Latin Small Letter O With Diaeresis"
    });
    let expected = concat!(
        "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",",
        "\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",",
        "\"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"
    );
    assert_eq!(canonicalize(&input).unwrap(), expected);
}

#[test]
fn g5_rfc8785_string_and_literals_bytes() {
    // Section 3.2.2 input without its numbers (the log has no floats), and the bytes of
    // Section 3.2.4 for the same members.
    let input: Value = serde_json::from_str(
        r#"{"string": "\u20ac$\u000F\u000aA'B\"\\\\\"\/", "literals": [null, true, false]}"#,
    )
    .unwrap();
    let expected: &[u8] = &[
        0x7b, 0x22, 0x6c, 0x69, 0x74, 0x65, 0x72, 0x61, 0x6c, 0x73, 0x22, 0x3a, 0x5b, 0x6e, 0x75,
        0x6c, 0x6c, 0x2c, 0x74, 0x72, 0x75, 0x65, 0x2c, 0x66, 0x61, 0x6c, 0x73, 0x65, 0x5d, 0x2c,
        0x22, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x22, 0x3a, 0x22, 0xe2, 0x82, 0xac, 0x24, 0x5c,
        0x75, 0x30, 0x30, 0x30, 0x66, 0x5c, 0x6e, 0x41, 0x27, 0x42, 0x5c, 0x22, 0x5c, 0x5c, 0x5c,
        0x5c, 0x5c, 0x22, 0x2f, 0x22, 0x7d,
    ];
    assert_eq!(canonicalize(&input).unwrap().as_bytes(), expected);
}

#[test]
fn control_characters_use_short_escapes_or_lowercase_hex() {
    let input = json!(["\u{8}\t\n\u{c}\r", "\u{0}\u{1f}\u{7f}"]);
    assert_eq!(
        canonicalize(&input).unwrap(),
        "[\"\\b\\t\\n\\f\\r\",\"\\u0000\\u001f\u{7f}\"]"
    );
}

#[test]
fn nested_objects_are_sorted_and_arrays_keep_their_order() {
    let input = json!({"b": [3, 1, {"z": 1, "a": -2}], "a": {"y": true, "x": null}});
    assert_eq!(
        canonicalize(&input).unwrap(),
        r#"{"a":{"x":null,"y":true},"b":[3,1,{"a":-2,"z":1}]}"#
    );
}

#[test]
fn floats_and_unsafe_integers_are_refused() {
    assert_eq!(canonicalize(&json!(1.5)), Err(CanonicalError::NotAnInteger));
    assert_eq!(
        canonicalize(&json!(9_007_199_254_740_992_u64)),
        Err(CanonicalError::IntegerTooLarge)
    );
    assert_eq!(
        canonicalize(&json!(9_007_199_254_740_991_u64)).unwrap(),
        "9007199254740991"
    );
    assert_eq!(
        canonicalize(&json!(-9_007_199_254_740_991_i64)).unwrap(),
        "-9007199254740991"
    );
}
