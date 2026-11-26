//! The de-obfuscation pipeline through the public API (Annex F.1, F.3; ADR 0008).
//!
//! Invisible characters are the detector here: hidden inside encoded layers, they show how
//! findings and flags travel back to the original text.
// Test helpers may panic: a scanning error is a test failure.
#![allow(clippy::unwrap_used)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use resguardo_core::config::ScanConfig;
use resguardo_core::{DataClass, Role, ScanLimit, ScanReport, ScanText};
use resguardo_scan::{Pipeline, ScanError};

fn scan_with(config: &ScanConfig, text: &str) -> ScanReport {
    Pipeline::new(config)
        .unwrap()
        .scan_text("/p", text)
        .unwrap()
}

fn scan(text: &str) -> ScanReport {
    scan_with(&ScanConfig::default(), text)
}

fn b64(text: &str) -> String {
    STANDARD.encode(text)
}

/// Readable text long enough to be a Base64 candidate, with a zero-width space inside.
const HIDDEN: &str = "nothing to see here,\u{200B} move along please";

#[test]
fn invisible_characters_are_reported_with_their_original_span() {
    let report = scan("gh\u{200B}p and \u{202E}x");
    let found: Vec<_> = report
        .findings
        .iter()
        .map(|f| (f.class, f.rule.as_str(), f.span.clone(), f.confidence))
        .collect();
    assert_eq!(
        found,
        vec![
            (
                DataClass::InvisibleText,
                "invisible_text.zero_width",
                2..5,
                100
            ),
            (DataClass::InvisibleText, "invisible_text.bidi", 11..14, 100),
        ]
    );
    assert!(
        report
            .findings
            .iter()
            .all(|f| f.pointer == "/p" && f.via.is_empty())
    );
    assert!(report.flags.is_empty());
}

#[test]
fn a_finding_inside_base64_spans_the_whole_fragment() {
    let encoded = b64(HIDDEN);
    let text = format!("see: {encoded} ok");
    let report = scan(&text);
    assert_eq!(report.findings.len(), 1, "{report:?}");
    let finding = &report.findings[0];
    assert_eq!(finding.class, DataClass::InvisibleText);
    assert_eq!(finding.span, 5..5 + encoded.len());
    assert_eq!(finding.via, ["base64"]);
    assert!(report.flags.is_empty());
}

#[test]
fn hex_and_url_layers_are_named_in_via() {
    let hex: String = HIDDEN.bytes().map(|b| format!("{b:02x}")).collect();
    let report = scan(&hex);
    assert_eq!(report.findings[0].via, ["hex"]);
    assert_eq!(report.findings[0].span, 0..hex.len());

    let url = "a%E2%80%8Bb%E2%80%8Bc%E2%80%8B";
    let report = scan(url);
    assert_eq!(report.findings[0].via, ["url"]);
    assert_eq!(report.findings[0].span, 0..url.len());
}

#[test]
fn layers_nest_in_the_order_they_are_crossed() {
    let inner = b64(HIDDEN);
    let url: String = inner.bytes().map(|b| format!("%{b:02X}")).collect();
    let report = scan(&url);
    let finding = report
        .findings
        .iter()
        .find(|f| f.class == DataClass::InvisibleText)
        .unwrap();
    assert_eq!(finding.via, ["url", "base64"]);
    assert_eq!(finding.span, 0..url.len());
}

#[test]
fn beyond_the_maximum_depth_there_is_only_a_flag() {
    let triple = b64(&b64(&b64(HIDDEN)));
    let report = scan(&triple);
    assert!(
        report
            .findings
            .iter()
            .all(|f| f.class != DataClass::InvisibleText),
        "{report:?}"
    );
    assert_eq!(report.flags.len(), 1, "{report:?}");
    let flag = &report.flags[0];
    assert_eq!(flag.limit, ScanLimit::DecodeDepth);
    assert_eq!(flag.span, 0..triple.len());
    assert_eq!(flag.via, ["base64", "base64", "base64"]);
    assert_eq!(flag.pointer, "/p");

    // One more level allowed: found, no flag.
    let deeper = ScanConfig {
        max_decode_depth: 3,
        ..ScanConfig::default()
    };
    let report = scan_with(&deeper, &triple);
    assert!(report.flags.is_empty(), "{report:?}");
    let finding = report
        .findings
        .iter()
        .find(|f| f.class == DataClass::InvisibleText)
        .unwrap();
    assert_eq!(finding.via, ["base64", "base64", "base64"]);
}

#[test]
fn with_depth_zero_nothing_is_decoded_and_text_is_flagged() {
    let config = ScanConfig {
        max_decode_depth: 0,
        ..ScanConfig::default()
    };
    let report = scan_with(&config, &b64(HIDDEN));
    assert!(report.findings.is_empty(), "{report:?}");
    assert_eq!(report.flags[0].limit, ScanLimit::DecodeDepth);
    assert_eq!(report.flags[0].via, ["base64"]);
}

#[test]
fn binary_payloads_are_not_decoded_and_raise_no_flags() {
    let binary: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let encoded = STANDARD.encode(binary);
    let config = ScanConfig {
        max_decode_depth: 0,
        ..ScanConfig::default()
    };
    for report in [scan(&encoded), scan_with(&config, &encoded)] {
        assert!(report.flags.is_empty(), "{report:?}");
        // The only finding is the entropy check on the encoded text itself (Annex F.2): nothing
        // comes from a decoded layer.
        let found: Vec<_> = report
            .findings
            .iter()
            .map(|f| (f.class, f.span.clone(), f.via.len()))
            .collect();
        assert_eq!(found, vec![(DataClass::SecretCandidate, 0..encoded.len(), 0)]);
    }
}

#[test]
fn a_long_decoded_text_is_scanned_up_to_the_limit_and_flagged() {
    // Invisible character at the start (within the limit) and at the end (beyond it).
    let config = ScanConfig {
        max_derived_bytes: 1000,
        ..ScanConfig::default()
    };
    let plain = format!("\u{200B}{}\u{2060}", "lorem ipsum ".repeat(200));
    let encoded = b64(&plain);
    let report = scan_with(&config, &encoded);
    assert_eq!(report.flags.len(), 1, "{report:?}");
    assert_eq!(report.flags[0].limit, ScanLimit::DerivedBytes);
    assert_eq!(report.flags[0].span, 0..encoded.len());
    let rules: Vec<_> = report.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rules, ["invisible_text.zero_width"]);
}

#[test]
fn findings_keep_the_order_and_pointer_of_their_text() {
    let texts = [
        ScanText {
            pointer: "/messages/0/content".into(),
            role: Role::User,
            text: "a\u{200B}".into(),
        },
        ScanText {
            pointer: "/system".into(),
            role: Role::System,
            text: "clean".into(),
        },
        ScanText {
            pointer: "/messages/1/content".into(),
            role: Role::Assistant,
            text: "\u{FEFF}b".into(),
        },
    ];
    let report = Pipeline::new(&ScanConfig::default())
        .unwrap()
        .scan(&texts)
        .unwrap();
    let pointers: Vec<_> = report.findings.iter().map(|f| f.pointer.as_str()).collect();
    assert_eq!(pointers, ["/messages/0/content", "/messages/1/content"]);
    assert_eq!(report.findings[1].span, 0..3);
}

#[test]
fn invalid_settings_are_refused() {
    let config = ScanConfig {
        entropy_threshold: f64::NAN,
        max_derived_bytes: 0,
        ..ScanConfig::default()
    };
    let Err(ScanError::Config(problems)) = Pipeline::new(&config) else {
        panic!("NaN threshold and zero bytes must be refused");
    };
    assert_eq!(problems.len(), 2, "{problems:?}");
}

#[test]
fn findings_and_flags_never_hold_content() {
    let text = format!("{} {}", b64(HIDDEN), b64(&b64(&b64(HIDDEN))));
    let report = scan(&text);
    let debug = format!("{report:?}");
    assert!(!debug.contains("nothing to see"), "{debug}");
    assert!(!debug.contains(&b64(HIDDEN)), "{debug}");
}
