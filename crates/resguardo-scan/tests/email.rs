//! Email addresses (Annex F.5) with the pattern and boundary checks of ADR 0010.
// Test helpers may panic: a scanning error is a test failure.
#![allow(clippy::unwrap_used)]

use std::ops::Range;

use resguardo_core::DataClass;
use resguardo_core::config::ScanConfig;
use resguardo_scan::Pipeline;

/// (class, span) of every finding.
fn found(text: &str) -> Vec<(DataClass, Range<usize>)> {
    Pipeline::new(&ScanConfig::default())
        .unwrap()
        .scan_text("/messages/0/content", text)
        .unwrap()
        .findings
        .into_iter()
        .map(|f| (f.class, f.span))
        .collect()
}

fn email(span: Range<usize>) -> Vec<(DataClass, Range<usize>)> {
    vec![(DataClass::Email, span)]
}

#[test]
fn an_address_in_a_sentence_is_found_without_the_final_dot() {
    assert_eq!(
        found("escribe a ana.garcia+test@example.co.uk."),
        email(10..39)
    );
}

#[test]
fn rule_and_confidence() {
    let report = Pipeline::new(&ScanConfig::default())
        .unwrap()
        .scan_text("", "ana@example.com")
        .unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule, "email.address");
    assert_eq!(report.findings[0].confidence, 80);
}

#[test]
fn upper_case_and_a_mailto_prefix_are_accepted() {
    assert_eq!(found("ANA@EXAMPLE.ES"), email(0..14));
    assert_eq!(found("mailto:ana@example.com"), email(7..22));
}

#[test]
fn addresses_without_a_valid_top_level_domain_are_not_found() {
    for text in [
        "ana@localhost",
        "ana@example.c",
        "ana@example.123",
        "@example.com",
    ] {
        assert_eq!(found(text), vec![], "{text}");
    }
}

#[test]
fn a_local_part_over_64_characters_is_not_an_address() {
    let text = format!("{}@example.com", "x".repeat(65));
    assert_eq!(found(&text), vec![]);
}

#[test]
fn two_addresses_are_two_findings() {
    assert_eq!(
        found("a@x.es, b@y.es"),
        vec![(DataClass::Email, 0..6), (DataClass::Email, 8..14)]
    );
}

#[test]
fn an_id_inside_an_address_keeps_both_findings() {
    // Both values are personal data; policy combines their actions (ADR 0010).
    assert_eq!(
        found("12345678Z@example.com"),
        // Ordered by start, then end.
        vec![(DataClass::EsId, 0..9), (DataClass::Email, 0..21)]
    );
}

#[test]
fn a_full_width_at_sign_is_found_through_nfkc() {
    // U+FF20 is three bytes and normalizes to `@`.
    let text = "ana＠example.com";
    assert_eq!(found(text), email(0..text.len()));
}
