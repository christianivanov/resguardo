//! Spanish ids (Annex F.4) with the candidate rules of ADR 0010: whole groups of letters and
//! digits, per-class separators and case.
// Test helpers may panic: a scanning error is a test failure.
#![allow(clippy::unwrap_used)]

use std::ops::Range;

use resguardo_core::DataClass;
use resguardo_core::config::ScanConfig;
use resguardo_scan::Pipeline;

/// (rule, span) of every `es_id` finding.
fn es_ids(text: &str) -> Vec<(String, Range<usize>)> {
    Pipeline::new(&ScanConfig::default())
        .unwrap()
        .scan_text("/messages/0/content", text)
        .unwrap()
        .findings
        .into_iter()
        .filter(|f| f.class == DataClass::EsId)
        .map(|f| (f.rule, f.span))
        .collect()
}

fn dni(span: Range<usize>) -> Vec<(String, Range<usize>)> {
    vec![("es_id.dni".to_owned(), span)]
}

#[test]
fn an_id_inside_a_sentence_is_found_without_its_punctuation() {
    assert_eq!(es_ids("Mi DNI es 12345678Z."), dni(10..19));
    assert_eq!(es_ids("(DNI: 12345678Z)"), dni(6..15));
}

#[test]
fn separators_space_hyphen_and_dot_are_accepted() {
    assert_eq!(es_ids("12.345.678-Z"), dni(0..12));
    assert_eq!(es_ids("12345678 Z"), dni(0..10));
    assert_eq!(es_ids("1234 5678 Z"), dni(0..11));
    assert_eq!(es_ids("X-1234567-L"), vec![("es_id.nie".to_owned(), 0..11)]);
    assert_eq!(es_ids("B-12345674"), vec![("es_id.cif".to_owned(), 0..10)]);
}

#[test]
fn lower_case_letters_are_accepted() {
    assert_eq!(es_ids("12345678z"), dni(0..9));
    assert_eq!(es_ids("x1234567l"), vec![("es_id.nie".to_owned(), 0..9)]);
}

#[test]
fn an_id_glued_to_letters_or_digits_is_not_reported() {
    for text in ["9912345678Z", "DNI12345678Z", "12345678ZA", "12345678Z9"] {
        assert_eq!(es_ids(text), vec![], "{text}");
    }
}

#[test]
fn two_separators_in_a_row_end_the_candidate() {
    assert_eq!(es_ids("12345678--Z"), vec![]);
    assert_eq!(es_ids("12345678  Z"), vec![]);
}

#[test]
fn other_separators_are_not_accepted() {
    assert_eq!(es_ids("12345678/Z"), vec![]);
    assert_eq!(es_ids("12345678_Z"), vec![]);
}

#[test]
fn spaced_single_digits_are_found() {
    assert_eq!(es_ids("1 2 3 4 5 6 7 8 Z"), dni(0..17));
}

#[test]
fn full_width_characters_are_found_through_nfkc() {
    // Nine full-width characters of three bytes each.
    let text = "１２３４５６７８Ｚ";
    assert_eq!(text.len(), 27);
    assert_eq!(es_ids(text), dni(0..27));
}

#[test]
fn the_longest_window_does_not_hide_a_neighbour() {
    // Two ids in one chunk of groups.
    assert_eq!(
        es_ids("12345678Z 87654321X"),
        vec![
            ("es_id.dni".to_owned(), 0..9),
            ("es_id.dni".to_owned(), 10..19)
        ]
    );
    // A leading group that is not part of the id.
    assert_eq!(es_ids("1 12345678Z"), dni(2..11));
}

#[test]
fn an_id_hidden_in_base64_is_found_over_the_encoded_fragment() {
    // Base64 of "Mi DNI es 12345678Z", computed outside the code. F.1 decodes fragments of
    // 24 characters or more, so a bare id in Base64 (16 characters) is not decoded.
    let encoded = "TWkgRE5JIGVzIDEyMzQ1Njc4Wg==";
    let report = Pipeline::new(&ScanConfig::default())
        .unwrap()
        .scan_text("", encoded)
        .unwrap();
    let found: Vec<_> = report
        .findings
        .iter()
        .map(|f| (f.class, f.span.clone(), f.via.clone()))
        .collect();
    assert_eq!(
        found,
        vec![(DataClass::EsId, 0..28, vec!["base64".to_owned()])]
    );
}
