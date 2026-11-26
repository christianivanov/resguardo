//! Cards and Spanish phones (Annex F.5) with the candidate rules of ADR 0010, and the
//! overlap rule between number classes.
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

fn card(span: Range<usize>) -> Vec<(DataClass, Range<usize>)> {
    vec![(DataClass::Card, span)]
}

fn phone(span: Range<usize>) -> Vec<(DataClass, Range<usize>)> {
    vec![(DataClass::Phone, span)]
}

// --- Cards -------------------------------------------------------------------------------

#[test]
fn cards_accept_spaces_and_hyphens_but_not_dots() {
    assert_eq!(found("4111-1111-1111-1111"), card(0..19));
    assert_eq!(found("4111111111111111"), card(0..16));
    assert_eq!(found("4111.1111.1111.1111"), vec![]);
}

#[test]
fn cards_of_13_and_15_digits_are_found() {
    // Visa test number of 13 digits, and an American Express test number in 4-6-5 groups.
    assert_eq!(found("4222222222222"), card(0..13));
    assert_eq!(found("3782 822463 10005"), card(0..17));
}

#[test]
fn a_card_followed_by_its_security_code_is_found() {
    // All 19 digits fail Luhn; the first 16 pass.
    assert_eq!(found("4111 1111 1111 1111 123"), card(0..19));
}

#[test]
fn a_card_glued_to_more_digits_is_not_reported() {
    assert_eq!(found("41111111111111111111"), vec![]);
    assert_eq!(found("x4111111111111111"), vec![]);
}

// --- Phones ------------------------------------------------------------------------------

#[test]
fn phones_in_their_usual_forms_are_found() {
    assert_eq!(found("612345678"), phone(0..9));
    assert_eq!(found("612 34 56 78"), phone(0..12));
    assert_eq!(found("612-345-678"), phone(0..11));
    assert_eq!(found("712345678"), phone(0..9));
    // A Madrid landline.
    assert_eq!(found("91 123 45 67"), phone(0..12));
}

#[test]
fn prefixes_are_part_of_the_span() {
    assert_eq!(found("+34612345678"), phone(0..12));
    assert_eq!(found("0034 612 345 678"), phone(0..16));
    assert_eq!(found("llama al +34 612 345 678."), phone(9..24));
}

#[test]
fn thirty_four_without_a_plus_is_not_a_prefix() {
    assert_eq!(found("34 612 345 678"), phone(3..14));
}

#[test]
fn dots_are_not_phone_separators() {
    // In Spain the dot is the thousands separator: this is an amount.
    assert_eq!(found("612.345.678 €"), vec![]);
}

#[test]
fn numbers_that_are_not_spanish_phones_are_not_reported() {
    for text in ["512345678", "61234567", "6123456789", "+33612345678"] {
        assert_eq!(found(text), vec![], "{text}");
    }
}

#[test]
fn a_foreign_number_whose_groups_look_spanish_is_reported_without_its_prefix() {
    // The groups after `+33` are a valid Spanish mobile on their own (whole groups, ADR
    // 0010). Reporting them is the safe outcome: the value is a phone either way.
    assert_eq!(found("+33 612 345 678"), phone(4..15));
}

// --- Overlaps between number classes (ADR 0010) -----------------------------------------

#[test]
fn a_phone_inside_a_card_is_dropped_for_the_card() {
    // The first three groups are a phone; all five are a card that passes Luhn.
    assert_eq!(found("612 345 678 1234 5674"), card(0..21));
    // With a wrong last digit there is no card, and the phone is reported.
    assert_eq!(found("612 345 678 1234 5675"), phone(0..11));
}

#[test]
fn values_of_number_classes_that_do_not_overlap_are_all_kept() {
    assert_eq!(
        found("4111 1111 1111 1111 / 612 345 678 / 12345678Z"),
        vec![
            (DataClass::Card, 0..19),
            (DataClass::Phone, 22..33),
            (DataClass::EsId, 36..45),
        ]
    );
}
