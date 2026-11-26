//! Golden cases of the design document: the secret rows of Annex G.1 and all of Annex G.2.
//! Expected values were computed outside the code (ADR 0008 records the interpretation of
//! G.2's last row). Key-shaped values are split with `concat!` so that secret scanners
//! reading this file do not mistake the fake keys for real ones.
// Test helpers may panic: a scanning error is a test failure.
#![allow(clippy::unwrap_used)]

use std::ops::Range;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use resguardo_core::config::ScanConfig;
use resguardo_core::{DataClass, ScanLimit, ScanReport};
use resguardo_scan::Pipeline;

/// "36 characters after `ghp_`" (G.1).
const GITHUB_TOKEN: &str = concat!("gh", "p_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");

fn scan(text: &str) -> ScanReport {
    Pipeline::new(&ScanConfig::default())
        .unwrap()
        .scan_text("/messages/0/content", text)
        .unwrap()
}

/// (class, rule, span, via) of every finding.
fn findings(report: &ScanReport) -> Vec<(DataClass, &str, Range<usize>, Vec<&str>)> {
    report
        .findings
        .iter()
        .map(|f| {
            let via = f.via.iter().map(String::as_str).collect();
            (f.class, f.rule.as_str(), f.span.clone(), via)
        })
        .collect()
}

// --- G.1, secret rows ------------------------------------------------------------------

#[test]
fn g1_aws_documentation_example_key_is_a_secret() {
    let report = scan(concat!("AKIA", "IOSFODNN7EXAMPLE"));
    assert_eq!(
        findings(&report),
        vec![(DataClass::Secret, "secret.aws_access_key", 0..20, vec![])]
    );
    assert_eq!(report.findings[0].confidence, 90);
}

#[test]
fn g1_github_token_with_36_characters_is_a_secret() {
    let report = scan(GITHUB_TOKEN);
    assert_eq!(
        findings(&report),
        vec![(DataClass::Secret, "secret.github_token", 0..40, vec![])]
    );
}

#[test]
fn g1_word_with_4_66_bits_per_character_is_a_secret_candidate() {
    let report = scan(concat!("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"));
    assert_eq!(
        findings(&report),
        vec![(
            DataClass::SecretCandidate,
            "secret_candidate.entropy",
            0..40,
            vec![]
        )]
    );
    assert_eq!(report.findings[0].confidence, 50);
}

#[test]
fn g1_password_below_the_entropy_threshold_is_not_a_finding() {
    assert_eq!(scan("SuperSecretPassword2026!!"), ScanReport::default());
}

// --- G.2 -----------------------------------------------------------------------------

#[test]
fn g2_base64_of_the_github_token_is_one_secret_over_the_whole_string() {
    // Base64 of GITHUB_TOKEN, computed outside the code.
    let encoded = "Z2hwX0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpag==";
    let report = scan(encoded);
    // No `secret_candidate`, although the encoded string has 4.93 bits per character.
    assert_eq!(
        findings(&report),
        vec![(
            DataClass::Secret,
            "secret.github_token",
            0..56,
            vec!["base64"]
        )]
    );
    assert!(report.flags.is_empty());
}

#[test]
fn g2_zero_width_space_inside_the_token_gives_invisible_text_and_secret() {
    let text = concat!("gh", "\u{200B}", "p_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
    let report = scan(text);
    assert_eq!(
        findings(&report),
        vec![
            (DataClass::Secret, "secret.github_token", 0..43, vec![]),
            (
                DataClass::InvisibleText,
                "invisible_text.zero_width",
                2..5,
                vec![]
            ),
        ]
    );
}

#[test]
fn g2_100_kb_of_base64_stops_at_max_derived_bytes_with_a_flag() {
    let plain = "The quick brown fox jumps over the lazy dog. ".repeat(1700);
    let encoded = STANDARD.encode(&plain);
    assert!(encoded.len() > 100_000);
    let report = scan(&encoded);
    assert_eq!(report.flags.len(), 1, "{:?}", report.flags);
    assert_eq!(report.flags[0].limit, ScanLimit::DerivedBytes);
    assert_eq!(report.flags[0].span, 0..encoded.len());
    assert_eq!(report.flags[0].via, ["base64"]);
}

#[test]
fn g2_double_base64_of_a_secret_is_detected_at_depth_2() {
    let encoded = "WjJod1gwRkNRMFJGUmtkSVNVcExURTFPVDFCUlVsTlVWVlpYV0ZsYVlXSmpaR1ZtWjJocGFnPT0=";
    let report = scan(encoded);
    assert_eq!(
        findings(&report),
        vec![(
            DataClass::Secret,
            "secret.github_token",
            0..76,
            vec!["base64", "base64"]
        )]
    );
    assert!(report.flags.is_empty());
}

#[test]
fn g2_triple_base64_of_a_secret_gives_only_a_flag_and_a_candidate() {
    let encoded = concat!(
        "V2pKb2QxZ3dSa05STUZKR1VtdGtTVk5WY0V4VVJURlBWREZDVWxWc1RsVldWbHBZ",
        "VjBac1lWbFhTbXBhUjFadFdqSm9jR0ZuUFQwPQ=="
    );
    assert_eq!(encoded.len(), 104);
    let report = scan(encoded);
    // The third layer is not decoded, so the token is never seen...
    assert_eq!(
        findings(&report),
        vec![(
            DataClass::SecretCandidate,
            "secret_candidate.entropy",
            0..104,
            vec![]
        )]
    );
    // ...but it does not leave silently.
    assert_eq!(report.flags.len(), 1, "{:?}", report.flags);
    assert_eq!(report.flags[0].limit, ScanLimit::DecodeDepth);
    assert_eq!(report.flags[0].span, 0..104);
    assert_eq!(report.flags[0].via, ["base64", "base64", "base64"]);
}
