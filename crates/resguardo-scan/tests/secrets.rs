//! Secret rules of Annex F.2 as checked against provider documentation (ADR 0008), and the
//! entropy check. Every key here is fake; key-shaped values are split with `concat!` so that
//! secret scanners reading this file do not mistake them for real ones.
// Test helpers may panic: a scanning error is a test failure.
#![allow(clippy::unwrap_used)]

use std::ops::Range;

use resguardo_core::config::ScanConfig;
use resguardo_core::{DataClass, ScanReport, VirtualKey};
use resguardo_scan::Pipeline;

fn scan(text: &str) -> ScanReport {
    Pipeline::new(&ScanConfig::default())
        .unwrap()
        .scan_text("/p", text)
        .unwrap()
}

/// Rules and spans of the `secret` findings only.
fn secrets(text: &str) -> Vec<(String, Range<usize>)> {
    scan(text)
        .findings
        .into_iter()
        .filter(|f| f.class == DataClass::Secret)
        .map(|f| (f.rule, f.span))
        .collect()
}

fn assert_secret(text: &str, rule: &str, span: Range<usize>) {
    assert_eq!(secrets(text), vec![(rule.to_owned(), span)], "{text:?}");
}

fn assert_no_secret(text: &str) {
    assert_eq!(secrets(text), vec![], "{text:?}");
}

/// 36 characters, the length of classic GitHub tokens.
const BODY_36: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";

#[test]
fn aws_access_keys_long_term_and_temporary() {
    let key = concat!("AKIA", "IOSFODNN7EXAMPLE");
    assert_secret(&format!("id={key};"), "secret.aws_access_key", 3..23);
    assert_secret(
        concat!("ASIA", "IOSFODNN7EXAMPLE"),
        "secret.aws_access_key",
        0..20,
    );
    // Other IAM prefixes are identifiers, not keys.
    assert_no_secret(concat!("AIDA", "IOSFODNN7EXAMPLE"));
    // A key glued to more key characters is not a 20-character key.
    assert_no_secret(concat!("AKIA", "IOSFODNN7EXAMPLEX"));
    assert_no_secret(concat!("XAKIA", "IOSFODNN7EXAMPLE"));
    // ASCII word boundaries: a non-ASCII letter does not hide the key.
    assert_secret(
        &format!("é{}é", concat!("AKIA", "IOSFODNN7EXAMPLE")),
        "secret.aws_access_key",
        2..22,
    );
}

#[test]
fn github_tokens_of_every_documented_kind() {
    for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
        let token = format!("{prefix}{BODY_36}");
        assert_secret(&format!("t {token} t"), "secret.github_token", 2..42);
    }
    // Classic tokens have exactly 36 characters; ghs_ can be longer (stateless format).
    assert_no_secret(&format!("{}{BODY_36}x", concat!("gh", "p_")));
    assert_no_secret(&format!("{}{}", concat!("gh", "p_"), &BODY_36[1..]));
    // Stateless installation token: ghs_ + app id + JWT, with dots and underscores.
    let stateless = format!(
        "{}12345_eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJnaXRodWIifQ.c2lnbmF0dXJl",
        concat!("gh", "s_")
    );
    assert_secret(&stateless, "secret.github_token", 0..stateless.len());
    let fine_grained = format!("{}{}", concat!("github", "_pat_"), "A1b2_".repeat(13));
    assert_secret(&fine_grained, "secret.github_token", 0..fine_grained.len());
    assert_no_secret(&format!("{}{}", concat!("github", "_pat_"), "A".repeat(59)));
}

#[test]
fn anthropic_and_openai_keys_do_not_overlap() {
    let anthropic = format!("{}{}", concat!("sk-", "ant-api03-"), "aB3_-x".repeat(16));
    assert_secret(&anthropic, "secret.anthropic_key", 0..anthropic.len());
    for kind in ["", "proj-", "svcacct-", "admin-"] {
        let openai = format!("{}{kind}{}", concat!("s", "k-"), "T3BlbkFJ".repeat(6));
        assert_secret(&openai, "secret.openai_key", 0..openai.len());
    }
    // Too short, or part of a longer word.
    assert_no_secret(concat!("s", "k-", "abcdefghijklmnopqrs"));
    assert_no_secret(concat!("tas", "k-", "abcdefghijklmnopqrstuvwxyz"));
}

#[test]
fn slack_tokens_including_app_level_workflow_and_rotating() {
    for prefix in ["xoxb-", "xoxp-", "xoxa-", "xoxe-", "xapp-", "xwfp-"] {
        let token = format!("{}{prefix}1-2345678901-abcdef", "");
        assert_secret(&token, "secret.slack_token", 0..token.len());
    }
    let rotated = concat!("xoxe.", "xoxp-", "1-2345678901-abcdef");
    assert_secret(rotated, "secret.slack_token", 5..rotated.len());
    assert_no_secret(concat!("xox", "b-short"));
    assert_no_secret(concat!("xox", "z-1-2345678901-abcdef"));
}

#[test]
fn google_api_keys_including_one_that_ends_in_a_dash() {
    let key = concat!("AIza", "SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe");
    assert_secret(&format!("key: {key}"), "secret.google_api_key", 5..44);
    let dash = concat!("AIza", "SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQ-");
    assert_secret(&format!("{dash} next"), "secret.google_api_key", 0..39);
    // 36 characters after the prefix is not a Google key.
    assert_no_secret(&format!("{key}x"));
    assert_no_secret(&format!("{dash}-"));
}

#[test]
fn stripe_live_secret_and_restricted_keys_but_not_test_keys() {
    for prefix in [concat!("sk", "_live_"), concat!("rk", "_live_")] {
        let key = format!("{prefix}{}", "4eC39HqLyjWDarjtT1zdp7dc");
        assert_secret(&key, "secret.stripe_live", 0..key.len());
    }
    assert_no_secret(&format!(
        "{}{}",
        concat!("sk", "_test_"),
        "4eC39HqLyjWDarjtT1zdp7dc"
    ));
}

#[test]
fn private_keys_cover_the_whole_block() {
    let begin = concat!("-----BEGIN RSA ", "PRIVATE KEY-----");
    let end = concat!("-----END RSA ", "PRIVATE KEY-----");
    let block = format!("{begin}\nMIIEowIBAAKCAQEA\nq83lkf==\n{end}");
    let text = format!("here:\n{block}\nthanks");
    assert_secret(&text, "secret.private_key", 6..6 + block.len());

    // Without an END line, the rest of the text is covered.
    let truncated = format!(
        "{}\nMIIEowIBAAKCAQEA",
        concat!("-----BEGIN ", "PRIVATE KEY-----")
    );
    assert_secret(&truncated, "secret.private_key", 0..truncated.len());

    let pgp = format!(
        "{}\nxcLYBGd\n{}",
        concat!("-----BEGIN PGP ", "PRIVATE KEY BLOCK-----"),
        concat!("-----END PGP ", "PRIVATE KEY BLOCK-----")
    );
    assert_secret(&pgp, "secret.private_key", 0..pgp.len());
    assert_no_secret(concat!("-----BEGIN ", "PUBLIC KEY-----"));
}

#[test]
fn jwts_and_resguardo_virtual_keys() {
    let jwt = concat!(
        "eyJ",
        "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    );
    assert_secret(&format!("Bearer {jwt}"), "secret.jwt", 7..7 + jwt.len());

    let key = VirtualKey::from_random_bytes(&[7; 32]);
    let key = key.expose_secret();
    assert_secret(
        &format!("my key is {key}"),
        "secret.resguardo_key",
        10..10 + key.len(),
    );
}

#[test]
fn full_width_characters_do_not_hide_a_key() {
    // Full-width "AKIA": 4 characters of 3 bytes each.
    let text = concat!("ＡＫＩＡ", "IOSFODNN7EXAMPLE");
    assert_secret(text, "secret.aws_access_key", 0..28);
}

#[test]
fn entropy_needs_the_minimum_length_and_respects_the_threshold() {
    // Same characters as the G.1 candidate, cut to 19: below entropy_min_len (20).
    let short = &concat!("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY")[..19];
    assert_eq!(scan(short), ScanReport::default());

    // The threshold is configurable: raising it above 4.66 removes the candidate.
    let strict = ScanConfig {
        entropy_threshold: 4.7,
        ..ScanConfig::default()
    };
    let report = Pipeline::new(&strict)
        .unwrap()
        .scan_text(
            "/p",
            concat!("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"),
        )
        .unwrap();
    assert_eq!(report, ScanReport::default());

    // Words are made of [A-Za-z0-9+/=_-]: punctuation splits them.
    assert_eq!(scan("aB3dE5fG7h.J9kL1mN3pQ5rS7tU9"), ScanReport::default());
}

#[test]
fn a_candidate_next_to_an_invisible_character_is_kept() {
    // The candidate rule only defers to `secret` findings (ADR 0008).
    let text = concat!("wJalrXUtnFEMI/K7MDENG/", "\u{200B}", "bPxRfiCYEXAMPLEKEY");
    let classes: Vec<_> = scan(text).findings.into_iter().map(|f| f.class).collect();
    assert_eq!(
        classes,
        [DataClass::SecretCandidate, DataClass::InvisibleText]
    );
}

#[test]
fn findings_never_hold_the_matched_value() {
    let key = concat!("AKIA", "IOSFODNN7EXAMPLE");
    let report = scan(&format!(
        "aws {key} and {GITHUB}",
        GITHUB = concat!("gh", "p_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    ));
    assert_eq!(report.findings.len(), 2);
    let debug = format!("{report:?}");
    assert!(!debug.contains("IOSFODNN7"), "{debug}");
    assert!(!debug.contains("ABCDEFGHIJ"), "{debug}");
}

#[test]
fn arbitrary_text_never_fails_and_spans_stay_inside_it() {
    let pool = [
        "AKIA",
        "ghp_",
        "sk-",
        "ant-",
        "xoxb-",
        "AIza",
        "eyJ",
        ".",
        "-----BEGIN ",
        "PRIVATE KEY-----",
        "A",
        "z",
        "9",
        "_",
        "-",
        "=",
        "/",
        "+",
        "%4",
        "1",
        " ",
        "\n",
        "é",
        "Ａ",
        "\u{200B}",
        "\u{E0041}",
    ];
    let mut state: u64 = 99;
    let mut next = || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) as usize
    };
    let pipeline = Pipeline::new(&ScanConfig::default()).unwrap();
    for _ in 0..1000 {
        let len = next() % 60;
        let text: String = (0..len).map(|_| pool[next() % pool.len()]).collect();
        let report = pipeline.scan_text("/p", &text).unwrap();
        for finding in &report.findings {
            assert!(
                text.get(finding.span.clone()).is_some(),
                "{text:?} {finding:?}"
            );
            assert!(finding.span.start < finding.span.end);
        }
        for flag in &report.flags {
            assert!(text.get(flag.span.clone()).is_some(), "{text:?} {flag:?}");
        }
    }
}
