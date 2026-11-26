//! Policy decisions (design document, "Política"; ADR 0012): the action per finding, the
//! combination and the result, including the pure-policy rows of Annex G.3.
// Test helpers may panic: an invalid fixture is a test failure.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use resguardo_core::{
    Action, BlockCode, Config, DataClass, Decision, Finding, Limits, Principal, PrincipalId,
    ScanFlag, ScanLimit, ScanReport, StreamMode,
};
use resguardo_policy::Policy;

/// The global actions of the example configuration (Annex E).
fn global_actions() -> BTreeMap<DataClass, Action> {
    BTreeMap::from([
        (DataClass::Secret, Action::Block),
        (DataClass::SecretCandidate, Action::Flag),
        (DataClass::EsId, Action::Redact),
        (DataClass::Iban, Action::Redact),
        (DataClass::Card, Action::Block),
        (DataClass::Phone, Action::Redact),
        (DataClass::Email, Action::Redact),
        (DataClass::InvisibleText, Action::Redact),
    ])
}

fn default_scan_limits() -> BTreeMap<ScanLimit, Action> {
    ScanLimit::ALL
        .into_iter()
        .map(|limit| (limit, limit.default_action()))
        .collect()
}

fn policy() -> Policy {
    Policy::new(global_actions(), default_scan_limits())
}

fn principal() -> Principal {
    Principal {
        id: PrincipalId::parse("bot").unwrap(),
        allowed: BTreeMap::new(),
        limits: Limits::default(),
        actions: BTreeMap::new(),
        scan_limits: BTreeMap::new(),
        stream_mode: StreamMode::default(),
        expires_at: None,
    }
}

fn finding(class: DataClass, start: usize, end: usize) -> Finding {
    Finding {
        class,
        pointer: "/messages/0/content".to_owned(),
        span: start..end,
        rule: format!("{}.test", class.as_str()),
        confidence: 90,
        via: Vec::new(),
    }
}

fn flag(limit: ScanLimit) -> ScanFlag {
    ScanFlag {
        limit,
        pointer: "/messages/0/content".to_owned(),
        span: 0..40,
        via: vec!["base64".to_owned(); 3],
    }
}

fn report(findings: Vec<Finding>, flags: Vec<ScanFlag>) -> ScanReport {
    ScanReport { findings, flags }
}

fn blocked(class: Option<DataClass>) -> Decision {
    Decision::Block {
        code: BlockCode::SensitiveData,
        class,
    }
}

// --- Annex G.3, pure-policy rows ---------------------------------------------------------

#[test]
fn g3_a_dni_is_redacted() {
    // "Mi DNI es 12345678Z"
    let dni = finding(DataClass::EsId, 10, 19);
    let decision = policy().decide(&principal(), &report(vec![dni.clone()], vec![]));
    assert_eq!(
        decision,
        Decision::Redact {
            spans: vec![dni],
            flags: vec![]
        }
    );
}

#[test]
fn g3_two_different_dnis_give_two_spans() {
    let first = finding(DataClass::EsId, 10, 19);
    let second = finding(DataClass::EsId, 24, 33);
    let decision = policy().decide(
        &principal(),
        &report(vec![first.clone(), second.clone()], vec![]),
    );
    assert_eq!(
        decision,
        Decision::Redact {
            spans: vec![first, second],
            flags: vec![]
        }
    );
}

#[test]
fn g3_an_aws_key_blocks_with_class_secret() {
    let key = finding(DataClass::Secret, 0, 20);
    let decision = policy().decide(&principal(), &report(vec![key], vec![]));
    assert_eq!(decision, blocked(Some(DataClass::Secret)));
}

#[test]
fn g3_a_request_without_findings_is_allowed() {
    let decision = policy().decide(&principal(), &ScanReport::default());
    assert_eq!(decision, Decision::Allow { flags: vec![] });
}

// --- Combination -------------------------------------------------------------------------

#[test]
fn flagged_findings_travel_with_an_allow() {
    let candidate = finding(DataClass::SecretCandidate, 0, 40);
    let decision = policy().decide(&principal(), &report(vec![candidate.clone()], vec![]));
    assert_eq!(
        decision,
        Decision::Allow {
            flags: vec![candidate]
        }
    );
}

#[test]
fn redact_wins_over_flag_and_keeps_the_flags_apart() {
    let candidate = finding(DataClass::SecretCandidate, 0, 40);
    let dni = finding(DataClass::EsId, 50, 59);
    let decision = policy().decide(
        &principal(),
        &report(vec![candidate.clone(), dni.clone()], vec![]),
    );
    assert_eq!(
        decision,
        Decision::Redact {
            spans: vec![dni],
            flags: vec![candidate]
        }
    );
}

#[test]
fn block_wins_over_everything() {
    let findings = vec![
        finding(DataClass::SecretCandidate, 0, 40),
        finding(DataClass::EsId, 50, 59),
        finding(DataClass::Card, 60, 79),
    ];
    let decision = policy().decide(&principal(), &report(findings, vec![]));
    assert_eq!(decision, blocked(Some(DataClass::Card)));
}

#[test]
fn the_blocking_class_follows_data_class_order_not_position() {
    // The card comes first in the text, but `secret` is reported (ADR 0012).
    let findings = vec![
        finding(DataClass::Card, 0, 19),
        finding(DataClass::Secret, 30, 50),
    ];
    let decision = policy().decide(&principal(), &report(findings, vec![]));
    assert_eq!(decision, blocked(Some(DataClass::Secret)));
}

// --- Per-principal actions ---------------------------------------------------------------

#[test]
fn a_principal_action_overrides_the_global_one() {
    let mut principal = principal();
    principal.actions.insert(DataClass::Email, Action::Allow);
    principal.actions.insert(DataClass::Phone, Action::Block);

    let email = finding(DataClass::Email, 0, 15);
    let decision = policy().decide(&principal, &report(vec![email], vec![]));
    assert_eq!(decision, Decision::Allow { flags: vec![] });

    let phone = finding(DataClass::Phone, 0, 9);
    let decision = policy().decide(&principal, &report(vec![phone], vec![]));
    assert_eq!(decision, blocked(Some(DataClass::Phone)));
}

#[test]
fn the_example_configuration_lets_support_bot_send_email_addresses() {
    let source = include_str!("../../../config/resguardo.example.toml");
    let config = Config::from_toml_str(source).unwrap();
    let support = &config.principals[0].principal;
    let email = finding(DataClass::Email, 0, 15);
    let decision = Policy::from_config(&config).decide(support, &report(vec![email], vec![]));
    assert_eq!(decision, Decision::Allow { flags: vec![] });
}

// --- Limit flags (ADR 0012) --------------------------------------------------------------

#[test]
fn decode_depth_blocks_by_default_without_a_class() {
    let decision = policy().decide(
        &principal(),
        &report(vec![], vec![flag(ScanLimit::DecodeDepth)]),
    );
    assert_eq!(decision, blocked(None));
}

#[test]
fn derived_bytes_is_only_recorded_by_default() {
    let decision = policy().decide(
        &principal(),
        &report(vec![], vec![flag(ScanLimit::DerivedBytes)]),
    );
    assert_eq!(decision, Decision::Allow { flags: vec![] });
}

#[test]
fn a_principal_can_block_on_derived_bytes() {
    let mut principal = principal();
    principal
        .scan_limits
        .insert(ScanLimit::DerivedBytes, Action::Block);
    let decision = policy().decide(
        &principal,
        &report(vec![], vec![flag(ScanLimit::DerivedBytes)]),
    );
    assert_eq!(decision, blocked(None));
}

#[test]
fn a_blocking_class_is_reported_even_when_a_limit_also_blocks() {
    let decision = policy().decide(
        &principal(),
        &report(
            vec![finding(DataClass::Secret, 0, 20)],
            vec![flag(ScanLimit::DecodeDepth)],
        ),
    );
    assert_eq!(decision, blocked(Some(DataClass::Secret)));
}

#[test]
fn a_limit_that_blocks_wins_over_a_redaction() {
    let decision = policy().decide(
        &principal(),
        &report(
            vec![finding(DataClass::EsId, 0, 9)],
            vec![flag(ScanLimit::DecodeDepth)],
        ),
    );
    assert_eq!(decision, blocked(None));
}

// --- Closed by default (ADR 0002, ADR 0012) ----------------------------------------------

#[test]
fn a_class_without_an_action_blocks() {
    let policy = Policy::new(BTreeMap::new(), default_scan_limits());
    let decision = policy.decide(
        &principal(),
        &report(vec![finding(DataClass::EsId, 0, 9)], vec![]),
    );
    assert_eq!(decision, blocked(Some(DataClass::EsId)));
}

#[test]
fn a_response_class_in_a_request_report_blocks() {
    // `url` has no request action: the configuration rejects one, so it can only block.
    let decision = policy().decide(
        &principal(),
        &report(vec![finding(DataClass::Url, 0, 30)], vec![]),
    );
    assert_eq!(decision, blocked(Some(DataClass::Url)));
}

#[test]
fn a_limit_without_an_action_blocks() {
    let policy = Policy::new(global_actions(), BTreeMap::new());
    let decision = policy.decide(
        &principal(),
        &report(vec![], vec![flag(ScanLimit::DerivedBytes)]),
    );
    assert_eq!(decision, blocked(None));
}

#[test]
fn a_limit_action_other_than_flag_or_block_blocks() {
    // The configuration rejects these; policy still does not let them through.
    for action in [Action::Allow, Action::Redact] {
        let policy = Policy::new(
            global_actions(),
            BTreeMap::from([(ScanLimit::DerivedBytes, action)]),
        );
        let decision = policy.decide(
            &principal(),
            &report(vec![], vec![flag(ScanLimit::DerivedBytes)]),
        );
        assert_eq!(decision, blocked(None), "{action:?}");
    }
}
