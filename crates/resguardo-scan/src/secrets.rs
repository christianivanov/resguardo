//! Secrets with a known format (Annex F.2), with the patterns checked against each provider's
//! documentation (ADR 0008).

use regex::{Regex, RegexSet};
use resguardo_core::DataClass;

use crate::pipeline::ScanError;
use crate::scanner::{Detection, Scanner};

/// Confidence of a known secret format (ADR 0008).
const CONFIDENCE: u8 = 90;

/// A check the `regex` crate cannot express, because it has no look-around.
#[derive(Debug, Clone, Copy)]
enum Check {
    None,
    /// Skip matches that start with this prefix (another rule owns them).
    NotPrefixed(&'static str),
    /// Skip matches followed by one more key character (`[A-Za-z0-9_-]`).
    NotFollowedByKeyChar,
}

struct Rule {
    name: &'static str,
    pattern: &'static str,
    check: Check,
}

/// `(?-u:\b)` is an ASCII word boundary: a non-ASCII letter next to a key does not hide it.
const RULES: &[Rule] = &[
    Rule {
        name: "secret.aws_access_key",
        pattern: r"(?-u:\b)(?:AKIA|ASIA)[0-9A-Z]{16}(?-u:\b)",
        check: Check::None,
    },
    Rule {
        name: "secret.github_token",
        pattern: r"(?-u:\b)gh[pour]_[A-Za-z0-9]{36}(?-u:\b)",
        check: Check::None,
    },
    // Installation tokens: the classic 36 characters or the stateless `ghs_APPID_JWT` format.
    Rule {
        name: "secret.github_token",
        pattern: r"(?-u:\b)ghs_[A-Za-z0-9._-]{36,}",
        check: Check::None,
    },
    Rule {
        name: "secret.github_token",
        pattern: r"(?-u:\b)github_pat_[A-Za-z0-9_]{60,}",
        check: Check::None,
    },
    Rule {
        name: "secret.anthropic_key",
        pattern: r"(?-u:\b)sk-ant-[A-Za-z0-9_-]{20,}",
        check: Check::None,
    },
    Rule {
        name: "secret.openai_key",
        pattern: r"(?-u:\b)sk-[A-Za-z0-9_-]{20,}",
        check: Check::NotPrefixed("sk-ant-"),
    },
    Rule {
        name: "secret.slack_token",
        pattern: r"(?-u:\b)(?:xox[abeposr]|xapp|xwfp)-[A-Za-z0-9-]{10,}",
        check: Check::None,
    },
    Rule {
        name: "secret.google_api_key",
        pattern: r"(?-u:\b)AIza[0-9A-Za-z_-]{35}",
        check: Check::NotFollowedByKeyChar,
    },
    Rule {
        name: "secret.stripe_live",
        pattern: r"(?-u:\b)(?:sk|rk)_live_[0-9A-Za-z]{20,}(?-u:\b)",
        check: Check::None,
    },
    // The whole block, so redacting it removes the key material, not only the header.
    Rule {
        name: "secret.private_key",
        pattern: r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\z)",
        check: Check::None,
    },
    Rule {
        name: "secret.jwt",
        pattern: r"(?-u:\b)eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        check: Check::None,
    },
    // An application must not leak its own virtual key.
    Rule {
        name: "secret.resguardo_key",
        pattern: r"(?-u:\b)rsg_[A-Za-z0-9]{40,}",
        check: Check::None,
    },
];

/// All patterns in one `RegexSet`, so the text is read once to learn which rules match
/// (Annex F.2); only those rules then look for positions.
#[derive(Debug)]
pub(crate) struct SecretScanner {
    set: RegexSet,
    regexes: Vec<Regex>,
}

impl SecretScanner {
    pub(crate) fn new() -> Result<Self, ScanError> {
        let set = RegexSet::new(RULES.iter().map(|rule| rule.pattern))
            .map_err(|e| ScanError::Pattern(e.to_string()))?;
        let regexes = RULES
            .iter()
            .map(|rule| Regex::new(rule.pattern).map_err(|e| ScanError::Pattern(e.to_string())))
            .collect::<Result<_, _>>()?;
        Ok(Self { set, regexes })
    }
}

impl Scanner for SecretScanner {
    fn scan(&self, text: &str, out: &mut Vec<Detection>) -> Result<(), ScanError> {
        for index in self.set.matches(text).iter() {
            let (Some(rule), Some(regex)) = (RULES.get(index), self.regexes.get(index)) else {
                return Err(ScanError::Internal("secret rule index out of range"));
            };
            for found in regex.find_iter(text) {
                let accepted = match rule.check {
                    Check::None => true,
                    Check::NotPrefixed(prefix) => !found.as_str().starts_with(prefix),
                    Check::NotFollowedByKeyChar => !text
                        .as_bytes()
                        .get(found.end())
                        .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                };
                if accepted {
                    out.push(Detection {
                        class: DataClass::Secret,
                        span: found.range(),
                        rule: rule.name,
                        confidence: CONFIDENCE,
                    });
                }
            }
        }
        Ok(())
    }
}
