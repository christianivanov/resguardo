//! The scanning pipeline of Annex F.1: normalize, report invisible text, run the detectors,
//! then decode candidates and scan what they hide, within the configured limits.

use std::ops::Range;

use resguardo_core::config::ScanConfig;
use resguardo_core::{DataClass, Finding, ScanFlag, ScanLimit, ScanReport, ScanText};

use crate::aggregate::{
    RawFinding, drop_candidates_overlapping_secrets, keep_most_confident_numbers, merge_overlapping,
};
use crate::card::CardScanner;
use crate::decode::{Layer, decode, find_candidates};
use crate::entropy::EntropyScanner;
use crate::es_id::EsIdScanner;
use crate::normalize::normalize;
use crate::phone::PhoneScanner;
use crate::scanner::Scanner;
use crate::secrets::SecretScanner;

/// Confidence of an invisible-character finding: their presence is certain (ADR 0008).
const INVISIBLE_CONFIDENCE: u8 = 100;

/// Why scanning could not finish. Callers block the request (`SCAN_ERROR`, ADR 0002).
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// The scan settings are not acceptable. Messages name settings, never content.
    #[error("invalid scan settings: {}", .0.join("; "))]
    Config(Vec<String>),
    /// A built-in detector pattern did not compile. The message holds the pattern, never
    /// scanned content.
    #[error("detector pattern: {0}")]
    Pattern(String),
    /// An internal invariant did not hold. Scanning stops instead of guessing.
    #[error("internal scanning error: {0}")]
    Internal(&'static str),
}

/// Scans request texts. Build it once and share it: it holds no per-request state.
///
/// `Pipeline` is `Send + Sync`, so one instance can serve concurrent requests behind an
/// `Arc`, like an immutable, thread-safe service object in Java.
#[derive(Debug)]
pub struct Pipeline {
    max_decode_depth: u8,
    max_derived_bytes: usize,
    /// Run on every text, original or decoded. `Box<dyn Scanner>` is a heap-allocated value
    /// behind an interface, like a `List<Scanner>` in Java.
    scanners: Vec<Box<dyn Scanner>>,
}

/// Where findings of a decoded text are reported: the outermost encoded fragment in the
/// original text, and the layers crossed to reach it.
struct Outer {
    span: Range<usize>,
    via: Vec<Layer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawFlag {
    limit: ScanLimit,
    span: Range<usize>,
    via: Vec<Layer>,
}

#[derive(Default)]
struct Collected {
    findings: Vec<RawFinding>,
    flags: Vec<RawFlag>,
}

impl Pipeline {
    /// Refuses settings that [`ScanConfig::problems`] rejects, even if they did not come from
    /// a validated configuration.
    pub fn new(config: &ScanConfig) -> Result<Self, ScanError> {
        let problems = config.problems();
        if !problems.is_empty() {
            return Err(ScanError::Config(problems));
        }
        Ok(Self {
            max_decode_depth: config.max_decode_depth,
            max_derived_bytes: config.max_derived_bytes,
            scanners: vec![
                Box::new(SecretScanner::new()?),
                Box::new(EsIdScanner),
                Box::new(CardScanner),
                Box::new(PhoneScanner),
                Box::new(EntropyScanner {
                    threshold: config.entropy_threshold,
                    min_len: config.entropy_min_len,
                }),
            ],
        })
    }

    /// Scans every text of a request. Findings and flags keep the order of `texts`, then of
    /// position within each text.
    pub fn scan(&self, texts: &[ScanText]) -> Result<ScanReport, ScanError> {
        let mut report = ScanReport::default();
        for text in texts {
            let one = self.scan_text(&text.pointer, &text.text)?;
            report.findings.extend(one.findings);
            report.flags.extend(one.flags);
        }
        Ok(report)
    }

    /// Scans one text. `pointer` is copied into every finding and flag.
    pub fn scan_text(&self, pointer: &str, text: &str) -> Result<ScanReport, ScanError> {
        let mut collected = Collected::default();
        self.scan_layer(text, 0, None, &mut collected)?;

        let mut raw = collected.findings;
        drop_candidates_overlapping_secrets(&mut raw);
        let findings = merge_overlapping(raw)
            .into_iter()
            .map(|f| Finding {
                class: f.class,
                pointer: pointer.to_owned(),
                span: f.span,
                rule: f.rule.to_owned(),
                confidence: f.confidence,
                via: layer_names(&f.via),
            })
            .collect();

        let mut flags = collected.flags;
        flags.sort_by(|a, b| {
            (a.span.start, a.span.end, a.limit, &a.via).cmp(&(
                b.span.start,
                b.span.end,
                b.limit,
                &b.via,
            ))
        });
        flags.dedup();
        let flags = flags
            .into_iter()
            .map(|f| ScanFlag {
                limit: f.limit,
                pointer: pointer.to_owned(),
                span: f.span,
                via: layer_names(&f.via),
            })
            .collect();

        Ok(ScanReport { findings, flags })
    }

    /// Scans `text` at `depth` (0 for the original). For decoded texts, `outer` says where
    /// their findings are reported. Recursion is bounded by `max_decode_depth` (at most 8).
    fn scan_layer(
        &self,
        text: &str,
        depth: u8,
        outer: Option<&Outer>,
        collected: &mut Collected,
    ) -> Result<(), ScanError> {
        let normalized = normalize(text);
        let via: Vec<Layer> = outer.map(|o| o.via.clone()).unwrap_or_default();
        // A span of the normalized text, as reported: in the original text for depth 0, the
        // whole outer fragment otherwise.
        let report_span = |span: Range<usize>| -> Result<Range<usize>, ScanError> {
            match outer {
                Some(outer) => Ok(outer.span.clone()),
                None => normalized.map.to_original(span).ok_or(ScanError::Internal(
                    "a span did not map to the original text",
                )),
            }
        };

        for run in &normalized.invisible {
            collected.findings.push(RawFinding {
                class: DataClass::InvisibleText,
                span: outer.map_or_else(|| run.span.clone(), |o| o.span.clone()),
                rule: run.kind.rule(),
                confidence: INVISIBLE_CONFIDENCE,
                via: via.clone(),
            });
        }

        let mut detections = Vec::new();
        for scanner in &self.scanners {
            scanner.scan(&normalized.text, &mut detections)?;
        }
        // Within this layer, before spans are mapped: two values decoded from one fragment
        // share its outer span, and must not be taken for overlapping (ADR 0010).
        keep_most_confident_numbers(&mut detections);
        for detection in detections {
            collected.findings.push(RawFinding {
                class: detection.class,
                span: report_span(detection.span)?,
                rule: detection.rule,
                confidence: detection.confidence,
                via: via.clone(),
            });
        }

        for candidate in find_candidates(&normalized.text) {
            let fragment =
                normalized
                    .text
                    .get(candidate.span.clone())
                    .ok_or(ScanError::Internal(
                        "a candidate is not a range of its text",
                    ))?;
            let Some(decoded) = decode(candidate.layer, fragment, self.max_derived_bytes) else {
                continue;
            };
            let span = report_span(candidate.span)?;
            let mut via = via.clone();
            via.push(candidate.layer);
            if depth >= self.max_decode_depth {
                collected.flags.push(RawFlag {
                    limit: ScanLimit::DecodeDepth,
                    span,
                    via,
                });
                continue;
            }
            if decoded.truncated {
                collected.flags.push(RawFlag {
                    limit: ScanLimit::DerivedBytes,
                    span: span.clone(),
                    via: via.clone(),
                });
            }
            let next = Outer { span, via };
            self.scan_layer(&decoded.text, depth + 1, Some(&next), collected)?;
        }
        Ok(())
    }
}

fn layer_names(via: &[Layer]) -> Vec<String> {
    via.iter().map(|layer| layer.as_str().to_owned()).collect()
}
