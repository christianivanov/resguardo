//! Aggregation (design document, "Motor de detección", step 4; ADR 0008): overlapping
//! findings of one class become one, and the most confident one gives it its rule.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Range;

use resguardo_core::DataClass;

use crate::decode::Layer;
use crate::scanner::Detection;

/// Classes whose overlaps are coincidences of digits inside a longer value (ADR 0010).
const NUMBER_CLASSES: [DataClass; 4] = [
    DataClass::Iban,
    DataClass::EsId,
    DataClass::Card,
    DataClass::Phone,
];

/// Among overlapping detections of `iban`, `es_id`, `card` and `phone` in one text, keeps
/// only the most confident: a phone inside a card, or a card inside an IBAN, is a
/// coincidence of digits (ADR 0010). Other classes are left alone.
pub(crate) fn keep_most_confident_numbers(detections: &mut Vec<Detection>) {
    let mut order: Vec<usize> = (0..detections.len())
        .filter(|&i| {
            detections
                .get(i)
                .is_some_and(|d| NUMBER_CLASSES.contains(&d.class))
        })
        .collect();
    if order.len() < 2 {
        return;
    }
    // Most confident first; then by position and rule, so the result is deterministic.
    order.sort_by_key(|&i| {
        detections.get(i).map(|d| {
            (
                std::cmp::Reverse(d.confidence),
                d.span.start,
                d.span.end,
                d.rule,
            )
        })
    });
    // Kept spans, disjoint, by start. The one with the largest start before a span's end is
    // the only one that can overlap it.
    let mut kept: BTreeMap<usize, usize> = BTreeMap::new();
    let mut keep = vec![true; detections.len()];
    for i in order {
        let Some(span) = detections.get(i).map(|d| d.span.clone()) else {
            continue;
        };
        let overlaps = kept
            .range(..span.end)
            .next_back()
            .is_some_and(|(_, &end)| end > span.start);
        if overlaps {
            if let Some(flag) = keep.get_mut(i) {
                *flag = false;
            }
        } else {
            kept.insert(span.start, span.end);
        }
    }
    let mut index = 0;
    detections.retain(|_| {
        let retained = keep.get(index).copied().unwrap_or(true);
        index += 1;
        retained
    });
}

/// A finding before it is tied to a [`resguardo_core::ScanText`]. The span is already in the
/// original text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawFinding {
    pub class: DataClass,
    pub span: Range<usize>,
    pub rule: &'static str,
    pub confidence: u8,
    pub via: Vec<Layer>,
}

/// Drops every `secret_candidate` that overlaps a `secret`: the specific finding already says
/// what the value is (ADR 0008). Only `secret` counts. If every class did, an invisible
/// character inside a high-entropy word would remove the candidate, and with
/// `invisible_text = "redact"` the word would leave without a flag.
pub(crate) fn drop_candidates_overlapping_secrets(findings: &mut Vec<RawFinding>) {
    let mut secrets: Vec<Range<usize>> = findings
        .iter()
        .filter(|f| f.class == DataClass::Secret)
        .map(|f| f.span.clone())
        .collect();
    if secrets.is_empty() {
        return;
    }
    // Disjoint, sorted intervals: each candidate then needs one binary search, so a text with
    // many findings costs O(n log n), not O(n^2).
    secrets.sort_by_key(|s| (s.start, s.end));
    let mut covered: Vec<Range<usize>> = Vec::with_capacity(secrets.len());
    for span in secrets {
        if let Some(last) = covered.last_mut()
            && span.start <= last.end
        {
            last.end = last.end.max(span.end);
        } else {
            covered.push(span);
        }
    }
    findings.retain(|f| f.class != DataClass::SecretCandidate || !overlaps_any(&covered, &f.span));
}

/// Whether `span` overlaps one of the disjoint, sorted `covered` intervals.
fn overlaps_any(covered: &[Range<usize>], span: &Range<usize>) -> bool {
    let first_ending_after = covered.partition_point(|c| c.end <= span.start);
    covered
        .get(first_ending_after)
        .is_some_and(|c| c.start < span.end)
}

/// Merges overlapping findings of the same class into one whose span is the union of theirs,
/// so redaction covers everything any detector saw. Returns them ordered by position.
pub(crate) fn merge_overlapping(mut findings: Vec<RawFinding>) -> Vec<RawFinding> {
    findings.sort_by(|a, b| {
        (a.class, a.span.start, a.span.end).cmp(&(b.class, b.span.start, b.span.end))
    });
    let mut merged: Vec<RawFinding> = Vec::with_capacity(findings.len());
    for finding in findings {
        if let Some(current) = merged.last_mut()
            && current.class == finding.class
            && finding.span.start < current.span.end
        {
            let end = current.span.end.max(finding.span.end);
            if outranks(&finding, current) {
                let start = current.span.start;
                *current = finding;
                current.span.start = start;
            }
            current.span.end = end;
            continue;
        }
        merged.push(finding);
    }
    merged.sort_by(|a, b| {
        (a.span.start, a.span.end, a.class, a.rule).cmp(&(
            b.span.start,
            b.span.end,
            b.class,
            b.rule,
        ))
    });
    merged
}

/// Higher confidence wins; then fewer decoding layers; then the rule that sorts first.
fn outranks(a: &RawFinding, b: &RawFinding) -> bool {
    let order = b
        .confidence
        .cmp(&a.confidence)
        .then(a.via.len().cmp(&b.via.len()))
        .then(a.rule.cmp(b.rule));
    order == Ordering::Less
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detection(class: DataClass, span: Range<usize>, confidence: u8) -> Detection {
        Detection {
            class,
            span,
            rule: "test.rule",
            confidence,
        }
    }

    #[test]
    fn the_most_confident_number_wins_and_its_neighbours_stay() {
        let mut detections = vec![
            detection(DataClass::Phone, 0..11, 60),
            detection(DataClass::Card, 0..21, 85),
            detection(DataClass::Iban, 30..59, 95),
            detection(DataClass::Card, 35..54, 85),
            detection(DataClass::Phone, 60..69, 60),
        ];
        keep_most_confident_numbers(&mut detections);
        let kept: Vec<_> = detections
            .iter()
            .map(|d| (d.class, d.span.clone()))
            .collect();
        assert_eq!(
            kept,
            vec![
                (DataClass::Card, 0..21),
                (DataClass::Iban, 30..59),
                (DataClass::Phone, 60..69),
            ]
        );
    }

    #[test]
    fn other_classes_are_never_dropped_by_numbers() {
        let mut detections = vec![
            detection(DataClass::Email, 0..21, 80),
            detection(DataClass::EsId, 0..9, 90),
            detection(DataClass::Secret, 5..30, 90),
        ];
        keep_most_confident_numbers(&mut detections);
        assert_eq!(detections.len(), 3);
    }

    #[test]
    fn a_chain_of_overlaps_keeps_the_strongest_and_what_it_does_not_touch() {
        // The card overlaps both phones; the phones do not overlap each other.
        let mut detections = vec![
            detection(DataClass::Phone, 0..9, 60),
            detection(DataClass::Card, 5..25, 85),
            detection(DataClass::Phone, 20..29, 60),
            detection(DataClass::Phone, 30..39, 60),
        ];
        keep_most_confident_numbers(&mut detections);
        let kept: Vec<_> = detections.iter().map(|d| d.span.clone()).collect();
        assert_eq!(kept, vec![5..25, 30..39]);
    }

    fn finding(
        class: DataClass,
        span: Range<usize>,
        rule: &'static str,
        confidence: u8,
    ) -> RawFinding {
        RawFinding {
            class,
            span,
            rule,
            confidence,
            via: Vec::new(),
        }
    }

    #[test]
    fn overlapping_findings_of_one_class_merge_into_the_union() {
        let merged = merge_overlapping(vec![
            finding(DataClass::Secret, 5..30, "secret.b", 50),
            finding(DataClass::Secret, 0..10, "secret.a", 90),
            finding(DataClass::Secret, 28..40, "secret.c", 70),
        ]);
        assert_eq!(
            merged,
            vec![finding(DataClass::Secret, 0..40, "secret.a", 90)]
        );
    }

    #[test]
    fn touching_spans_and_other_classes_stay_apart() {
        let merged = merge_overlapping(vec![
            finding(DataClass::Secret, 10..20, "secret.a", 90),
            finding(DataClass::Secret, 0..10, "secret.a", 90),
            finding(DataClass::InvisibleText, 5..6, "invisible_text.bidi", 100),
        ]);
        let spans: Vec<_> = merged.iter().map(|f| (f.class, f.span.clone())).collect();
        assert_eq!(
            spans,
            vec![
                (DataClass::Secret, 0..10),
                (DataClass::InvisibleText, 5..6),
                (DataClass::Secret, 10..20),
            ]
        );
    }

    #[test]
    fn ties_go_to_fewer_layers_then_to_the_first_rule() {
        let mut decoded = finding(DataClass::Secret, 0..10, "secret.a", 90);
        decoded.via = vec![Layer::Base64];
        let plain = finding(DataClass::Secret, 2..8, "secret.z", 90);
        let merged = merge_overlapping(vec![decoded, plain]);
        assert_eq!(
            merged,
            vec![finding(DataClass::Secret, 0..10, "secret.z", 90)]
        );

        let merged = merge_overlapping(vec![
            finding(DataClass::Secret, 0..10, "secret.z", 90),
            finding(DataClass::Secret, 0..10, "secret.a", 90),
        ]);
        assert_eq!(merged[0].rule, "secret.a");
    }

    #[test]
    fn candidates_overlapping_a_secret_are_dropped() {
        let mut findings = vec![
            finding(DataClass::Secret, 10..20, "secret.a", 90),
            finding(DataClass::Secret, 20..25, "secret.b", 90),
            finding(
                DataClass::SecretCandidate,
                0..10,
                "secret_candidate.entropy",
                50,
            ),
            finding(
                DataClass::SecretCandidate,
                5..11,
                "secret_candidate.entropy",
                50,
            ),
            finding(
                DataClass::SecretCandidate,
                24..30,
                "secret_candidate.entropy",
                50,
            ),
            finding(
                DataClass::SecretCandidate,
                25..40,
                "secret_candidate.entropy",
                50,
            ),
            finding(DataClass::InvisibleText, 12..13, "invisible_text.bidi", 100),
        ];
        drop_candidates_overlapping_secrets(&mut findings);
        let kept: Vec<_> = findings.iter().map(|f| (f.class, f.span.clone())).collect();
        assert_eq!(
            kept,
            vec![
                (DataClass::Secret, 10..20),
                (DataClass::Secret, 20..25),
                (DataClass::SecretCandidate, 0..10),
                (DataClass::SecretCandidate, 25..40),
                (DataClass::InvisibleText, 12..13),
            ]
        );
    }

    #[test]
    fn candidates_stay_when_only_other_classes_overlap() {
        let mut findings = vec![
            finding(
                DataClass::InvisibleText,
                5..8,
                "invisible_text.zero_width",
                100,
            ),
            finding(
                DataClass::SecretCandidate,
                0..40,
                "secret_candidate.entropy",
                50,
            ),
        ];
        drop_candidates_overlapping_secrets(&mut findings);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn identical_findings_collapse() {
        let one = finding(
            DataClass::InvisibleText,
            0..3,
            "invisible_text.zero_width",
            100,
        );
        let merged = merge_overlapping(vec![one.clone(), one.clone(), one.clone()]);
        assert_eq!(merged, vec![one]);
    }
}
