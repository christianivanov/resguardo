//! Aggregation (design document, "Motor de detección", step 4; ADR 0008): overlapping
//! findings of one class become one, and the most confident one gives it its rule.

use std::cmp::Ordering;
use std::ops::Range;

use resguardo_core::DataClass;

use crate::decode::Layer;

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
