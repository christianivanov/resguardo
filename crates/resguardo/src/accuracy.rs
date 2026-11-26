//! `resguardo accuracy` (milestone M6.1, ADR 0016): runs the detectors over a labelled
//! corpus and counts, per class, what was found, missed and wrongly found.

use std::collections::{BTreeMap, BTreeSet};

use resguardo_scan::{Pipeline, ScanError};
use serde::Deserialize;
use serde_json::{Value, json};

/// One corpus line.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub text: String,
    /// Classes that must be found. Empty for a negative.
    #[serde(default)]
    pub expect: BTreeSet<String>,
    /// Classes that may be found without counting as false positives.
    #[serde(default)]
    pub allow: BTreeSet<String>,
    #[serde(default)]
    pub group: String,
}

/// Counts for one class.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClassCounts {
    /// Texts that should contain the class.
    pub positives: u64,
    pub found: u64,
    pub missed: u64,
    /// Texts where the class was found but neither expected nor allowed.
    pub false_positives: u64,
}

#[derive(Debug, Default)]
pub struct Report {
    pub texts: u64,
    /// Texts that expect nothing.
    pub negatives: u64,
    pub classes: BTreeMap<String, ClassCounts>,
    /// Groups of the texts with a mistake, for the report.
    pub mistakes: BTreeMap<String, u64>,
}

pub fn run(pipeline: &Pipeline, samples: &[Sample]) -> Result<Report, ScanError> {
    let mut report = Report::default();
    for sample in samples {
        let found: BTreeSet<String> = pipeline
            .scan_text("", &sample.text)?
            .findings
            .iter()
            .map(|f| f.class.as_str().to_owned())
            .collect();
        report.texts += 1;
        if sample.expect.is_empty() {
            report.negatives += 1;
        }
        let mut mistake = false;
        for class in &sample.expect {
            let counts = report.classes.entry(class.clone()).or_default();
            counts.positives += 1;
            if found.contains(class) {
                counts.found += 1;
            } else {
                counts.missed += 1;
                mistake = true;
            }
        }
        for class in found.difference(&sample.expect) {
            if !sample.allow.contains(class) {
                report
                    .classes
                    .entry(class.clone())
                    .or_default()
                    .false_positives += 1;
                mistake = true;
            }
        }
        if mistake {
            *report.mistakes.entry(sample.group.clone()).or_default() += 1;
        }
    }
    Ok(report)
}

impl Report {
    /// The table `resguardo accuracy` prints. The false-positive rate is over the negatives,
    /// the texts that should give no finding at all.
    pub fn table(&self) -> String {
        let mut out = format!(
            "{} texts, {} negatives\n\n{:<18} {:>9} {:>6} {:>7} {:>9} {:>8}\n",
            self.texts,
            self.negatives,
            "class",
            "positives",
            "found",
            "missed",
            "false pos",
            "FP rate"
        );
        for (class, c) in &self.classes {
            let rate = if self.negatives == 0 {
                0.0
            } else {
                c.false_positives as f64 * 100.0 / self.negatives as f64
            };
            out.push_str(&format!(
                "{class:<18} {:>9} {:>6} {:>7} {:>9} {:>7.1}%\n",
                c.positives, c.found, c.missed, c.false_positives, rate
            ));
        }
        if !self.mistakes.is_empty() {
            out.push_str("\nmistakes by group:");
            for (group, n) in &self.mistakes {
                out.push_str(&format!(" {group}={n}"));
            }
            out.push('\n');
        }
        out
    }

    /// The counts a later run may not exceed.
    pub fn baseline(&self) -> Value {
        json!(
            self.classes
                .iter()
                .map(|(class, c)| (
                    class.clone(),
                    json!({"missed": c.missed, "false_positives": c.false_positives})
                ))
                .collect::<BTreeMap<_, _>>()
        )
    }

    /// Classes whose misses or false positives went up compared with `baseline`.
    pub fn regressions(&self, baseline: &Value) -> Vec<String> {
        let mut out = Vec::new();
        for (class, c) in &self.classes {
            let limit = |field: &str| {
                baseline
                    .get(class)
                    .and_then(|b| b.get(field))
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            };
            if c.missed > limit("missed") {
                out.push(format!(
                    "{class}: {} missed (baseline {})",
                    c.missed,
                    limit("missed")
                ));
            }
            if c.false_positives > limit("false_positives") {
                out.push(format!(
                    "{class}: {} false positives (baseline {})",
                    c.false_positives,
                    limit("false_positives")
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use resguardo_core::config::ScanConfig;

    use super::*;

    fn sample(text: &str, expect: &[&str], allow: &[&str]) -> Sample {
        Sample {
            text: text.to_owned(),
            expect: expect.iter().map(|s| (*s).to_owned()).collect(),
            allow: allow.iter().map(|s| (*s).to_owned()).collect(),
            group: "test".to_owned(),
        }
    }

    #[test]
    fn found_missed_and_false_positives_are_counted_per_class() {
        let pipeline = Pipeline::new(&ScanConfig::default()).unwrap();
        let report = run(
            &pipeline,
            &[
                sample("Mi DNI es 12345678Z", &["es_id"], &[]),
                sample("DNI12345678Z", &["es_id"], &[]),
                sample("Ref. 612345678", &[], &[]),
                sample("Pedido 12345678 enviado", &[], &[]),
            ],
        )
        .unwrap();
        assert_eq!(report.texts, 4);
        assert_eq!(report.negatives, 2);
        assert_eq!(
            report.classes["es_id"],
            ClassCounts {
                positives: 2,
                found: 1,
                missed: 1,
                false_positives: 0
            }
        );
        assert_eq!(report.classes["phone"].false_positives, 1);
        assert_eq!(report.mistakes["test"], 2);
    }

    #[test]
    fn a_regression_is_any_count_above_the_baseline() {
        let pipeline = Pipeline::new(&ScanConfig::default()).unwrap();
        let report = run(&pipeline, &[sample("Ref. 612345678", &[], &[])]).unwrap();
        assert!(report.regressions(&report.baseline()).is_empty());
        let stricter = json!({"phone": {"missed": 0, "false_positives": 0}});
        assert_eq!(report.regressions(&stricter).len(), 1);
    }
}
