//! The detector interface (glossary: `Scanner`).

use std::ops::Range;

use resguardo_core::DataClass;

use crate::pipeline::ScanError;

/// A match in the normalized text a detector was given. The pipeline maps it back to the
/// original text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Detection {
    pub class: DataClass,
    pub span: Range<usize>,
    pub rule: &'static str,
    pub confidence: u8,
}

/// A detector: reads one normalized text and appends what it finds.
///
/// `Send + Sync` lets the pipeline, which owns the detectors, be shared across threads.
pub(crate) trait Scanner: Send + Sync + std::fmt::Debug {
    fn scan(&self, text: &str, out: &mut Vec<Detection>) -> Result<(), ScanError>;
}
