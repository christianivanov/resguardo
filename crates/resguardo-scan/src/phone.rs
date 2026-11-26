//! Spanish phones (Annex F.5, ADR 0010): nine digits starting with 6, 7, 8 or 9, with an
//! optional `+34` or `0034` prefix.

use std::ops::Range;

use resguardo_core::DataClass;

use crate::pipeline::ScanError;
use crate::scanner::{Detection, Scanner};
use crate::windows::{WindowRule, scan_windows};

/// Format only: nine digits that start with 6 to 9 are also order numbers or references
/// (ADR 0010).
const CONFIDENCE: u8 = 60;

const NUMBER_DIGITS: usize = 9;

#[derive(Debug)]
pub(crate) struct PhoneScanner;

impl Scanner for PhoneScanner {
    fn scan(&self, text: &str, out: &mut Vec<Detection>) -> Result<(), ScanError> {
        scan_windows(self, text, out);
        Ok(())
    }
}

impl WindowRule for PhoneScanner {
    /// `0034` and nine digits.
    const MAX_LEN: usize = 4 + NUMBER_DIGITS;
    /// No dot: in Spain it is the thousands separator, so `612.345.678` is an amount.
    const SEPARATORS: &'static [u8] = b" -";

    fn check(&self, text: &str, span: Range<usize>, compact: &[u8]) -> Option<Detection> {
        if !compact.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let span = match compact.len() {
            NUMBER_DIGITS => span,
            13 if compact.starts_with(b"0034") => span,
            // `34` is a prefix only with the `+` right before it, which joins the span.
            11 if compact.starts_with(b"34") => {
                let plus = span.start.checked_sub(1)?;
                if text.as_bytes().get(plus) != Some(&b'+') {
                    return None;
                }
                plus..span.end
            }
            _ => return None,
        };
        let first = compact.get(compact.len() - NUMBER_DIGITS)?;
        matches!(first, b'6'..=b'9').then_some(Detection {
            class: DataClass::Phone,
            span,
            rule: "phone.es",
            confidence: CONFIDENCE,
        })
    }
}
