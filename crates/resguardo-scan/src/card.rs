//! Payment cards (Annex F.5, ADR 0010): 13 to 19 digits that pass Luhn.

use std::ops::Range;

use resguardo_core::DataClass;

use crate::pipeline::ScanError;
use crate::scanner::{Detection, Scanner};
use crate::windows::{WindowRule, scan_windows};

/// Luhn confirms the value, but a random number passes 1 time in 10 (ADR 0010).
const CONFIDENCE: u8 = 85;

const MIN_DIGITS: usize = 13;
const MAX_DIGITS: usize = 19;

#[derive(Debug)]
pub(crate) struct CardScanner;

impl Scanner for CardScanner {
    fn scan(&self, text: &str, out: &mut Vec<Detection>) -> Result<(), ScanError> {
        scan_windows(self, text, out);
        Ok(())
    }
}

impl WindowRule for CardScanner {
    const MAX_LEN: usize = MAX_DIGITS;
    const SEPARATORS: &'static [u8] = b" -";

    fn check(&self, _text: &str, span: Range<usize>, compact: &[u8]) -> Option<Detection> {
        let accepted = (MIN_DIGITS..=MAX_DIGITS).contains(&compact.len())
            && compact.iter().all(u8::is_ascii_digit)
            && passes_luhn(compact);
        accepted.then_some(Detection {
            class: DataClass::Card,
            span,
            rule: "card.luhn",
            confidence: CONFIDENCE,
        })
    }
}

/// From the right, every second digit is doubled (minus 9 if above 9); the sum must end in 0.
fn passes_luhn(digits: &[u8]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, &b)| {
            let digit = u32::from(b - b'0');
            if index % 2 == 1 {
                let doubled = digit * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                digit
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_accepts_exactly_one_check_digit() {
        for prefix in ["411111111111111", "37828224631000", "601100000000000"] {
            let accepted = (b'0'..=b'9')
                .filter(|&last| {
                    let mut digits = prefix.as_bytes().to_vec();
                    digits.push(last);
                    passes_luhn(&digits)
                })
                .count();
            assert_eq!(accepted, 1, "{prefix}");
        }
    }

    #[test]
    fn lengths_outside_13_to_19_are_not_cards() {
        // Twelve zeros pass Luhn but are too short.
        let span = 0..12;
        assert_eq!(CardScanner.check("", span, b"000000000000"), None);
    }
}
