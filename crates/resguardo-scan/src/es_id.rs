//! Spanish ids (Annex F.4, ADR 0010): DNI, NIE and CIF, reported only when their control
//! character is right.

use std::ops::Range;

use resguardo_core::DataClass;

use crate::pipeline::ScanError;
use crate::scanner::{Detection, Scanner};
use crate::windows::{WindowRule, scan_windows};

/// A control letter or digit confirms the value (ADR 0010).
const CONFIDENCE: u8 = 90;

/// Every id has nine characters without separators.
const ID_LEN: usize = 9;

/// DNI and NIE control letter, indexed by the number modulo 23.
const DNI_LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";

/// First letters of a CIF.
const CIF_FIRST: &[u8] = b"ABCDEFGHJNPQRSUVW";
/// CIF control as a letter, indexed by the control digit.
const CIF_CONTROL_LETTERS: &[u8; 10] = b"JABCDEFGHI";
/// CIF first letters whose control must be a letter.
const CIF_LETTER_CONTROL: &[u8] = b"NPQRSW";
/// CIF first letters whose control must be a digit.
const CIF_DIGIT_CONTROL: &[u8] = b"ABEH";

#[derive(Debug)]
pub(crate) struct EsIdScanner;

impl Scanner for EsIdScanner {
    fn scan(&self, text: &str, out: &mut Vec<Detection>) -> Result<(), ScanError> {
        scan_windows(self, text, out);
        Ok(())
    }
}

impl WindowRule for EsIdScanner {
    const MAX_LEN: usize = ID_LEN;
    const SEPARATORS: &'static [u8] = b" .-";

    fn check(&self, _text: &str, span: Range<usize>, compact: &[u8]) -> Option<Detection> {
        let id: [u8; ID_LEN] = compact.try_into().ok()?;
        let rule = classify(&id.map(|b| b.to_ascii_uppercase()))?;
        Some(Detection {
            class: DataClass::EsId,
            span,
            rule,
            confidence: CONFIDENCE,
        })
    }
}

/// The rule an upper-case id matches, if its control character is right.
fn classify(id: &[u8; ID_LEN]) -> Option<&'static str> {
    let [first, middle @ .., control] = id;
    match first {
        b'0'..=b'9' => {
            // DNI: eight digits, then the letter.
            let number = number(&id[..8])?;
            (dni_letter(number) == *control).then_some("es_id.dni")
        }
        b'X' | b'Y' | b'Z' => {
            // NIE: X, Y or Z stand for 0, 1 or 2 in front of the seven digits.
            let prefix = u32::from(first - b'X');
            let number = prefix * 10_000_000 + number(middle)?;
            (dni_letter(number) == *control).then_some("es_id.nie")
        }
        _ if CIF_FIRST.contains(first) => {
            cif_is_valid(*first, middle, *control).then_some("es_id.cif")
        }
        _ => None,
    }
}

fn dni_letter(number: u32) -> u8 {
    // `number % 23` is always a valid index of the 23 letters.
    DNI_LETTERS[(number % 23) as usize]
}

/// The decimal value of ASCII digits, or `None` if any byte is not a digit. At most eight
/// digits are passed, so the value fits in a `u32`.
fn number(digits: &[u8]) -> Option<u32> {
    digits.iter().try_fold(0u32, |acc, &b| {
        b.is_ascii_digit().then(|| acc * 10 + u32::from(b - b'0'))
    })
}

/// Annex F.4: A sums the digits in even positions, B sums the digits of twice each digit in
/// odd positions, and the control is (10 - (A + B) mod 10) mod 10, as a digit or a letter.
fn cif_is_valid(first: u8, digits: &[u8], control: u8) -> bool {
    if digits.len() != 7 || !digits.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let mut sum = 0u32;
    for (index, &b) in digits.iter().enumerate() {
        let digit = u32::from(b - b'0');
        // Index 0 is the 1st position, which is odd.
        sum += if index % 2 == 1 {
            digit
        } else {
            let doubled = digit * 2;
            doubled / 10 + doubled % 10
        };
    }
    let expected = (10 - sum % 10) % 10;
    // `expected` is 0 to 9, a valid index of the ten letters.
    let as_letter = CIF_CONTROL_LETTERS[expected as usize];
    let as_digit = b'0' + expected as u8;
    if control.is_ascii_digit() {
        control == as_digit && !CIF_LETTER_CONTROL.contains(&first)
    } else {
        control == as_letter && !CIF_DIGIT_CONTROL.contains(&first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str) -> Option<&'static str> {
        classify(&id.as_bytes().try_into().unwrap())
    }

    #[test]
    fn every_dni_number_has_exactly_one_letter() {
        for number in [0u32, 1, 22, 23, 12_345_678, 99_999_999] {
            let accepted = (b'A'..=b'Z')
                .filter(|&letter| {
                    let id = format!("{number:08}{}", char::from(letter));
                    rule(&id) == Some("es_id.dni")
                })
                .count();
            assert_eq!(accepted, 1, "{number}");
        }
    }

    #[test]
    fn nie_z_stands_for_2() {
        // 21234567 mod 23 = 1, letter R (computed outside the code).
        assert_eq!(rule("Z1234567R"), Some("es_id.nie"));
        // As if Z were 0, the letter would be L (01234567 mod 23 = 19).
        assert_eq!(rule("Z1234567L"), None);
    }

    #[test]
    fn cif_with_a_free_control_accepts_digit_and_letter() {
        // G: either form. Digits 1234567 give control 4, letter D.
        assert_eq!(rule("G12345674"), Some("es_id.cif"));
        assert_eq!(rule("G1234567D"), Some("es_id.cif"));
        assert_eq!(rule("G12345675"), None);
    }

    #[test]
    fn letters_outside_the_id_alphabets_are_rejected() {
        assert_eq!(rule("I12345674"), None);
        assert_eq!(rule("K1234567D"), None);
    }
}
