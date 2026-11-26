//! IBANs (Annex F.5, ADR 0010): two letters, two check digits and the account, with the
//! length of that country in the SWIFT IBAN Registry, and mod 97 = 1.

use std::ops::Range;

use resguardo_core::DataClass;

use crate::pipeline::ScanError;
use crate::scanner::{Detection, Scanner};
use crate::windows::{WindowRule, scan_windows};

/// Country length and mod 97: a random value passes about 1 time in 97 (ADR 0010).
const CONFIDENCE: u8 = 95;

/// The longest IBAN ISO 13616 allows.
const MAX_IBAN_LEN: usize = 34;

/// IBAN length by country, sorted by code, for a binary search.
///
/// Source: SWIFT IBAN Registry, TXT format, downloaded on 2026-11-26 (89 entries, most
/// recent "Last update date" Sep-26, SHA-256
/// `ad13d9595a991790ad1a5a1363d574a43357c710e3bce2170f95c9bef8932df0`). Generated from the
/// file, not typed. Territories that use another country's code (AX, GF, JE…) have no entry
/// of their own.
const LENGTHS: &[([u8; 2], u8)] = &[
    (*b"AD", 24),
    (*b"AE", 23),
    (*b"AL", 28),
    (*b"AT", 20),
    (*b"AZ", 28),
    (*b"BA", 20),
    (*b"BE", 16),
    (*b"BG", 22),
    (*b"BH", 22),
    (*b"BI", 27),
    (*b"BR", 29),
    (*b"BY", 28),
    (*b"CH", 21),
    (*b"CR", 22),
    (*b"CY", 28),
    (*b"CZ", 24),
    (*b"DE", 22),
    (*b"DJ", 27),
    (*b"DK", 18),
    (*b"DO", 28),
    (*b"EE", 20),
    (*b"EG", 29),
    (*b"ES", 24),
    (*b"FI", 18),
    (*b"FK", 18),
    (*b"FO", 18),
    (*b"FR", 27),
    (*b"GB", 22),
    (*b"GE", 22),
    (*b"GI", 23),
    (*b"GL", 18),
    (*b"GR", 27),
    (*b"GT", 28),
    (*b"HN", 28),
    (*b"HR", 21),
    (*b"HU", 28),
    (*b"IE", 22),
    (*b"IL", 23),
    (*b"IQ", 23),
    (*b"IS", 26),
    (*b"IT", 27),
    (*b"JO", 30),
    (*b"KW", 30),
    (*b"KZ", 20),
    (*b"LB", 28),
    (*b"LC", 32),
    (*b"LI", 21),
    (*b"LT", 20),
    (*b"LU", 20),
    (*b"LV", 21),
    (*b"LY", 25),
    (*b"MC", 27),
    (*b"MD", 24),
    (*b"ME", 22),
    (*b"MK", 19),
    (*b"MN", 20),
    (*b"MR", 27),
    (*b"MT", 31),
    (*b"MU", 30),
    (*b"NI", 28),
    (*b"NL", 18),
    (*b"NO", 15),
    (*b"OM", 23),
    (*b"PK", 24),
    (*b"PL", 28),
    (*b"PS", 29),
    (*b"PT", 25),
    (*b"QA", 29),
    (*b"RO", 24),
    (*b"RS", 22),
    (*b"RU", 33),
    (*b"SA", 24),
    (*b"SC", 31),
    (*b"SD", 18),
    (*b"SE", 24),
    (*b"SI", 19),
    (*b"SK", 24),
    (*b"SM", 27),
    (*b"SO", 23),
    (*b"ST", 25),
    (*b"SV", 28),
    (*b"TL", 23),
    (*b"TN", 24),
    (*b"TR", 26),
    (*b"UA", 29),
    (*b"VA", 22),
    (*b"VG", 24),
    (*b"XK", 20),
    (*b"YE", 30),
];

#[derive(Debug)]
pub(crate) struct IbanScanner;

impl Scanner for IbanScanner {
    fn scan(&self, text: &str, out: &mut Vec<Detection>) -> Result<(), ScanError> {
        scan_windows(self, text, out);
        Ok(())
    }
}

impl WindowRule for IbanScanner {
    const MAX_LEN: usize = MAX_IBAN_LEN;
    /// The print format: groups of four separated by spaces.
    const SEPARATORS: &'static [u8] = b" ";

    fn check(&self, _text: &str, span: Range<usize>, compact: &[u8]) -> Option<Detection> {
        is_valid(&compact.to_ascii_uppercase()).then_some(Detection {
            class: DataClass::Iban,
            span,
            rule: "iban.mod97",
            confidence: CONFIDENCE,
        })
    }
}

/// An upper-case IBAN without separators.
fn is_valid(iban: &[u8]) -> bool {
    let [c1, c2, d1, d2, account @ ..] = iban else {
        return false;
    };
    let Ok(index) = LENGTHS.binary_search_by_key(&[*c1, *c2], |(code, _)| *code) else {
        return false;
    };
    let expected = LENGTHS.get(index).map(|(_, len)| usize::from(*len));
    expected == Some(iban.len())
        && d1.is_ascii_digit()
        && d2.is_ascii_digit()
        && account.iter().all(u8::is_ascii_alphanumeric)
        && mod_97(account.iter().chain([c1, c2, d1, d2])) == 1
}

/// The account, then the country and check digits, with each letter as a number (A = 10 …
/// Z = 35), modulo 97. Computed digit by digit, so the remainder always fits in a `u32`.
fn mod_97<'a>(chars: impl Iterator<Item = &'a u8>) -> u32 {
    chars.fold(0, |rest, &b| {
        if b.is_ascii_digit() {
            (rest * 10 + u32::from(b - b'0')) % 97
        } else {
            (rest * 100 + u32::from(b - b'A') + 10) % 97
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_sorted_and_without_duplicates() {
        assert_eq!(LENGTHS.len(), 89);
        assert!(LENGTHS.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert!(
            LENGTHS
                .iter()
                .all(|(_, len)| (15..=MAX_IBAN_LEN as u8).contains(len))
        );
    }

    #[test]
    fn spain_is_24_characters() {
        let index = LENGTHS
            .binary_search_by_key(b"ES", |(code, _)| *code)
            .unwrap();
        assert_eq!(LENGTHS[index].1, 24);
    }

    #[test]
    fn mod_97_of_the_spanish_example_is_1() {
        let iban = b"ES9121000418450200051332";
        assert_eq!(mod_97(iban[4..].iter().chain(&iban[..4])), 1);
        assert!(is_valid(iban));
        assert!(!is_valid(b"ES9121000418450200051333"));
    }
}
