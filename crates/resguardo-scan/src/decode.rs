//! Steps 3 and 4 of Annex F.1: find encoded fragments and decode them, within a size limit.
//!
//! Decoders are lenient on purpose (ADR 0008): the sender chooses the encoding, so anything a
//! reader could still decode should be decoded here.

use std::ops::Range;

use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

/// Shortest Base64 fragment worth decoding (Annex F.1).
const MIN_BASE64_CHARS: usize = 24;
/// Shortest hexadecimal fragment worth decoding (Annex F.1).
const MIN_HEX_DIGITS: usize = 32;
/// Fewest `%XX` sequences that make a URL-encoded fragment (Annex F.1).
const MIN_URL_ESCAPES: usize = 3;
/// Share of printable characters a decoded text needs to be scanned (Annex F.1).
const MIN_PRINTABLE_PERCENT: u128 = 90;

/// Padding optional, non-canonical trailing bits accepted.
const LENIENT: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_decode_padding_mode(DecodePaddingMode::Indifferent)
    .with_decode_allow_trailing_bits(true);
const STANDARD_LENIENT: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, LENIENT);
const URL_SAFE_LENIENT: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, LENIENT);

/// A decoding layer, named in `Finding::via` and `ScanFlag::via`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Layer {
    Base64,
    Hex,
    Url,
}

impl Layer {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Layer::Base64 => "base64",
            Layer::Hex => "hex",
            Layer::Url => "url",
        }
    }
}

/// An encoded fragment, as a byte range of the text it was found in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub layer: Layer,
    pub span: Range<usize>,
}

/// Printable text decoded from a candidate.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Decoded {
    pub text: String,
    /// The fragment held more than `max_bytes`; `text` is only its first part.
    pub truncated: bool,
}

/// Every candidate in `text`, in order of position. A fragment can be a candidate for more
/// than one layer (hexadecimal digits are also Base64 characters).
pub(crate) fn find_candidates(text: &str) -> Vec<Candidate> {
    let bytes = text.as_bytes();
    let mut candidates = Vec::new();
    for run in runs(bytes, is_base64_byte) {
        if run.len() < MIN_BASE64_CHARS {
            continue;
        }
        // Up to two padding characters right after the run belong to it.
        let padding = bytes
            .get(run.end..)
            .unwrap_or_default()
            .iter()
            .take(2)
            .take_while(|&&b| b == b'=')
            .count();
        candidates.push(Candidate {
            layer: Layer::Base64,
            span: run.start..run.end + padding,
        });
    }
    for run in runs(bytes, |b| b.is_ascii_hexdigit()) {
        if run.len() >= MIN_HEX_DIGITS && run.len() % 2 == 0 {
            candidates.push(Candidate {
                layer: Layer::Hex,
                span: run,
            });
        }
    }
    for run in runs(bytes, is_url_byte) {
        if url_escapes(bytes.get(run.clone()).unwrap_or_default()) >= MIN_URL_ESCAPES {
            candidates.push(Candidate {
                layer: Layer::Url,
                span: run,
            });
        }
    }
    candidates.sort_by_key(|c| (c.span.start, c.span.end, c.layer));
    candidates
}

/// Maximal runs of bytes for which `accept` holds. Every accepted byte is ASCII, so runs start
/// and end on character boundaries.
fn runs(bytes: &[u8], accept: impl Fn(u8) -> bool) -> Vec<Range<usize>> {
    let mut found = Vec::new();
    let mut start = None;
    for (i, &b) in bytes.iter().enumerate() {
        match (accept(b), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                found.push(s..i);
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        found.push(s..bytes.len());
    }
    found
}

fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-')
}

/// RFC 3986 unreserved and reserved characters, and `%`.
fn is_url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=%".contains(&b)
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Number of valid `%XX` sequences, counted without overlap.
fn url_escapes(bytes: &[u8]) -> usize {
    let mut count = 0;
    let mut i = 0;
    while i < bytes.len() {
        if percent_escape(bytes, i).is_some() {
            count += 1;
            i += 3;
        } else {
            i += 1;
        }
    }
    count
}

/// The byte encoded by `%XX` at position `i`, if there is one.
fn percent_escape(bytes: &[u8], i: usize) -> Option<u8> {
    if bytes.get(i) != Some(&b'%') {
        return None;
    }
    let high = hex_value(*bytes.get(i + 1)?)?;
    let low = hex_value(*bytes.get(i + 2)?)?;
    Some((high << 4) | low)
}

/// Decodes `fragment` into at most `max_bytes` bytes. Returns `None` unless the result is
/// printable text (Annex F.1, ADR 0008).
pub(crate) fn decode(layer: Layer, fragment: &str, max_bytes: usize) -> Option<Decoded> {
    let (bytes, truncated) = match layer {
        Layer::Base64 => decode_base64(fragment, max_bytes)?,
        Layer::Hex => decode_hex(fragment, max_bytes)?,
        Layer::Url => decode_url(fragment, max_bytes),
    };
    let text = printable_text(bytes, truncated)?;
    Some(Decoded { text, truncated })
}

fn decode_base64(fragment: &str, max_bytes: usize) -> Option<(Vec<u8>, bool)> {
    let digits = fragment.trim_end_matches('=');
    let url_safe = digits.contains(['-', '_']);
    if url_safe && digits.contains(['+', '/']) {
        return None;
    }
    let engine = if url_safe {
        &URL_SAFE_LENIENT
    } else {
        &STANDARD_LENIENT
    };
    let full_len = digits.len() / 4 * 3
        + match digits.len() % 4 {
            0 => 0,
            2 => 1,
            3 => 2,
            _ => return None,
        };
    if full_len <= max_bytes {
        return Some((engine.decode(digits).ok()?, false));
    }
    // Every 4 characters decode to 3 bytes, so a prefix of whole groups needs no padding.
    let prefix = digits.get(..max_bytes / 3 * 4)?;
    Some((engine.decode(prefix).ok()?, true))
}

fn decode_hex(fragment: &str, max_bytes: usize) -> Option<(Vec<u8>, bool)> {
    let pairs = fragment.len() / 2;
    let take = pairs.min(max_bytes);
    let mut bytes = Vec::with_capacity(take);
    let (whole_pairs, _) = fragment.as_bytes().as_chunks::<2>();
    for [high, low] in whole_pairs.iter().take(take) {
        bytes.push((hex_value(*high)? << 4) | hex_value(*low)?);
    }
    Some((bytes, pairs > max_bytes))
}

fn decode_url(fragment: &str, max_bytes: usize) -> (Vec<u8>, bool) {
    let input = fragment.as_bytes();
    let mut bytes = Vec::with_capacity(input.len().min(max_bytes));
    let mut i = 0;
    while let Some(&b) = input.get(i) {
        if bytes.len() == max_bytes {
            return (bytes, true);
        }
        match percent_escape(input, i) {
            Some(decoded) => {
                bytes.push(decoded);
                i += 3;
            }
            None => {
                bytes.push(b);
                i += 1;
            }
        }
    }
    (bytes, false)
}

/// The bytes as text if they are UTF-8 and at least 90 % printable. When the decoding was cut
/// short, a character split at the end is dropped first.
fn printable_text(bytes: Vec<u8>, truncated: bool) -> Option<String> {
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => {
            let utf8 = error.utf8_error();
            if !truncated || utf8.error_len().is_some() {
                return None;
            }
            let mut bytes = error.into_bytes();
            bytes.truncate(utf8.valid_up_to());
            String::from_utf8(bytes).ok()?
        }
    };
    let mut total: u128 = 0;
    let mut printable: u128 = 0;
    for c in text.chars() {
        total += 1;
        if !c.is_control() || matches!(c, '\t' | '\n' | '\r') {
            printable += 1;
        }
    }
    (total > 0 && printable * 100 >= total * MIN_PRINTABLE_PERCENT).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
    /// Base64 of `TOKEN` (Annex G.2), computed outside the code.
    const TOKEN_BASE64: &str = "Z2hwX0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpag==";
    /// Hexadecimal of `TOKEN`, computed outside the code.
    const TOKEN_HEX: &str =
        "6768705f4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a";

    fn layers(text: &str) -> Vec<(Layer, Range<usize>)> {
        find_candidates(text)
            .into_iter()
            .map(|c| (c.layer, c.span))
            .collect()
    }

    #[test]
    fn base64_candidates_need_24_characters_and_keep_their_padding() {
        let text = format!("token: {TOKEN_BASE64}.");
        assert_eq!(layers(&text), vec![(Layer::Base64, 7..63)]);
        assert!(layers("abcdefghijklmnopqrstuvw").is_empty());
        assert_eq!(layers("abcdefghijklmnopqrstuvwx===")[0].1, 0..26);
    }

    #[test]
    fn hex_candidates_need_32_digits_in_even_number() {
        let text = format!("0x{TOKEN_HEX}");
        let found = layers(&text);
        assert!(found.contains(&(Layer::Hex, 2..82)), "{found:?}");
        assert!(
            !layers(&"a".repeat(31))
                .iter()
                .any(|(l, _)| *l == Layer::Hex)
        );
        assert!(
            !layers(&"a".repeat(33))
                .iter()
                .any(|(l, _)| *l == Layer::Hex)
        );
    }

    #[test]
    fn url_candidates_need_three_escapes_anywhere_in_the_run() {
        assert_eq!(layers("x %67%68p_ok"), vec![]);
        assert_eq!(layers("x %67h%70%5Fok y"), vec![(Layer::Url, 2..14)]);
        assert_eq!(layers("\"%41%42%43\""), vec![(Layer::Url, 1..10)]);
        // An invalid escape does not count.
        assert_eq!(layers("%41%4G%43"), vec![]);
    }

    #[test]
    fn base64_decodes_with_either_alphabet_and_optional_padding() {
        let decoded = decode(Layer::Base64, TOKEN_BASE64, 1024).unwrap();
        assert_eq!(decoded.text, TOKEN);
        assert!(!decoded.truncated);
        let unpadded = TOKEN_BASE64.trim_end_matches('=');
        assert_eq!(decode(Layer::Base64, unpadded, 1024).unwrap().text, TOKEN);
        // "??>" encodes to "Pz8+" (standard) and "Pz8-" (URL-safe).
        let standard = "Pz8+".repeat(8);
        let url_safe = "Pz8-".repeat(8);
        assert_eq!(
            decode(Layer::Base64, &standard, 1024).unwrap().text,
            "??>".repeat(8)
        );
        assert_eq!(
            decode(Layer::Base64, &url_safe, 1024).unwrap().text,
            "??>".repeat(8)
        );
        let mixed = format!("{standard}{url_safe}");
        assert_eq!(decode(Layer::Base64, &mixed, 1024), None);
    }

    #[test]
    fn hex_and_url_decode() {
        assert_eq!(decode(Layer::Hex, TOKEN_HEX, 1024).unwrap().text, TOKEN);
        let upper = TOKEN_HEX.to_ascii_uppercase();
        assert_eq!(decode(Layer::Hex, &upper, 1024).unwrap().text, TOKEN);
        let url = decode(Layer::Url, "%67h%70%5Fok+%C3%B1", 1024).unwrap();
        assert_eq!(url.text, "ghp_ok+ñ");
    }

    #[test]
    fn binary_or_invalid_results_are_not_text() {
        // 24 zero bytes.
        assert_eq!(decode(Layer::Base64, &"A".repeat(32), 1024), None);
        // Invalid UTF-8.
        assert_eq!(decode(Layer::Hex, &"ff".repeat(16), 1024), None);
        // Mostly control characters.
        assert_eq!(decode(Layer::Url, "%01%02%03%04ab", 1024), None);
    }

    #[test]
    fn printable_means_at_least_90_percent() {
        let nine_of_ten = format!("{}\u{1}", "a".repeat(9));
        assert!(printable_text(nine_of_ten.into_bytes(), false).is_some());
        let eight_of_ten = format!("{}\u{1}\u{1}", "a".repeat(8));
        assert!(printable_text(eight_of_ten.into_bytes(), false).is_none());
        assert!(printable_text(b"a\tb\nc\r".to_vec(), false).is_some());
        assert!(printable_text(Vec::new(), false).is_none());
    }

    #[test]
    fn decoding_stops_at_max_bytes_and_says_so() {
        let decoded = decode(Layer::Base64, TOKEN_BASE64, 10).unwrap();
        assert_eq!(decoded.text, &TOKEN[..9]);
        assert!(decoded.truncated);
        let decoded = decode(Layer::Hex, TOKEN_HEX, 10).unwrap();
        assert_eq!(decoded.text, &TOKEN[..10]);
        assert!(decoded.truncated);
        let decoded = decode(Layer::Url, "%41%42%43%44", 3).unwrap();
        assert_eq!(decoded.text, "ABC");
        assert!(decoded.truncated);
        // Exactly at the limit is not truncated.
        assert!(!decode(Layer::Url, "%41%42%43", 3).unwrap().truncated);
    }

    #[test]
    fn a_character_cut_by_the_limit_is_dropped() {
        // "aaa" then "ñ" (2 bytes): a limit of 4 bytes cuts the "ñ" in half.
        let decoded = decode(Layer::Url, "aaa%C3%B1%41", 4).unwrap();
        assert_eq!(decoded.text, "aaa");
        assert!(decoded.truncated);
        // Without truncation, the same broken byte is invalid text.
        assert_eq!(decode(Layer::Url, "aaa%C3%41%42", 1024), None);
    }

    #[test]
    fn arbitrary_input_never_panics() {
        let pool = [
            "A", "z", "0", "9", "+", "/", "-", "_", "=", "%", "4", "f", "é", " ", "%4",
        ];
        let mut rng = crate::test_support::Lcg(7);
        for _ in 0..2000 {
            let len = (rng.next() % 80) as usize;
            let text: String = (0..len)
                .map(|_| pool[(rng.next() as usize) % pool.len()])
                .collect();
            for candidate in find_candidates(&text) {
                let fragment = text.get(candidate.span.clone()).unwrap();
                for max in [0, 1, 2, 3, 4, 7, 1024] {
                    if let Some(decoded) = decode(candidate.layer, fragment, max) {
                        assert!(decoded.text.len() <= max);
                    }
                }
            }
        }
    }
}
