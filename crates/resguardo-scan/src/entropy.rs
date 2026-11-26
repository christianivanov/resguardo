//! Secrets without a known format, by Shannon entropy (Annex F.2).

use resguardo_core::DataClass;

use crate::pipeline::ScanError;
use crate::scanner::{Detection, Scanner};

/// Confidence of an entropy finding (ADR 0008).
const CONFIDENCE: u8 = 50;
const RULE: &str = "secret_candidate.entropy";

/// Flags words of at least `min_len` characters of `[A-Za-z0-9+/=_-]` whose entropy is above
/// `threshold` bits per character. A word that is a known secret is dropped later, during
/// aggregation (ADR 0008).
#[derive(Debug)]
pub(crate) struct EntropyScanner {
    pub threshold: f64,
    pub min_len: usize,
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

/// Shannon entropy in bits per byte. Word bytes are ASCII, so bytes are characters.
fn shannon_entropy(word: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in word {
        counts[usize::from(b)] += 1;
    }
    // Lossless for any length that fits in memory: f64 is exact up to 2^53.
    let total = word.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

impl Scanner for EntropyScanner {
    fn scan(&self, text: &str, out: &mut Vec<Detection>) -> Result<(), ScanError> {
        let bytes = text.as_bytes();
        let mut start = 0;
        while start < bytes.len() {
            let Some(offset) = bytes[start..].iter().position(|&b| is_word_byte(b)) else {
                break;
            };
            let word_start = start + offset;
            let word_len = bytes[word_start..]
                .iter()
                .take_while(|&&b| is_word_byte(b))
                .count();
            let word_end = word_start + word_len;
            if word_len >= self.min_len
                && shannon_entropy(&bytes[word_start..word_end]) > self.threshold
            {
                out.push(Detection {
                    class: DataClass::SecretCandidate,
                    span: word_start..word_end,
                    rule: RULE,
                    confidence: CONFIDENCE,
                });
            }
            start = word_end;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_matches_values_computed_outside_the_code() {
        // Annex G.1, computed with Python.
        let g1 = shannon_entropy(b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        assert!((g1 - 4.663).abs() < 0.001, "{g1}");
        let word = shannon_entropy(b"SuperSecretPassword2026");
        assert!((word - 3.849).abs() < 0.001, "{word}");
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
        assert_eq!(shannon_entropy(b"ab"), 1.0);
    }

    #[test]
    fn words_are_split_on_other_characters() {
        let scanner = EntropyScanner {
            threshold: 3.0,
            min_len: 16,
        };
        let mut out = Vec::new();
        let text = "x abcdefghijklmnop.ABCDEFGHIJKLMNOP!0123456789abcdef";
        scanner.scan(text, &mut out).unwrap();
        let spans: Vec<_> = out.iter().map(|d| d.span.clone()).collect();
        assert_eq!(spans, vec![2..18, 19..35, 36..52]);
    }
}
