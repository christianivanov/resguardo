//! Email addresses (Annex F.5, ADR 0010): a simple `local@domain.tld` pattern with explicit
//! length limits, and boundaries checked in code.

use regex::Regex;
use resguardo_core::DataClass;

use crate::pipeline::ScanError;
use crate::scanner::{Detection, Scanner};

/// Format only, but the shape is distinctive (ADR 0010).
const CONFIDENCE: u8 = 80;

/// Local part up to 64 characters, labels up to 63, top-level domain of 2 to 63 letters.
const PATTERN: &str =
    r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,63}";

#[derive(Debug)]
pub(crate) struct EmailScanner {
    regex: Regex,
}

impl EmailScanner {
    pub(crate) fn new() -> Result<Self, ScanError> {
        let regex = Regex::new(PATTERN).map_err(|e| ScanError::Pattern(e.to_string()))?;
        Ok(Self { regex })
    }
}

fn is_local_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"._%+-".contains(&b)
}

impl Scanner for EmailScanner {
    fn scan(&self, text: &str, out: &mut Vec<Detection>) -> Result<(), ScanError> {
        let bytes = text.as_bytes();
        for found in self.regex.find_iter(text) {
            // No look-around in `regex`: a match that starts inside a longer local part, or
            // whose domain goes on, is not an address.
            let before = found
                .start()
                .checked_sub(1)
                .and_then(|i| bytes.get(i))
                .is_some_and(|&b| is_local_byte(b));
            let after = bytes
                .get(found.end())
                .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'-');
            if !before && !after {
                out.push(Detection {
                    class: DataClass::Email,
                    span: found.range(),
                    rule: "email.address",
                    confidence: CONFIDENCE,
                });
            }
        }
        Ok(())
    }
}
