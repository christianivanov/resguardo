//! Redaction (Annex F.6, ADR 0013): spans become `[REDACTED:<class>:<n>]`, and only the JSON
//! strings that hold them change in the original bytes.
//!
//! Serializing the parsed body again would sort object keys and change whitespace, escapes
//! and numbers across the whole request, which breaks coding agents and prompt caching.
//! Instead, a locator finds the byte range of each affected string, and the new text is
//! spliced in. The result is parsed again and compared with what was intended before it is
//! returned.

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

use resguardo_core::{DataClass, Finding, ScanText};
use serde_json::Value;

use crate::json::parse_strict;
use crate::request::{ParsedRequest, with_segment};

/// Same limit as the strict parser (ADR 0007).
const MAX_DEPTH: usize = 128;

/// Why a body could not be redacted. The request is blocked (`SCAN_ERROR`, ADR 0002).
/// Messages never include body content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RedactError {
    #[error("a redaction span does not fit its text")]
    Span,
    #[error("the request body could not be rewritten")]
    Rewrite,
    #[error("the rewritten request body does not match the redaction")]
    Mismatch,
}

/// Returns `body` with every span replaced. `parsed` must come from `body`.
pub fn redact(
    body: &[u8],
    parsed: &ParsedRequest,
    spans: &[Finding],
) -> Result<Vec<u8>, RedactError> {
    if spans.is_empty() {
        return Ok(body.to_vec());
    }
    let replacements = redacted_texts(&parsed.texts, spans)?;
    replace_strings(body, &parsed.raw, &replacements)
}

/// Returns `body` with the string at each pointer replaced by its new text, and every other
/// byte unchanged. `raw` must be `body` parsed strictly. The result is parsed again and
/// compared with `raw` plus the replacements before it is returned.
pub fn replace_strings(
    body: &[u8],
    raw: &Value,
    replacements: &BTreeMap<String, String>,
) -> Result<Vec<u8>, RedactError> {
    if replacements.is_empty() {
        return Ok(body.to_vec());
    }
    let located = locate(body, replacements)?;
    if located.len() != replacements.len() {
        return Err(RedactError::Rewrite);
    }

    let mut out = Vec::with_capacity(body.len());
    let mut copied = 0;
    for (range, pointer) in &located {
        let text = replacements.get(pointer).ok_or(RedactError::Rewrite)?;
        let encoded = serde_json::to_string(text).map_err(|_| RedactError::Rewrite)?;
        out.extend_from_slice(body.get(copied..range.start).ok_or(RedactError::Rewrite)?);
        out.extend_from_slice(encoded.as_bytes());
        copied = range.end;
    }
    out.extend_from_slice(body.get(copied..).ok_or(RedactError::Rewrite)?);

    // The locator is a second reader of the JSON: check its work with the strict parser.
    let mut expected = raw.clone();
    for (pointer, text) in replacements {
        *expected.pointer_mut(pointer).ok_or(RedactError::Mismatch)? = Value::String(text.clone());
    }
    if parse_strict(&out).map_err(|_| RedactError::Mismatch)? != expected {
        return Err(RedactError::Mismatch);
    }
    Ok(out)
}

/// One merged span of a text and what replaces it.
struct Group {
    span: Range<usize>,
    class: DataClass,
    /// Invisible text found in the text itself is removed, not replaced (ADR 0013).
    remove: bool,
}

/// The new text of every affected `ScanText`, by pointer.
fn redacted_texts(
    texts: &[ScanText],
    spans: &[Finding],
) -> Result<BTreeMap<String, String>, RedactError> {
    let by_pointer: HashMap<&str, &ScanText> =
        texts.iter().map(|t| (t.pointer.as_str(), t)).collect();
    let mut spans_of: HashMap<&str, Vec<&Finding>> = HashMap::new();
    for finding in spans {
        let text = by_pointer
            .get(finding.pointer.as_str())
            .ok_or(RedactError::Span)?;
        let Range { start, end } = finding.span;
        let fits = start < end
            && end <= text.text.len()
            && text.text.is_char_boundary(start)
            && text.text.is_char_boundary(end);
        if !fits {
            return Err(RedactError::Span);
        }
        spans_of.entry(&finding.pointer).or_default().push(finding);
    }

    // Texts outside `messages` first, then the messages, each in the parser's order, so a
    // conversation that grows at the end keeps the numbers of its earlier turns.
    let mut order: Vec<&ScanText> = texts
        .iter()
        .filter(|t| spans_of.contains_key(t.pointer.as_str()))
        .collect();
    order.sort_by_key(|t| t.pointer.starts_with("/messages/"));

    // The same text gets the same number. Values stay in memory: they are never logged.
    let mut numbers: HashMap<(DataClass, &str), usize> = HashMap::new();
    let mut counters: BTreeMap<DataClass, usize> = BTreeMap::new();
    let mut replacements = BTreeMap::new();
    for text in order {
        let findings = spans_of
            .get_mut(text.pointer.as_str())
            .ok_or(RedactError::Span)?;
        let mut pieces = Vec::new();
        for group in merge(findings) {
            let replacement = if group.remove {
                String::new()
            } else {
                let value = text.text.get(group.span.clone()).ok_or(RedactError::Span)?;
                let n = *numbers.entry((group.class, value)).or_insert_with(|| {
                    let counter = counters.entry(group.class).or_insert(0);
                    *counter += 1;
                    *counter
                });
                format!("[REDACTED:{}:{n}]", group.class)
            };
            pieces.push((group.span, replacement));
        }
        // Back to front, so earlier spans keep their positions (F.6.3).
        let mut redacted = text.text.clone();
        for (span, replacement) in pieces.iter().rev() {
            redacted.replace_range(span.clone(), replacement);
        }
        replacements.insert(text.pointer.clone(), redacted);
    }
    Ok(replacements)
}

/// Merges overlapping spans (F.6.1). A group takes the class of its longest finding, with
/// ties going to `DataClass` order. Touching spans stay apart.
fn merge(findings: &mut [&Finding]) -> Vec<Group> {
    findings.sort_by_key(|f| (f.span.start, f.span.end));
    let mut groups: Vec<(Group, usize)> = Vec::new();
    for finding in findings.iter() {
        let len = finding.span.end - finding.span.start;
        let removable = finding.class == DataClass::InvisibleText && finding.via.is_empty();
        if let Some((group, longest)) = groups.last_mut()
            && finding.span.start < group.span.end
        {
            group.span.end = group.span.end.max(finding.span.end);
            group.remove &= removable;
            if len > *longest || (len == *longest && finding.class < group.class) {
                group.class = finding.class;
                *longest = len;
            }
            continue;
        }
        groups.push((
            Group {
                span: finding.span.clone(),
                class: finding.class,
                remove: removable,
            },
            len,
        ));
    }
    groups.into_iter().map(|(group, _)| group).collect()
}

/// The byte range, quotes included, of every string value whose pointer is in `targets`, in
/// the order they appear in `body`.
fn locate(
    body: &[u8],
    targets: &BTreeMap<String, String>,
) -> Result<Vec<(Range<usize>, String)>, RedactError> {
    let mut locator = Locator {
        bytes: body,
        pos: 0,
        targets,
        found: Vec::new(),
    };
    let mut pointer = String::new();
    locator.value(&mut pointer, 0)?;
    locator.skip_whitespace();
    if locator.pos != body.len() {
        return Err(RedactError::Rewrite);
    }
    Ok(locator.found)
}

/// Walks JSON that the strict parser has already accepted. Anything unexpected is an error,
/// never a guess.
struct Locator<'a> {
    bytes: &'a [u8],
    pos: usize,
    targets: &'a BTreeMap<String, String>,
    found: Vec<(Range<usize>, String)>,
}

impl Locator<'_> {
    fn value(&mut self, pointer: &mut String, depth: usize) -> Result<(), RedactError> {
        if depth > MAX_DEPTH {
            return Err(RedactError::Rewrite);
        }
        self.skip_whitespace();
        match self.bytes.get(self.pos) {
            Some(b'{') => self.object(pointer, depth),
            Some(b'[') => self.array(pointer, depth),
            Some(b'"') => {
                let range = self.string()?;
                if self.targets.contains_key(pointer.as_str()) {
                    self.found.push((range, pointer.clone()));
                }
                Ok(())
            }
            Some(_) => self.scalar(),
            None => Err(RedactError::Rewrite),
        }
    }

    fn object(&mut self, pointer: &mut String, depth: usize) -> Result<(), RedactError> {
        self.pos += 1;
        self.skip_whitespace();
        if self.bytes.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            self.skip_whitespace();
            let key_range = self.string()?;
            let key_token = self.bytes.get(key_range).ok_or(RedactError::Rewrite)?;
            // Keys are unescaped by serde_json, the same reader that built the pointers.
            let key: String =
                serde_json::from_slice(key_token).map_err(|_| RedactError::Rewrite)?;
            self.skip_whitespace();
            self.expect(b':')?;
            with_segment(pointer, &key, |pointer| self.value(pointer, depth + 1))?;
            self.skip_whitespace();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return Err(RedactError::Rewrite),
            }
        }
    }

    fn array(&mut self, pointer: &mut String, depth: usize) -> Result<(), RedactError> {
        self.pos += 1;
        self.skip_whitespace();
        if self.bytes.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(());
        }
        let mut index = 0usize;
        loop {
            with_segment(pointer, &index.to_string(), |pointer| {
                self.value(pointer, depth + 1)
            })?;
            index += 1;
            self.skip_whitespace();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return Err(RedactError::Rewrite),
            }
        }
    }

    /// A string token, quotes included. An escape always covers the byte after the
    /// backslash, so an escaped quote never ends the string.
    fn string(&mut self) -> Result<Range<usize>, RedactError> {
        let start = self.pos;
        if self.bytes.get(start) != Some(&b'"') {
            return Err(RedactError::Rewrite);
        }
        let mut i = start + 1;
        loop {
            match self.bytes.get(i) {
                Some(b'\\') => i += 2,
                Some(b'"') => {
                    self.pos = i + 1;
                    return Ok(start..self.pos);
                }
                Some(_) => i += 1,
                None => return Err(RedactError::Rewrite),
            }
        }
    }

    /// A number, `true`, `false` or `null`: everything up to the next delimiter.
    fn scalar(&mut self) -> Result<(), RedactError> {
        let start = self.pos;
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| !matches!(b, b',' | b']' | b'}' | b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.pos += 1;
        }
        if self.pos == start {
            return Err(RedactError::Rewrite);
        }
        Ok(())
    }

    fn expect(&mut self, byte: u8) -> Result<(), RedactError> {
        if self.bytes.get(self.pos) == Some(&byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(RedactError::Rewrite)
        }
    }

    fn skip_whitespace(&mut self) {
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.pos += 1;
        }
    }
}
