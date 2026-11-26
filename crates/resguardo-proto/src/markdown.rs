//! Response controls (design document, "Streaming"; ADR 0014): remote Markdown images are
//! replaced by `[image removed]`, and links to hosts outside a list keep only their text.
//! After a prompt injection, an image is the usual way to send data out: the client loads
//! its URL, with the data in the query, without a click.
//!
//! Text can arrive split across stream events, so [`MarkdownFilter`] holds a possible
//! construct from its `[` or `![`. What is decided about it depends only on the first
//! [`HOLD_LIMIT`] bytes from there, so the output is the same wherever the text is split,
//! and the work per candidate is bounded.

use std::collections::BTreeSet;

use resguardo_core::config::ResponseConfig;
use url::Url;

/// The longest construct held, from its `[` or `![` (Annex F.7).
pub const HOLD_LIMIT: usize = 512;

const IMAGE_REMOVED: &str = "[image removed]";
/// The placeholder when `(` follows it, so the two cannot form a link.
const IMAGE_REMOVED_ESCAPED: &str = r"\[image removed\]";

/// What the configuration asks for, built once.
#[derive(Debug, Clone)]
pub struct ResponseControls {
    strip_remote_images: bool,
    strip_links_outside: bool,
    allowed_hosts: BTreeSet<String>,
}

/// Where a Markdown destination points.
enum Destination {
    /// No scheme and no authority: `#part`, `/docs/a`, `img.png`.
    Local,
    Data,
    /// `http` or `https`, with its host as a browser reads it.
    Web(Option<String>),
    /// Any other scheme (`javascript:`, `mailto:`…) or an unreadable URL.
    Other,
}

/// How a possible construct at a `[` turned out.
enum Parsed {
    Complete {
        end: usize,
        replacement: String,
    },
    /// A remote image to remove: its placeholder depends on the next character.
    RemovedImage {
        end: usize,
    },
    /// Brackets closed at `close` but not followed by `(`.
    NotAConstruct {
        close: usize,
    },
    /// The text ended before the construct did, within the limit.
    Incomplete,
    /// [`HOLD_LIMIT`] bytes passed without the construct closing.
    Overflow,
}

impl ResponseControls {
    pub fn new(
        strip_remote_images: bool,
        strip_links_outside: bool,
        allowed_hosts: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            strip_remote_images,
            strip_links_outside,
            allowed_hosts: allowed_hosts
                .into_iter()
                .map(|host| host.to_ascii_lowercase())
                .collect(),
        }
    }

    pub fn from_config(config: &ResponseConfig) -> Self {
        Self::new(
            config.strip_remote_images,
            config.strip_links_outside,
            config.allowed_link_hosts.iter().cloned(),
        )
    }

    /// Adds `text` to what `state` holds from earlier chunks, returns what can be released
    /// now and keeps in `state` what must wait. For callers that keep one state per stream
    /// block; [`MarkdownFilter`] wraps it for a single text.
    pub fn push(&self, state: &mut MarkdownState, text: &str) -> String {
        let mut buf = std::mem::take(&mut state.held);
        buf.push_str(text);
        let (out, held) = self.process(&buf, false, state.after_bang);
        state.held = held;
        state.after_bang = ends_in_bang(&out, state.after_bang);
        out
    }

    /// The text ended: resolves and returns whatever `state` held.
    pub fn finish(&self, state: &mut MarkdownState) -> String {
        let buf = std::mem::take(&mut state.held);
        let (out, _) = self.process(&buf, true, state.after_bang);
        state.after_bang = ends_in_bang(&out, state.after_bang);
        out
    }

    /// The controls applied to the content between a construct's brackets. If the result
    /// does not have balanced brackets (an image removed up to the content's end took a
    /// `]` with it, for example), its brackets are escaped, so the construct's own `]`
    /// still closes it and nothing new can form around it.
    fn contained(&self, text: &str) -> String {
        let out = self.apply(text);
        if balanced(&out) {
            out
        } else {
            escape_brackets(&out)
        }
    }

    /// Applies the controls to a complete text.
    pub fn apply(&self, text: &str) -> String {
        let mut filter = MarkdownFilter::new(self);
        let mut out = filter.push(text);
        out.push_str(&filter.finish());
        out
    }

    /// Returns what can be released and what must be held. With `at_end`, nothing is held.
    /// `bang_before`: the text released before `buf` ends in a plain `!`.
    fn process(&self, buf: &str, at_end: bool, bang_before: bool) -> (String, String) {
        let bytes = buf.as_bytes();
        let mut out = String::with_capacity(buf.len());
        let mut i = 0;
        loop {
            let Some(open) = next_open(bytes, i) else {
                out.push_str(slice(buf, i, bytes.len()));
                if at_end {
                    return (out, String::new());
                }
                // What comes next is read together with the end of this text.
                return hold(out, "");
            };
            let image = open > 0 && bytes.get(open - 1) == Some(&b'!') && !escaped(bytes, open - 1);
            let start = if image { open - 1 } else { open };
            out.push_str(slice(buf, i, start));
            let removes_image = image && self.strip_remote_images;
            match self.parse(buf, start, open, image) {
                Parsed::Complete { end, replacement } => {
                    out.push_str(&replacement);
                    i = end;
                }
                Parsed::RemovedImage { end } => {
                    match placeholder(ends_in_bang(&out, bang_before), bytes, end, at_end) {
                        Some(text) => {
                            out.push_str(text);
                            i = end;
                        }
                        None => return hold(out, slice(buf, start, bytes.len())),
                    }
                }
                // The brackets stay as one unit around their controlled content. Changing the
                // content one construct at a time could make another `]` close them, and a
                // new link or image appear (found by the fuzzer). The content has balanced
                // brackets, and so do its replacements, so the same `]` still closes them.
                Parsed::NotAConstruct { close } => {
                    out.push_str(slice(buf, start, open + 1));
                    out.push_str(&self.contained(slice(buf, open + 1, close)));
                    out.push(']');
                    i = close + 1;
                }
                Parsed::Incomplete if !at_end => {
                    return hold(out, slice(buf, start, bytes.len()));
                }
                // An image that never closes is removed, so a long URL cannot get through.
                Parsed::Incomplete if removes_image => {
                    let text =
                        placeholder(ends_in_bang(&out, bang_before), bytes, bytes.len(), true)
                            .unwrap_or(IMAGE_REMOVED);
                    out.push_str(text);
                    i = bytes.len();
                }
                Parsed::Overflow if removes_image => {
                    let end = limit_end(buf, start);
                    match placeholder(ends_in_bang(&out, bang_before), bytes, end, at_end) {
                        Some(text) => {
                            out.push_str(text);
                            i = end;
                        }
                        None => return hold(out, slice(buf, start, bytes.len())),
                    }
                }
                // Anything else is released as text, and scanning goes on after its `[`.
                Parsed::Incomplete | Parsed::Overflow => {
                    out.push_str(slice(buf, start, open + 1));
                    i = open + 1;
                }
            }
        }
    }

    /// Reads `[text](destination)` from the `[` at `open`, within the hold limit.
    fn parse(&self, buf: &str, start: usize, open: usize, image: bool) -> Parsed {
        let bytes = buf.as_bytes();
        let limit = limit_end(buf, start);
        let beyond = |pos: usize| {
            if pos >= limit {
                Some(Parsed::Overflow)
            } else if pos >= bytes.len() {
                Some(Parsed::Incomplete)
            } else {
                None
            }
        };

        // The `]` that closes the text, with nested brackets balanced.
        let mut j = open + 1;
        let mut depth = 0usize;
        let close = loop {
            if let Some(end) = beyond(j) {
                return end;
            }
            match bytes.get(j) {
                Some(b'\\') => j += 2,
                Some(b'[') => {
                    depth += 1;
                    j += 1;
                }
                Some(b']') if depth == 0 => break j,
                Some(b']') => {
                    depth -= 1;
                    j += 1;
                }
                _ => j += 1,
            }
        };
        if let Some(end) = beyond(close + 1) {
            return end;
        }
        if bytes.get(close + 1) != Some(&b'(') {
            return Parsed::NotAConstruct { close };
        }

        // The `)` that closes the destination, with nested parentheses balanced.
        let mut m = close + 2;
        let mut depth = 0usize;
        let end = loop {
            if let Some(end) = beyond(m) {
                return end;
            }
            match bytes.get(m) {
                Some(b'\\') => m += 2,
                Some(b'(') => {
                    depth += 1;
                    m += 1;
                }
                Some(b')') if depth == 0 => break m,
                Some(b')') => {
                    depth -= 1;
                    m += 1;
                }
                _ => m += 1,
            }
        };

        let text = slice(buf, open + 1, close);
        let destination = slice(buf, close + 2, end);
        let replacement = if image {
            let local = matches!(
                classify(destination),
                Destination::Local | Destination::Data
            );
            // A renderer may not accept it as an image (a destination with a space, say) and
            // read its parts as Markdown. A destination the controls would change is not a
            // real one: the image is removed.
            let tampered = self.apply(destination) != destination;
            if (self.strip_remote_images && !local) || tampered {
                return Parsed::RemovedImage { end: end + 1 };
            }
            format!("![{}]({destination})", self.contained(text))
        } else {
            // The link text may hold an image of its own.
            let inner = self.contained(text);
            let allowed = match classify(destination) {
                Destination::Local => true,
                Destination::Web(Some(host)) => self.allowed_hosts.contains(&host),
                Destination::Web(None) | Destination::Data | Destination::Other => false,
            };
            // As for images: a destination the controls would change is not a real one.
            let tampered = self.apply(destination) != destination;
            if (self.strip_links_outside && !allowed) || tampered {
                escape_link_text(&inner)
            } else {
                format!("[{inner}]({destination})")
            }
        };
        Parsed::Complete {
            end: end + 1,
            replacement,
        }
    }
}

/// Returns what is released and what is held. The end of the released text that changes
/// how the held text reads is held with it:
/// - a plain `!`, which with a following `[` starts an image;
/// - otherwise one backslash if the text ends in an odd number of them, because it escapes
///   the next character (only the parity matters, so one is enough).
fn hold(mut out: String, held: &str) -> (String, String) {
    let mut kept = String::new();
    if out.ends_with('!') && !escaped(out.as_bytes(), out.len() - 1) {
        out.pop();
        kept.push('!');
    } else if escaped(out.as_bytes(), out.len()) {
        out.pop();
        kept.push('\\');
    }
    kept.push_str(held);
    (out, kept)
}

/// Whether the released text, `out` after whatever was released before it, ends in a plain
/// `!`. An empty `out` leaves the earlier answer.
fn ends_in_bang(out: &str, before: bool) -> bool {
    if out.is_empty() {
        before
    } else {
        out.ends_with('!') && !escaped(out.as_bytes(), out.len() - 1)
    }
}

/// The placeholder for an image removed up to `end`, escaped when `(` follows it or the
/// output so far ends in a plain `!`, so it can never read as a link or an image. `None` if
/// the next character has not arrived yet.
fn placeholder(after_bang: bool, bytes: &[u8], end: usize, at_end: bool) -> Option<&'static str> {
    match bytes.get(end) {
        None if !at_end => None,
        Some(b'(') => Some(IMAGE_REMOVED_ESCAPED),
        _ if after_bang => Some(IMAGE_REMOVED_ESCAPED),
        _ => Some(IMAGE_REMOVED),
    }
}

/// Whether the unescaped brackets of `text` pair up, never closing more than they opened.
fn balanced(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if escaped(bytes, i) {
            continue;
        }
        match b {
            b'[' => depth += 1,
            b']' if depth == 0 => return false,
            b']' => depth -= 1,
            _ => {}
        }
    }
    depth == 0
}

/// `text` with a backslash before every unescaped bracket.
fn escape_brackets(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len() + 8);
    for (i, c) in text.char_indices() {
        if matches!(c, '[' | ']') && !escaped(bytes, i) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The text of a removed link, with Markdown that could start a new link or image made
/// literal: backslashes and brackets escaped, and a final `!` too.
fn escape_link_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if matches!(c, '\\' | '[' | ']') {
            out.push('\\');
        }
        out.push(c);
    }
    if out.ends_with('!') {
        out.insert(out.len() - 1, '\\');
    }
    out
}

/// What the controls keep between chunks of one text: the possible start of a construct,
/// and whether the text released so far ends in a plain `!` (a removed image right after
/// it gets the escaped placeholder, wherever the text was split).
#[derive(Debug, Clone, Default)]
pub struct MarkdownState {
    held: String,
    after_bang: bool,
}

impl MarkdownState {
    /// Bytes held, never more than [`HOLD_LIMIT`] plus a few characters.
    pub fn held(&self) -> usize {
        self.held.len()
    }
}

/// The controls applied to one text that arrives in chunks.
#[derive(Debug)]
pub struct MarkdownFilter<'a> {
    controls: &'a ResponseControls,
    state: MarkdownState,
}

impl<'a> MarkdownFilter<'a> {
    pub fn new(controls: &'a ResponseControls) -> Self {
        Self {
            controls,
            state: MarkdownState::default(),
        }
    }

    /// Adds text and returns what can be released now.
    pub fn push(&mut self, text: &str) -> String {
        self.controls.push(&mut self.state, text)
    }

    /// The text ended: resolves and returns whatever was held.
    pub fn finish(&mut self) -> String {
        self.controls.finish(&mut self.state)
    }

    /// Bytes held, never more than [`HOLD_LIMIT`] plus a few characters.
    pub fn held(&self) -> usize {
        self.state.held()
    }
}

/// The next `[` at or after `from` that is not escaped by a backslash.
fn next_open(bytes: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while let Some(offset) = bytes.get(i..)?.iter().position(|&b| b == b'[') {
        let at = i + offset;
        if !escaped(bytes, at) {
            return Some(at);
        }
        i = at + 1;
    }
    None
}

/// Whether the byte at `pos` follows an odd number of backslashes.
fn escaped(bytes: &[u8], pos: usize) -> bool {
    let backslashes = bytes
        .get(..pos)
        .unwrap_or_default()
        .iter()
        .rev()
        .take_while(|&&b| b == b'\\')
        .count();
    backslashes % 2 == 1
}

/// The first char boundary at or after `start + HOLD_LIMIT`.
fn limit_end(buf: &str, start: usize) -> usize {
    let mut end = start.saturating_add(HOLD_LIMIT);
    while end < buf.len() && !buf.is_char_boundary(end) {
        end += 1;
    }
    end
}

/// `buf[from..to]`, or an empty string if that is not a valid range. Every position used
/// is an ASCII byte or a char boundary, so the fallback is never taken in practice.
fn slice(buf: &str, from: usize, to: usize) -> &str {
    buf.get(from..to.min(buf.len())).unwrap_or_default()
}

/// Reads a destination the way a browser does (WHATWG URL, through the `url` crate), so
/// `https://allowed@attacker.test`, `//attacker.test` and backslashes resolve to the host
/// that would really be contacted.
fn classify(destination: &str) -> Destination {
    let trimmed = destination.trim_start();
    let url = match trimmed.strip_prefix('<') {
        Some(rest) => rest.split('>').next().unwrap_or_default(),
        None => trimmed.split_whitespace().next().unwrap_or_default(),
    };
    // As a browser does before anything else (WHATWG URL): remove tabs and newlines
    // anywhere, and strip leading and trailing control characters and spaces. Otherwise
    // "\u{1}//attacker.test" would look local here and be remote there.
    let cleaned: String = url
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let url = cleaned.trim_matches(|c: char| c <= ' ');
    let protocol_relative = ["//", "\\\\", "/\\", "\\/"]
        .iter()
        .any(|prefix| url.starts_with(prefix));
    let parsed = if protocol_relative {
        Url::parse(&format!("https:{url}"))
    } else {
        Url::parse(url)
    };
    match parsed {
        Ok(url) => match url.scheme() {
            "http" | "https" => Destination::Web(
                url.host_str()
                    .map(|host| host.trim_end_matches('.').to_ascii_lowercase()),
            ),
            "data" => Destination::Data,
            _ => Destination::Other,
        },
        Err(url::ParseError::RelativeUrlWithoutBase) => Destination::Local,
        Err(_) => Destination::Other,
    }
}
