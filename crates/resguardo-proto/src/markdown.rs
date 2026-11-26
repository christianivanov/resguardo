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

/// What the controls removed from a text, for the receipt (ADR 0017). Counts only: a URL
/// may carry the very data an injection tried to send out, so it is never kept.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Removals {
    /// Remote images replaced by the placeholder.
    pub images: u64,
    /// Links that kept only their text.
    pub links: u64,
}

impl Removals {
    pub fn is_empty(&self) -> bool {
        self.images == 0 && self.links == 0
    }

    /// Adds the counts of `other`.
    pub fn add(&mut self, other: Self) {
        self.images = self.images.saturating_add(other.images);
        self.links = self.links.saturating_add(other.links);
    }
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
    /// `removed`: what was removed inside `replacement`.
    Complete {
        end: usize,
        replacement: String,
        removed: Removals,
    },
    /// A remote image to remove: its placeholder depends on the next character.
    RemovedImage { end: usize },
    /// Brackets closed at `close` but not followed by `(`.
    NotAConstruct { close: usize },
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
        let (out, held, after_close) = self.process(
            &buf,
            false,
            state.after_bang,
            state.after_close,
            &mut state.removed,
        );
        state.held = held;
        state.after_bang = ends_in_bang(&out, state.after_bang);
        state.after_close = after_close;
        out
    }

    /// The text ended: resolves and returns whatever `state` held.
    pub fn finish(&self, state: &mut MarkdownState) -> String {
        let buf = std::mem::take(&mut state.held);
        let (out, _, after_close) = self.process(
            &buf,
            true,
            state.after_bang,
            state.after_close,
            &mut state.removed,
        );
        state.after_bang = ends_in_bang(&out, state.after_bang);
        state.after_close = after_close;
        out
    }

    /// The controls applied to the content between a construct's brackets. If the result
    /// does not have balanced brackets (an image removed up to the content's end took a
    /// `]` with it, for example), its brackets are escaped, so the construct's own `]`
    /// still closes it and nothing new can form around it. Returns what was removed in it.
    fn contained(&self, text: &str) -> (String, Removals) {
        let (out, removed) = self.apply_counted(text);
        if balanced(&out) {
            (out, removed)
        } else {
            (escape_brackets(&out), removed)
        }
    }

    /// Applies the controls to a complete text.
    pub fn apply(&self, text: &str) -> String {
        self.apply_counted(text).0
    }

    /// Applies the controls to a complete text, and says what they removed.
    pub fn apply_counted(&self, text: &str) -> (String, Removals) {
        let mut filter = MarkdownFilter::new(self);
        let mut out = filter.push(text);
        out.push_str(&filter.finish());
        (out, filter.removed())
    }

    /// Returns what can be released and what must be held. With `at_end`, nothing is held.
    /// `bang_before`: the text released before `buf` ends in a plain `!`. `close_before`: it
    /// ends in a `]` the controls wrote. Returns the released text, the held text and the
    /// new `close_before`. What is removed in the released text is added to `removed`;
    /// what is held is counted when a later call releases it.
    fn process(
        &self,
        buf: &str,
        at_end: bool,
        bang_before: bool,
        close_before: bool,
        removed: &mut Removals,
    ) -> (String, String, bool) {
        let bytes = buf.as_bytes();
        let mut out = String::with_capacity(buf.len());
        let mut close = close_before;
        let mut i = 0;
        loop {
            let Some(open) = next_open(bytes, i) else {
                append(&mut out, &mut close, false, slice(buf, i, bytes.len()));
                if at_end {
                    return (out, String::new(), close);
                }
                // What comes next is read together with the end of this text.
                return with_close(hold(out, ""), close);
            };
            let image = open > 0 && bytes.get(open - 1) == Some(&b'!') && !escaped(bytes, open - 1);
            let start = if image { open - 1 } else { open };
            append(&mut out, &mut close, false, slice(buf, i, start));
            let removes_image = image && self.strip_remote_images;
            match self.parse(buf, start, open, image) {
                Parsed::Complete {
                    end,
                    replacement,
                    removed: inside,
                } => {
                    append(&mut out, &mut close, true, &replacement);
                    removed.add(inside);
                    i = end;
                }
                Parsed::RemovedImage { end } => {
                    match placeholder(ends_in_bang(&out, bang_before), bytes, end, at_end) {
                        Some(text) => {
                            append(&mut out, &mut close, true, text);
                            removed.images = removed.images.saturating_add(1);
                            i = end;
                        }
                        None => {
                            return with_close(hold(out, slice(buf, start, bytes.len())), close);
                        }
                    }
                }
                // The brackets stay as one unit around their controlled content. Changing the
                // content one construct at a time could make another `]` close them, and a
                // new link or image appear (found by the fuzzer). The content has balanced
                // brackets, and so do its replacements, so the same `]` still closes them.
                Parsed::NotAConstruct { close: bracket } => {
                    append(&mut out, &mut close, false, slice(buf, start, open + 1));
                    let (content, inside) = self.contained(slice(buf, open + 1, bracket));
                    append(&mut out, &mut close, false, &content);
                    removed.add(inside);
                    append(&mut out, &mut close, true, "]");
                    i = bracket + 1;
                }
                Parsed::Incomplete if !at_end => {
                    return with_close(hold(out, slice(buf, start, bytes.len())), close);
                }
                // An image that never closes is removed, so a long URL cannot get through.
                Parsed::Incomplete if removes_image => {
                    let text =
                        placeholder(ends_in_bang(&out, bang_before), bytes, bytes.len(), true)
                            .unwrap_or(IMAGE_REMOVED);
                    append(&mut out, &mut close, true, text);
                    removed.images = removed.images.saturating_add(1);
                    i = bytes.len();
                }
                Parsed::Overflow if removes_image => {
                    let end = limit_end(buf, start);
                    match placeholder(ends_in_bang(&out, bang_before), bytes, end, at_end) {
                        Some(text) => {
                            append(&mut out, &mut close, true, text);
                            removed.images = removed.images.saturating_add(1);
                            i = end;
                        }
                        None => {
                            return with_close(hold(out, slice(buf, start, bytes.len())), close);
                        }
                    }
                }
                // Anything else is released as text, and scanning goes on after its `[`.
                Parsed::Incomplete | Parsed::Overflow => {
                    append(&mut out, &mut close, false, slice(buf, start, open + 1));
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
        let (replacement, removed) = if image {
            let local = matches!(
                classify(destination),
                Destination::Local | Destination::Data
            );
            // A renderer may not accept it as an image (a destination with a space, say) and
            // read its parts as Markdown. A destination the controls would change is not a
            // real one: the image is removed. (Only the result matters here: what this check
            // removes is never released, so it is not counted.)
            let tampered = self.apply(destination) != destination;
            if (self.strip_remote_images && !local) || tampered {
                return Parsed::RemovedImage { end: end + 1 };
            }
            let (inner, removed) = self.contained(text);
            (format!("![{inner}]({destination})"), removed)
        } else {
            // The link text may hold an image of its own.
            let (inner, mut removed) = self.contained(text);
            let allowed = match classify(destination) {
                Destination::Local => true,
                Destination::Web(Some(host)) => self.allowed_hosts.contains(&host),
                Destination::Web(None) | Destination::Data | Destination::Other => false,
            };
            // As for images: a destination the controls would change is not a real one.
            let tampered = self.apply(destination) != destination;
            if (self.strip_links_outside && !allowed) || tampered {
                removed.links = removed.links.saturating_add(1);
                (escape_link_text(&inner), removed)
            } else {
                (format!("[{inner}]({destination})"), removed)
            }
        };
        Parsed::Complete {
            end: end + 1,
            replacement,
            removed,
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

/// Appends `text`. `close` says whether the output ends in a `]` the controls wrote (the
/// end of a bracket unit or of the placeholder). A `(` right after such a `]` is escaped:
/// a replacement can put the two next to each other, and `](` would turn those brackets
/// into a link or an image (found by the fuzzer). A `]` from unchanged text keeps what
/// followed it in the input, so it never needs this.
fn append(out: &mut String, close: &mut bool, ours: bool, text: &str) {
    if text.is_empty() {
        return;
    }
    if *close && text.starts_with('(') {
        out.push('\\');
    }
    out.push_str(text);
    *close = ours && out.ends_with(']') && !escaped(out.as_bytes(), out.len() - 1);
}

/// Adds the `close` state to what [`hold`] returns.
fn with_close((out, held): (String, String), close: bool) -> (String, String, bool) {
    (out, held, close)
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
    after_close: bool,
    /// What was removed in the text released so far.
    removed: Removals,
}

impl MarkdownState {
    /// Bytes held, never more than [`HOLD_LIMIT`] plus a few characters.
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// What the controls removed in the text released so far (ADR 0017).
    pub fn removed(&self) -> Removals {
        self.removed
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

    /// What the controls removed in the text released so far (ADR 0017).
    pub fn removed(&self) -> Removals {
        self.state.removed()
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
