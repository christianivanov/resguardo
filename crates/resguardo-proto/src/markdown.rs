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
    NotAConstruct,
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

    /// Applies the controls to a complete text.
    pub fn apply(&self, text: &str) -> String {
        let mut filter = MarkdownFilter::new(self);
        let mut out = filter.push(text);
        out.push_str(&filter.finish());
        out
    }

    /// Returns what can be released and what must be held. With `at_end`, nothing is held.
    fn process(&self, buf: &str, at_end: bool) -> (String, String) {
        let bytes = buf.as_bytes();
        let mut out = String::with_capacity(buf.len());
        let mut i = 0;
        loop {
            let Some(open) = next_open(bytes, i) else {
                // A final `!` may be the start of an image whose `[` comes next.
                let last = bytes.len().wrapping_sub(1);
                if !at_end
                    && bytes.len() > i
                    && bytes.get(last) == Some(&b'!')
                    && !escaped(bytes, last)
                {
                    out.push_str(slice(buf, i, last));
                    return (out, "!".to_owned());
                }
                out.push_str(slice(buf, i, bytes.len()));
                return (out, String::new());
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
                Parsed::NotAConstruct => {
                    out.push_str(slice(buf, start, open + 1));
                    i = open + 1;
                }
                Parsed::Incomplete if !at_end => {
                    return (out, slice(buf, start, bytes.len()).to_owned());
                }
                // An image that never closes is removed, so a long URL cannot get through.
                Parsed::Incomplete if removes_image => {
                    out.push_str(IMAGE_REMOVED);
                    i = bytes.len();
                }
                Parsed::Overflow if removes_image => {
                    out.push_str(IMAGE_REMOVED);
                    i = limit_end(buf, start);
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
            return Parsed::NotAConstruct;
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
        let whole = slice(buf, start, end + 1);
        let replacement = if image {
            let local = matches!(
                classify(destination),
                Destination::Local | Destination::Data
            );
            if self.strip_remote_images && !local {
                IMAGE_REMOVED.to_owned()
            } else {
                whole.to_owned()
            }
        } else {
            // The link text may hold an image of its own.
            let inner = self.apply(text);
            let allowed = match classify(destination) {
                Destination::Local => true,
                Destination::Web(Some(host)) => self.allowed_hosts.contains(&host),
                Destination::Web(None) | Destination::Data | Destination::Other => false,
            };
            if self.strip_links_outside && !allowed {
                inner
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

/// Holds what may be the start of a construct between chunks of one text.
#[derive(Debug)]
pub struct MarkdownFilter<'a> {
    controls: &'a ResponseControls,
    pending: String,
}

impl<'a> MarkdownFilter<'a> {
    pub fn new(controls: &'a ResponseControls) -> Self {
        Self {
            controls,
            pending: String::new(),
        }
    }

    /// Adds text and returns what can be released now.
    pub fn push(&mut self, text: &str) -> String {
        let mut buf = std::mem::take(&mut self.pending);
        buf.push_str(text);
        let (out, pending) = self.controls.process(&buf, false);
        self.pending = pending;
        out
    }

    /// The text ended: resolves and returns whatever was held.
    pub fn finish(&mut self) -> String {
        let buf = std::mem::take(&mut self.pending);
        self.controls.process(&buf, true).0
    }

    /// Bytes held, never more than [`HOLD_LIMIT`] plus one character.
    pub fn held(&self) -> usize {
        self.pending.len()
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
