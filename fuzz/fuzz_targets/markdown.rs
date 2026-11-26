//! Response controls on arbitrary text, split at arbitrary points (M4.5).
//!
//! Properties: no panic; the same output wherever the text is split; never more held than
//! the hold limit plus a few characters; and no complete remote image left in the output,
//! checked by an independent detector without the hold limit.
#![no_main]

use libfuzzer_sys::fuzz_target;
use resguardo_proto::markdown::HOLD_LIMIT;
use resguardo_proto::{MarkdownFilter, ResponseControls};

/// Whether the byte at `pos` follows an odd number of backslashes.
fn escaped(bytes: &[u8], pos: usize) -> bool {
    bytes[..pos].iter().rev().take_while(|&&b| b == b'\\').count() % 2 == 1
}

/// The index of the byte that closes the bracket or parenthesis opened at `open`.
fn closing(bytes: &[u8], open: usize, opener: u8, closer: u8) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 1,
            b if b == opener => depth += 1,
            b if b == closer && depth == 0 => return Some(i),
            b if b == closer => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    None
}

/// A destination that a browser would fetch from another host: `http` or `https`, or
/// protocol-relative, read with the WHATWG URL parser (which strips leading control
/// characters). Like CommonMark, a destination ends at the first space.
fn is_remote(destination: &str) -> bool {
    let trimmed = destination.trim_start();
    let token = match trimmed.strip_prefix('<') {
        Some(rest) => rest.split('>').next().unwrap_or_default(),
        None => trimmed.split_whitespace().next().unwrap_or_default(),
    };
    // The WHATWG parser's first steps: tabs and newlines removed, controls and spaces
    // trimmed.
    let cleaned: String = token.chars().filter(|c| !matches!(c, '\t' | '\n' | '\r')).collect();
    let token = cleaned.trim_matches(|c: char| c <= ' ');
    let relative = ["//", "\\\\", "/\\", "\\/"]
        .iter()
        .any(|prefix| token.starts_with(prefix));
    let parsed = if relative {
        url::Url::parse(&format!("https:{token}"))
    } else {
        url::Url::parse(token)
    };
    parsed.is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
}

/// Every complete `![alt](destination)` with a remote destination, however long.
fn remote_images(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for open in 1..bytes.len() {
        if bytes[open] != b'[' || bytes[open - 1] != b'!' || escaped(bytes, open - 1) || escaped(bytes, open) {
            continue;
        }
        let Some(close) = closing(bytes, open, b'[', b']') else {
            continue;
        };
        if bytes.get(close + 1) != Some(&b'(') {
            continue;
        }
        let Some(end) = closing(bytes, close + 1, b'(', b')') else {
            continue;
        };
        let destination = String::from_utf8_lossy(&bytes[close + 2..end]).into_owned();
        if is_remote(&destination) {
            found.push(destination);
        }
    }
    found
}

fuzz_target!(|data: &[u8]| {
    let [a, rest @ ..] = data else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let controls = ResponseControls::new(true, true, ["docs.example.com".to_owned()]);
    let whole = controls.apply(text);

    let mut split = usize::from(*a).min(text.len());
    while !text.is_char_boundary(split) {
        split -= 1;
    }
    let mut filter = MarkdownFilter::new(&controls);
    let mut out = filter.push(&text[..split]);
    assert!(filter.held() <= HOLD_LIMIT + 8);
    out.push_str(&filter.push(&text[split..]));
    assert!(filter.held() <= HOLD_LIMIT + 8);
    out.push_str(&filter.finish());
    assert_eq!(out, whole);

    let left = remote_images(&whole);
    assert!(left.is_empty(), "remote images left: {left:?}");
});
