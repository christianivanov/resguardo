//! Candidate windows of ADR 0010: runs of whole groups of ASCII letters and digits.
//!
//! The `regex` crate has no look-around, so "not part of a longer number or word" is
//! enforced here: a candidate is made of whole groups, and a group is never split.

use std::collections::VecDeque;
use std::ops::Range;

use crate::scanner::Detection;

/// Characters that may join two groups of one chunk. Each rule accepts a subset.
const CHUNK_SEPARATORS: &[u8] = b" .-";

/// A run of ASCII letters and digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Group {
    pub start: usize,
    pub end: usize,
    /// The single separator before this group, when it continues the previous group's chunk.
    pub joined_by: Option<u8>,
}

/// The groups of `text`, in order. Lazy, so a long text is never copied into a list.
pub(crate) fn groups(text: &str) -> impl Iterator<Item = Group> + '_ {
    let bytes = text.as_bytes();
    let mut pos = 0;
    let mut previous_end: Option<usize> = None;
    std::iter::from_fn(move || {
        while pos < bytes.len() && !bytes[pos].is_ascii_alphanumeric() {
            pos += 1;
        }
        if pos >= bytes.len() {
            return None;
        }
        let start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_alphanumeric() {
            pos += 1;
        }
        // Joined only if exactly one separator lies between this group and the previous one.
        let joined_by = match previous_end {
            Some(end) if end + 1 == start => bytes
                .get(end)
                .copied()
                .filter(|b| CHUNK_SEPARATORS.contains(b)),
            _ => None,
        };
        previous_end = Some(pos);
        Some(Group {
            start,
            end: pos,
            joined_by,
        })
    })
}

/// A validator for one class, applied to windows of whole groups.
pub(crate) trait WindowRule {
    /// The longest value of the class without separators. Bounds the work per group.
    const MAX_LEN: usize;
    /// Separators this class accepts between the groups of one value.
    const SEPARATORS: &'static [u8];

    /// Checks one window. `compact` is the window without separators; `span` is its range in
    /// `text`.
    fn check(&self, text: &str, span: Range<usize>, compact: &[u8]) -> Option<Detection>;
}

/// Walks the groups of `text` from left to right. At each group, the longest window that
/// `rule` accepts is reported and the walk continues after it; otherwise it moves on by one
/// group (ADR 0010).
pub(crate) fn scan_windows<R: WindowRule>(rule: &R, text: &str, out: &mut Vec<Detection>) {
    let bytes = text.as_bytes();
    let mut source = groups(text);
    // Groups read but not yet passed. A window has at most MAX_LEN groups, so this never
    // holds more than MAX_LEN + 1.
    let mut pending: VecDeque<Group> = VecDeque::new();
    let mut compact: Vec<u8> = Vec::with_capacity(R::MAX_LEN);
    loop {
        if pending.is_empty() {
            match source.next() {
                Some(group) => pending.push_back(group),
                None => return,
            }
        }
        compact.clear();
        let mut best: Option<(usize, Detection)> = None;
        let mut taken = 0;
        loop {
            if taken == pending.len() {
                match source.next() {
                    Some(group) => pending.push_back(group),
                    None => break,
                }
            }
            let Some(&group) = pending.get(taken) else {
                break;
            };
            if taken > 0
                && !group
                    .joined_by
                    .is_some_and(|sep| R::SEPARATORS.contains(&sep))
            {
                break;
            }
            let Some(part) = bytes.get(group.start..group.end) else {
                break;
            };
            if compact.len() + part.len() > R::MAX_LEN {
                break;
            }
            compact.extend_from_slice(part);
            taken += 1;
            let first_start = pending.front().map_or(group.start, |g| g.start);
            if let Some(found) = rule.check(text, first_start..group.end, &compact) {
                best = Some((taken, found));
            }
        }
        match best {
            Some((used, found)) => {
                out.push(found);
                pending.drain(..used);
            }
            None => {
                pending.pop_front();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(text: &str) -> Vec<(Range<usize>, Option<u8>)> {
        groups(text)
            .map(|g| (g.start..g.end, g.joined_by))
            .collect()
    }

    #[test]
    fn single_separators_join_groups_and_anything_else_splits_chunks() {
        assert_eq!(
            spans("ab 12.c-d  e/f"),
            vec![
                (0..2, None),
                (3..5, Some(b' ')),
                (6..7, Some(b'.')),
                (8..9, Some(b'-')),
                (11..12, None),
                (13..14, None),
            ]
        );
    }

    #[test]
    fn non_ascii_characters_split_groups() {
        assert_eq!(spans("añb"), vec![(0..1, None), (3..4, None)]);
    }

    #[test]
    fn empty_and_separator_only_texts_have_no_groups() {
        assert_eq!(spans(""), vec![]);
        assert_eq!(spans(" .- "), vec![]);
    }
}
