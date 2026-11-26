//! Steps 1 and 2 of Annex F.1: NFKC character by character and removal of invisible
//! characters (F.3), keeping a map from the normalized text back to the original.

use std::ops::Range;

use unicode_normalization::UnicodeNormalization;

/// Kinds of invisible characters removed and reported (Annex F.3, ADR 0008).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum InvisibleKind {
    /// Zero-width space, joiners, word joiner, invisible operators, byte order mark.
    ZeroWidth,
    /// Directional marks, embeddings, overrides and isolates.
    Bidi,
    /// The tag block, which can spell out hidden ASCII.
    Tag,
}

impl InvisibleKind {
    pub(crate) fn of(c: char) -> Option<Self> {
        match c {
            '\u{200B}'..='\u{200D}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}' => {
                Some(InvisibleKind::ZeroWidth)
            }
            '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => {
                Some(InvisibleKind::Bidi)
            }
            '\u{E0000}'..='\u{E007F}' => Some(InvisibleKind::Tag),
            _ => None,
        }
    }

    pub(crate) fn rule(self) -> &'static str {
        match self {
            InvisibleKind::ZeroWidth => "invisible_text.zero_width",
            InvisibleKind::Bidi => "invisible_text.bidi",
            InvisibleKind::Tag => "invisible_text.tag",
        }
    }
}

/// Consecutive invisible characters of one kind, as a byte range of the input text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InvisibleRun {
    pub kind: InvisibleKind,
    pub span: Range<usize>,
}

/// The text detectors read, with the way back to the input.
#[derive(Debug)]
pub(crate) struct Normalized {
    pub text: String,
    pub map: PositionMap,
    pub invisible: Vec<InvisibleRun>,
}

/// Normalizes `input`: NFKC per character, invisible characters removed and recorded.
///
/// NFKC per character is not NFKC of the whole string (combining sequences are not
/// recomposed), but it folds what matters to detectors (full-width forms, ligatures,
/// compatibility digits) and keeps the map simple (Annex F.1).
pub(crate) fn normalize(input: &str) -> Normalized {
    let mut text = String::with_capacity(input.len());
    let mut map = PositionMap::default();
    let mut invisible: Vec<InvisibleRun> = Vec::new();
    let mut expansion = String::new();

    for (start, c) in input.char_indices() {
        let original = start..start + c.len_utf8();
        if let Some(kind) = InvisibleKind::of(c) {
            push_invisible(&mut invisible, kind, original);
            continue;
        }
        // ASCII is unchanged by NFKC.
        if c.is_ascii() {
            map.push_identity(text.len(), original);
            text.push(c);
            continue;
        }
        expansion.clear();
        for folded in c.nfkc() {
            match InvisibleKind::of(folded) {
                Some(kind) => push_invisible(&mut invisible, kind, original.clone()),
                None => expansion.push(folded),
            }
        }
        if expansion.is_empty() {
            continue;
        }
        if expansion.len() == c.len_utf8() && expansion.starts_with(c) {
            map.push_identity(text.len(), original);
        } else {
            map.push_changed(text.len(), expansion.len(), original);
        }
        text.push_str(&expansion);
    }
    Normalized {
        text,
        map,
        invisible,
    }
}

fn push_invisible(runs: &mut Vec<InvisibleRun>, kind: InvisibleKind, span: Range<usize>) {
    if let Some(last) = runs.last_mut()
        && last.kind == kind
        && last.span.end >= span.start
    {
        last.span.end = last.span.end.max(span.end);
        return;
    }
    runs.push(InvisibleRun { kind, span });
}

/// Maps byte ranges of the normalized text to byte ranges of the original.
///
/// Stored as segments, not one entry per byte: a run of unchanged text is one segment, and
/// each character NFKC changed is its own. The memory used grows with the number of changed
/// characters, not with the length of the text.
#[derive(Debug, Default)]
pub(crate) struct PositionMap {
    segments: Vec<Segment>,
    /// Length of the normalized text.
    len: usize,
}

#[derive(Debug, Clone, Copy)]
struct Segment {
    /// Where the segment starts in the normalized text. Its end is the next segment's start.
    normalized_start: usize,
    original_start: usize,
    original_end: usize,
    /// Unchanged text: bytes correspond one to one. Otherwise, every byte of the segment
    /// comes from the whole original character.
    identity: bool,
}

impl PositionMap {
    fn push_identity(&mut self, normalized_start: usize, original: Range<usize>) {
        let added = original.len();
        if let Some(last) = self.segments.last_mut()
            && last.identity
            && last.original_end == original.start
        {
            last.original_end = original.end;
        } else {
            self.segments.push(Segment {
                normalized_start,
                original_start: original.start,
                original_end: original.end,
                identity: true,
            });
        }
        self.len = normalized_start + added;
    }

    fn push_changed(
        &mut self,
        normalized_start: usize,
        normalized_len: usize,
        original: Range<usize>,
    ) {
        self.segments.push(Segment {
            normalized_start,
            original_start: original.start,
            original_end: original.end,
            identity: false,
        });
        self.len = normalized_start + normalized_len;
    }

    /// The original bytes behind `normalized`, or `None` if the range is empty or outside the
    /// normalized text. A range that starts or ends inside the expansion of one character
    /// widens to that whole character.
    pub(crate) fn to_original(&self, normalized: Range<usize>) -> Option<Range<usize>> {
        if normalized.start >= normalized.end || normalized.end > self.len {
            return None;
        }
        let first = self.segment_at(normalized.start)?;
        let last = self.segment_at(normalized.end - 1)?;
        let start = if first.identity {
            first.original_start + (normalized.start - first.normalized_start)
        } else {
            first.original_start
        };
        let end = if last.identity {
            last.original_start + (normalized.end - last.normalized_start)
        } else {
            last.original_end
        };
        (start < end).then_some(start..end)
    }

    /// The segment holding byte `position` of the normalized text.
    fn segment_at(&self, position: usize) -> Option<Segment> {
        let index = self
            .segments
            .partition_point(|s| s.normalized_start <= position)
            .checked_sub(1)?;
        self.segments.get(index).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original_of(input: &str, normalized: Range<usize>) -> Option<Range<usize>> {
        normalize(input).map.to_original(normalized)
    }

    #[test]
    fn ascii_is_unchanged_and_maps_one_to_one() {
        let n = normalize("key AKIA");
        assert_eq!(n.text, "key AKIA");
        assert!(n.invisible.is_empty());
        assert_eq!(n.map.segments.len(), 1);
        assert_eq!(n.map.to_original(4..8), Some(4..8));
    }

    #[test]
    fn full_width_characters_fold_and_map_back() {
        // Each full-width letter is 3 bytes and folds to 1.
        let input = "ＡＫＩＡ12";
        let n = normalize(input);
        assert_eq!(n.text, "AKIA12");
        assert_eq!(n.map.to_original(0..4), Some(0..12));
        assert_eq!(n.map.to_original(1..2), Some(3..6));
        assert_eq!(n.map.to_original(3..6), Some(9..14));
    }

    #[test]
    fn a_span_inside_an_expansion_widens_to_the_whole_character() {
        // U+FB01 LATIN SMALL LIGATURE FI is 3 bytes and folds to "fi".
        let input = "\u{FB01}x";
        assert_eq!(normalize(input).text, "fix");
        assert_eq!(original_of(input, 1..2), Some(0..3));
        assert_eq!(original_of(input, 1..3), Some(0..4));
    }

    #[test]
    fn unchanged_non_ascii_is_identity() {
        let n = normalize("año é");
        assert_eq!(n.text, "año é");
        assert_eq!(n.map.segments.len(), 1);
        assert_eq!(n.map.to_original(1..3), Some(1..3));
    }

    #[test]
    fn invisible_characters_are_removed_and_recorded() {
        let input = "gh\u{200B}p_";
        let n = normalize(input);
        assert_eq!(n.text, "ghp_");
        assert_eq!(
            n.invisible,
            vec![InvisibleRun {
                kind: InvisibleKind::ZeroWidth,
                span: 2..5,
            }]
        );
        // A span across the removed character covers it in the original.
        assert_eq!(n.map.to_original(0..4), Some(0..7));
        assert_eq!(n.map.to_original(2..3), Some(5..6));
    }

    #[test]
    fn consecutive_invisible_characters_of_one_kind_are_one_run() {
        // "hi" written with tag characters, then a zero-width joiner, then a letter and a BOM.
        let input = "a\u{E0068}\u{E0069}\u{200D}b\u{FEFF}";
        let n = normalize(input);
        assert_eq!(n.text, "ab");
        let runs: Vec<_> = n
            .invisible
            .iter()
            .map(|r| (r.kind, r.span.clone()))
            .collect();
        assert_eq!(
            runs,
            vec![
                (InvisibleKind::Tag, 1..9),
                (InvisibleKind::ZeroWidth, 9..12),
                (InvisibleKind::ZeroWidth, 13..16),
            ]
        );
    }

    #[test]
    fn every_listed_range_is_invisible() {
        let listed = [
            ('\u{200B}', '\u{200D}', InvisibleKind::ZeroWidth),
            ('\u{2060}', '\u{2064}', InvisibleKind::ZeroWidth),
            ('\u{FEFF}', '\u{FEFF}', InvisibleKind::ZeroWidth),
            ('\u{200E}', '\u{200F}', InvisibleKind::Bidi),
            ('\u{202A}', '\u{202E}', InvisibleKind::Bidi),
            ('\u{2066}', '\u{2069}', InvisibleKind::Bidi),
            ('\u{E0000}', '\u{E007F}', InvisibleKind::Tag),
        ];
        for (first, last, kind) in listed {
            for c in first..=last {
                assert_eq!(InvisibleKind::of(c), Some(kind), "U+{:04X}", u32::from(c));
            }
        }
        for c in [
            'a',
            ' ',
            '\u{200A}',
            '\u{2065}',
            '\u{206A}',
            '\u{E0080}',
            '\u{00AD}',
        ] {
            assert_eq!(InvisibleKind::of(c), None, "U+{:04X}", u32::from(c));
        }
    }

    #[test]
    fn empty_and_out_of_range_spans_map_to_none() {
        let n = normalize("abc");
        assert_eq!(n.map.to_original(1..1), None);
        assert_eq!(n.map.to_original(2..4), None);
        assert_eq!(normalize("").map.to_original(0..1), None);
        assert_eq!(normalize("\u{200B}").map.to_original(0..1), None);
    }

    #[test]
    fn every_mapped_span_is_a_valid_range_of_the_original() {
        let pool = [
            "a",
            "Z",
            "7",
            "_",
            " ",
            "é",
            "ñ",
            "Ａ",
            "１",
            "\u{FB01}",
            "\u{FDFA}",
            "\u{3300}",
            "\u{200B}",
            "\u{202E}",
            "\u{E0041}",
            "\u{FEFF}",
            "😀",
            "\u{0301}",
            "ß",
            "Ⅻ",
        ];
        let mut rng = crate::test_support::Lcg(42);
        for _ in 0..500 {
            let len = (rng.next() % 24) as usize;
            let input: String = (0..len)
                .map(|_| pool[(rng.next() as usize) % pool.len()])
                .collect();
            let n = normalize(&input);
            let boundaries: Vec<usize> = (0..=n.text.len())
                .filter(|&i| n.text.is_char_boundary(i))
                .collect();
            for _ in 0..50 {
                let a = boundaries[(rng.next() as usize) % boundaries.len()];
                let b = boundaries[(rng.next() as usize) % boundaries.len()];
                let (start, end) = (a.min(b), a.max(b));
                let mapped = n.map.to_original(start..end);
                if start == end {
                    assert_eq!(mapped, None);
                    continue;
                }
                let Some(range) = mapped else {
                    panic!("{input:?}: {start}..{end} did not map");
                };
                assert!(input.get(range.clone()).is_some(), "{input:?}: {range:?}");
            }
            for run in &n.invisible {
                assert!(input.get(run.span.clone()).is_some());
            }
        }
    }
}
