//! Property tests of redaction (M3.4, ADR 0013), on random documents.
//!
//! The documents are serialized here, with random whitespace, escapes and number formats, so
//! the byte range of every string is known without asking the code under test. Redaction
//! must return exactly the original bytes with those strings, and only those, replaced by
//! what a simple reference model of ADR 0013 computes.
// Test helpers may panic: a failed property is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;

use resguardo_core::{DataClass, Finding};
use resguardo_proto::{ApiFormat, parse_request, redact};

/// Deterministic pseudo-random numbers (the same LCG as `resguardo-scan`'s tests), so every
/// failure can be reproduced from its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn percent(&mut self, p: u64) -> bool {
        self.next() % 100 < p
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// A JSON document. Numbers keep their written form.
enum J {
    Null,
    Bool(bool),
    Num(&'static str),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

/// Characters that stress escaping: quotes, backslashes, slashes, controls, multi-byte and
/// astral characters, line separators and invisible characters.
const ALPHABET: &[char] = &[
    'a', 'b', 'Z', '0', '7', ' ', '-', '.', '@', '~', '/', '"', '\\', '\n', '\t', '\u{1}', 'ñ',
    'é', '€', '😀', '\u{2028}', '\u{200B}',
];

const NUMBERS: &[&str] = &["0", "-1", "2.50", "1e3", "1.0E-2", "123456789012", "-0.0"];

/// Keys include ones that need RFC 6901 escaping (`/`, `~`) and JSON escaping.
const KEYS: &[&str] = &[
    "a",
    "b",
    "messages",
    "text",
    "type",
    "a/b",
    "m~n",
    "q\"uote",
    "back\\slash",
    "ñ",
    "😀",
    "",
    "role",
];

fn text(rng: &mut Rng) -> String {
    (0..rng.below(24)).map(|_| *rng.pick(ALPHABET)).collect()
}

fn value(rng: &mut Rng, depth: usize) -> J {
    let kinds = if depth == 0 { 4 } else { 6 };
    match rng.below(kinds) {
        0 => J::Null,
        1 => J::Bool(rng.percent(50)),
        2 => J::Num(rng.pick(NUMBERS)),
        3 => J::Str(text(rng)),
        4 => J::Arr((0..rng.below(4)).map(|_| value(rng, depth - 1)).collect()),
        _ => object(rng, depth - 1),
    }
}

/// An object with unique keys, in random order.
fn object(rng: &mut Rng, depth: usize) -> J {
    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    for _ in 0..rng.below(4) {
        let key = (*rng.pick(KEYS)).to_owned();
        if seen.insert(key.clone()) {
            entries.push((key, value(rng, depth)));
        }
    }
    J::Obj(entries)
}

/// A request: `model`, `messages` and some other fields, in random order.
fn request(rng: &mut Rng) -> J {
    let messages = (0..rng.below(4))
        .map(|_| {
            let content = if rng.percent(50) {
                J::Str(text(rng))
            } else {
                J::Arr(
                    (0..rng.below(3))
                        .map(|_| {
                            J::Obj(vec![
                                ("type".to_owned(), J::Str("text".to_owned())),
                                ("text".to_owned(), J::Str(text(rng))),
                            ])
                        })
                        .collect(),
                )
            };
            let mut entries = vec![
                (
                    "role".to_owned(),
                    J::Str(rng.pick(&["user", "assistant"]).to_string()),
                ),
                ("content".to_owned(), content),
            ];
            if rng.percent(30) {
                entries.push(("extra".to_owned(), value(rng, 2)));
            }
            shuffle(rng, &mut entries);
            J::Obj(entries)
        })
        .collect();
    let mut entries = vec![
        ("model".to_owned(), J::Str("m".to_owned())),
        ("messages".to_owned(), J::Arr(messages)),
    ];
    if rng.percent(60) {
        entries.push(("system".to_owned(), J::Str(text(rng))));
    }
    if rng.percent(60) {
        entries.push(("metadata".to_owned(), object(rng, 3)));
    }
    if rng.percent(40) {
        entries.push(("tools".to_owned(), value(rng, 3)));
    }
    shuffle(rng, &mut entries);
    J::Obj(entries)
}

fn shuffle<T>(rng: &mut Rng, items: &mut [T]) {
    for i in (1..items.len()).rev() {
        items.swap(i, rng.below(i + 1));
    }
}

/// Serializes `doc` with random whitespace and escapes, and records the byte range of every
/// string value by its JSON Pointer.
struct Writer<'r> {
    rng: &'r mut Rng,
    out: Vec<u8>,
    strings: BTreeMap<String, Range<usize>>,
}

impl Writer<'_> {
    fn space(&mut self) {
        for _ in 0..self.rng.below(3) {
            let ws = *self.rng.pick(b" \n\t\r");
            self.out.push(ws);
        }
    }

    fn string(&mut self, s: &str) {
        self.out.push(b'"');
        for c in s.chars() {
            match c {
                '"' => self.out.extend_from_slice(b"\\\""),
                '\\' => self.out.extend_from_slice(b"\\\\"),
                '\n' => self.out.extend_from_slice(b"\\n"),
                '\t' => self.out.extend_from_slice(b"\\t"),
                c if (c as u32) < 0x20 => self.unicode_escape(c),
                '/' if self.rng.percent(50) => self.out.extend_from_slice(b"\\/"),
                c if self.rng.percent(25) => self.unicode_escape(c),
                c => {
                    let mut buf = [0u8; 4];
                    self.out
                        .extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
            }
        }
        self.out.push(b'"');
    }

    /// `\uXXXX`, with a surrogate pair for characters outside the Basic Multilingual Plane.
    fn unicode_escape(&mut self, c: char) {
        let mut units = [0u16; 2];
        for unit in c.encode_utf16(&mut units) {
            self.out
                .extend_from_slice(format!("\\u{:04X}", unit).as_bytes());
        }
    }

    fn value(&mut self, doc: &J, pointer: &str) {
        self.space();
        match doc {
            J::Null => self.out.extend_from_slice(b"null"),
            J::Bool(b) => self
                .out
                .extend_from_slice(if *b { b"true" } else { b"false" }),
            J::Num(n) => self.out.extend_from_slice(n.as_bytes()),
            J::Str(s) => {
                let start = self.out.len();
                self.string(s);
                self.strings
                    .insert(pointer.to_owned(), start..self.out.len());
            }
            J::Arr(items) => {
                self.out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        self.out.push(b',');
                    }
                    self.value(item, &format!("{pointer}/{i}"));
                    self.space();
                }
                if items.is_empty() {
                    self.space();
                }
                self.out.push(b']');
            }
            J::Obj(entries) => {
                self.out.push(b'{');
                for (i, (key, item)) in entries.iter().enumerate() {
                    if i > 0 {
                        self.out.push(b',');
                    }
                    self.space();
                    self.string(key);
                    self.space();
                    self.out.push(b':');
                    let segment = key.replace('~', "~0").replace('/', "~1");
                    self.value(item, &format!("{pointer}/{segment}"));
                    self.space();
                }
                if entries.is_empty() {
                    self.space();
                }
                self.out.push(b'}');
            }
        }
    }
}

const CLASSES: &[DataClass] = &[
    DataClass::Secret,
    DataClass::EsId,
    DataClass::Iban,
    DataClass::Card,
    DataClass::Phone,
    DataClass::Email,
    DataClass::InvisibleText,
];

/// Random spans on char boundaries of some of the texts.
fn random_spans(rng: &mut Rng, texts: &[(String, String)]) -> Vec<Finding> {
    let mut spans = Vec::new();
    for (pointer, text) in texts {
        if text.is_empty() || !rng.percent(50) {
            continue;
        }
        let mut bounds: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
        bounds.push(text.len());
        for _ in 0..1 + rng.below(3) {
            let a = rng.below(bounds.len());
            let b = rng.below(bounds.len());
            if a == b {
                continue;
            }
            let (start, end) = (bounds[a.min(b)], bounds[a.max(b)]);
            let class = *rng.pick(CLASSES);
            spans.push(Finding {
                class,
                pointer: pointer.clone(),
                span: start..end,
                rule: format!("{class}.test"),
                confidence: 90,
                via: if rng.percent(30) {
                    vec!["base64".to_owned()]
                } else {
                    Vec::new()
                },
            });
        }
    }
    spans
}

/// ADR 0013, written a second, simpler way: merge, label, number and rebuild forwards.
fn reference(texts: &[(String, String)], spans: &[Finding]) -> BTreeMap<String, String> {
    let mut order: Vec<&(String, String)> = texts
        .iter()
        .filter(|(p, _)| spans.iter().any(|s| &s.pointer == p))
        .collect();
    order.sort_by_key(|(p, _)| p.starts_with("/messages/"));

    let mut numbers: HashMap<(DataClass, String), usize> = HashMap::new();
    let mut counters: HashMap<DataClass, usize> = HashMap::new();
    let mut result = BTreeMap::new();
    for (pointer, text) in order {
        let mut mine: Vec<&Finding> = spans.iter().filter(|s| &s.pointer == pointer).collect();
        mine.sort_by_key(|s| (s.span.start, s.span.end));
        // (start, end, label, longest, remove)
        let mut groups: Vec<(usize, usize, DataClass, usize, bool)> = Vec::new();
        for s in mine {
            let len = s.span.len();
            let removable = s.class == DataClass::InvisibleText && s.via.is_empty();
            match groups.last_mut() {
                Some(g) if s.span.start < g.1 => {
                    g.1 = g.1.max(s.span.end);
                    g.4 = g.4 && removable;
                    if len > g.3 || (len == g.3 && s.class < g.2) {
                        g.2 = s.class;
                        g.3 = len;
                    }
                }
                _ => groups.push((s.span.start, s.span.end, s.class, len, removable)),
            }
        }
        let mut out = String::new();
        let mut pos = 0;
        for (start, end, class, _, remove) in groups {
            out.push_str(&text[pos..start]);
            if !remove {
                let next = numbers
                    .entry((class, text[start..end].to_owned()))
                    .or_insert_with(|| {
                        let c = counters.entry(class).or_insert(0);
                        *c += 1;
                        *c
                    });
                out.push_str(&format!("[REDACTED:{class}:{next}]"));
            }
            pos = end;
        }
        out.push_str(&text[pos..]);
        result.insert(pointer.clone(), out);
    }
    result
}

#[test]
fn redaction_changes_exactly_the_redacted_strings() {
    let mut redacted_requests = 0;
    for seed in 0..400 {
        let mut rng = Rng(seed);
        let doc = request(&mut rng);
        let mut writer = Writer {
            rng: &mut rng,
            out: Vec::new(),
            strings: BTreeMap::new(),
        };
        writer.value(&doc, "");
        writer.space();
        let Writer {
            out: body, strings, ..
        } = writer;

        let parsed = parse_request(ApiFormat::AnthropicMessages, &body)
            .unwrap_or_else(|e| panic!("seed {seed}: generated body rejected: {e}"));
        // The serializer and the parser agree on every text and its pointer.
        for t in &parsed.texts {
            let range = strings
                .get(&t.pointer)
                .unwrap_or_else(|| panic!("seed {seed}: no string at {}", t.pointer));
            let decoded: String = serde_json::from_slice(&body[range.clone()]).unwrap();
            assert_eq!(decoded, t.text, "seed {seed}: {}", t.pointer);
        }

        let texts: Vec<(String, String)> = parsed
            .texts
            .iter()
            .map(|t| (t.pointer.clone(), t.text.clone()))
            .collect();
        let spans = random_spans(&mut rng, &texts);
        let expected_texts = reference(&texts, &spans);

        // The original bytes with only the redacted strings replaced, in byte order.
        let mut targets: Vec<(&Range<usize>, &String)> = expected_texts
            .iter()
            .map(|(pointer, text)| (&strings[pointer], text))
            .collect();
        targets.sort_by_key(|(range, _)| range.start);
        let mut expected = Vec::new();
        let mut copied = 0;
        for (range, text) in targets {
            expected.extend_from_slice(&body[copied..range.start]);
            expected.extend_from_slice(serde_json::to_string(text).unwrap().as_bytes());
            copied = range.end;
        }
        expected.extend_from_slice(&body[copied..]);

        let out = redact(&body, &parsed, &spans)
            .unwrap_or_else(|e| panic!("seed {seed}: redaction failed: {e}"));
        assert_eq!(
            String::from_utf8_lossy(&out),
            String::from_utf8_lossy(&expected),
            "seed {seed}"
        );
        if !spans.is_empty() {
            redacted_requests += 1;
        }
    }
    // The generator must actually exercise redaction, not only empty span lists.
    assert!(redacted_requests > 200, "{redacted_requests}");
}

#[test]
fn deeply_nested_strings_are_located() {
    // 100 levels of arrays and objects around the text, under the strict parser's limit.
    let mut body = String::from(r#"{"model":"m","messages":[],"metadata":"#);
    let mut pointer = String::from("/metadata");
    for _ in 0..50 {
        body.push_str(r#"{"k":["#);
        pointer.push_str("/k/0");
    }
    body.push_str(r#""DNI 12345678Z""#);
    for _ in 0..50 {
        body.push_str("]}");
    }
    body.push('}');
    let parsed = parse_request(ApiFormat::AnthropicMessages, body.as_bytes()).unwrap();
    let span = Finding {
        class: DataClass::EsId,
        pointer: pointer.clone(),
        span: 4..13,
        rule: "es_id.test".to_owned(),
        confidence: 90,
        via: Vec::new(),
    };
    let out = String::from_utf8(redact(body.as_bytes(), &parsed, &[span]).unwrap()).unwrap();
    assert_eq!(out, body.replace("12345678Z", "[REDACTED:es_id:1]"));
}
