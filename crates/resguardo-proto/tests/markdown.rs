//! Response controls (design document, "Streaming"; Annex G.4; ADR 0014): remote Markdown
//! images become `[image removed]`, links outside the allowed hosts keep only their text,
//! and the result does not depend on how the text is split across events.
// Test helpers may panic: an invalid fixture is a test failure.
#![allow(clippy::unwrap_used)]

use std::time::Instant;

use resguardo_proto::markdown::HOLD_LIMIT;
use resguardo_proto::{MarkdownFilter, MarkdownState, Removals, ResponseControls};

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
    // Each candidate costs at most HOLD_LIMIT bytes, about 1 s here in a debug build; a
    // quadratic scan of these 300,000 brackets would take hours. The bound leaves room for a
    // loaded machine running other tests in parallel.
    assert!(start.elapsed().as_secs() < 20, "{:?}", start.elapsed());
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
        // Found by the fuzzer: the first `!` is plain text, the second starts an image that
        // never closes; the placeholder after a `!` must not look like an image.
        "!![[[",
        "!![x](https://a.test/) fin",
        "!![[[[[[\u{8}\n[",
    ] {
        let once = apply(text);
        assert_eq!(apply(&once), once, "{text}");
    }
}

#[test]
fn a_bang_released_earlier_still_escapes_the_placeholder() {
    // Found by the fuzzer: split between the two `!`, the first was released before the
    // image was decided.
    assert_eq!(
        apply_split_everywhere("!![[[[[[\u{8}\n["),
        r"!\[image removed\]"
    );
}

#[test]
fn a_backslash_at_a_split_still_escapes_what_follows() {
    // Found by the fuzzer: split after the backslash, `\!` lost its escape.
    assert_eq!(apply_split_everywhere("v\\![["), "v\\![[");
    assert_eq!(
        apply_split_everywhere("a\\[x](https://attacker.test/) b\\\\[y](https://attacker.test/)"),
        "a\\[x](https://attacker.test/) b\\\\y"
    );
}

#[test]
fn markdown_inside_a_kept_destination_removes_the_construct() {
    // Found by the fuzzer: CommonMark does not accept "x ![b](...)" as a destination, so it
    // renders the outer link as text and the inner image as an image. A destination that
    // the controls would change is not a real one, so the construct is not kept.
    assert_eq!(
        apply_split_everywhere("[a](x ![b](https://attacker.test/?d=1))"),
        "a"
    );
    assert_eq!(
        apply("![a](x.png ![b](https://attacker.test/?d=1))"),
        "[image removed]"
    );
}

#[test]
fn removing_a_construct_inside_brackets_cannot_make_a_new_image() {
    // Found by the fuzzer: removing the inner link made the outer `![` pair with a later
    // `](...)` and become an image.
    let text = "![a [x](https://attacker.test/)] b](https://attacker.test/i.png)";
    // The brackets keep their content as a unit, so `![a x]` is still closed before " b]".
    let out = apply_split_everywhere(text);
    assert_eq!(out, "![a x] b](https://attacker.test/i.png)");
    assert_eq!(apply(&out), out);
}

#[test]
fn destinations_are_cleaned_like_a_browser_before_they_are_judged() {
    // A browser strips leading control characters and removes tabs and newlines, so these
    // resolve to attacker.test even though they do not start with "//".
    assert_eq!(apply("![x](\u{1}//attacker.test/i.png)"), "[image removed]");
    assert_eq!(apply("[x](\u{1}//attacker.test/)"), "x");
    assert_eq!(apply("[x](<\t//attacker.test/>)"), "x");
}

#[test]
fn a_replacement_cannot_put_a_parenthesis_right_after_released_brackets() {
    // Found by the fuzzer: `![ ]` was not an image because `[` followed it; once the link
    // after it was removed, `(` followed it, and `![ ](...)` became an image.
    assert_eq!(
        apply_split_everywhere("![ ][](https://attacker.test/)(https://attacker.test/x.png)"),
        r"![ ]\(https://attacker.test/x.png)"
    );
    assert_eq!(
        apply_split_everywhere(
            "![x](https://a.test/)[](https://attacker.test/)(https://attacker.test/)"
        ),
        r"[image removed]\(https://attacker.test/)"
    );
    // Text that was not changed keeps its parentheses.
    assert_eq!(apply("a [1] (b) [c](#d)"), "a [1] (b) [c](#d)");
}

// --- What the controls removed, for the receipt (ADR 0017) --------------------------------

fn removals(images: u64, links: u64) -> Removals {
    Removals { images, links }
}

/// The removals for `text`, checked to be the same when it arrives whole, in two parts
/// split at every char boundary, and one character at a time.
fn removed(text: &str) -> Removals {
    let controls = controls();
    let (whole_text, whole) = controls.apply_counted(text);
    for split in (0..=text.len()).filter(|&i| text.is_char_boundary(i)) {
        let mut filter = MarkdownFilter::new(&controls);
        let mut out = filter.push(&text[..split]);
        out.push_str(&filter.push(&text[split..]));
        out.push_str(&filter.finish());
        assert_eq!(out, whole_text, "split at {split} of {text:?}");
        assert_eq!(filter.removed(), whole, "split at {split} of {text:?}");
    }
    let mut filter = MarkdownFilter::new(&controls);
    let mut out = String::new();
    for c in text.chars() {
        out.push_str(&filter.push(c.encode_utf8(&mut [0; 4])));
    }
    out.push_str(&filter.finish());
    assert_eq!(out, whole_text, "one character at a time: {text:?}");
    assert_eq!(filter.removed(), whole, "one character at a time: {text:?}");
    whole
}

#[test]
fn an_untouched_text_removes_nothing() {
    assert_eq!(
        removed("hola, sin enlaces ni imágenes"),
        Removals::default()
    );
}

#[test]
fn one_image_and_one_link_are_counted() {
    assert_eq!(
        removed("Hecho ![x](https://attacker.test/p?d=abc) y [aquí](https://attacker.test/)"),
        removals(1, 1)
    );
}

#[test]
fn an_allowed_link_and_a_local_image_count_nothing() {
    assert_eq!(
        removed("[guía](https://docs.example.com/x) ![logo](logo.png) [arriba](#top)"),
        Removals::default()
    );
}

#[test]
fn an_image_that_never_closes_counts_as_removed() {
    assert_eq!(
        removed("ver ![x](https://attacker.test/p?d=abc"),
        removals(1, 0)
    );
}

#[test]
fn an_image_past_the_hold_limit_counts_once() {
    let text = format!("![x](https://attacker.test/?d={})", "a".repeat(HOLD_LIMIT));
    assert_eq!(removed(&text), removals(1, 0));
}

#[test]
fn a_tampered_destination_counts_only_what_the_application_sees_removed() {
    // The link inside each destination is read only to see that the destination is not a
    // real one; it is not released on its own, so it is not counted.
    assert_eq!(
        removed("![x](logo.png[y](https://attacker.test/))"),
        removals(1, 0)
    );
    assert_eq!(removed("[a](x[b](https://attacker.test/))"), removals(0, 1));
}

#[test]
fn an_image_inside_a_link_counts_as_one_of_each() {
    assert_eq!(
        removed("[![x](https://attacker.test/i.png)](https://attacker.test/l)"),
        removals(1, 1)
    );
}

#[test]
fn removals_inside_brackets_that_are_not_a_link_count() {
    assert_eq!(
        removed("[ver ![x](https://attacker.test/i.png) y [a](https://attacker.test/)]"),
        removals(1, 1)
    );
}

#[test]
fn an_escaped_placeholder_is_still_one_image() {
    assert_eq!(
        removed("![x](https://attacker.test/p)(https://attacker.test/q)"),
        removals(1, 0)
    );
}

#[test]
fn a_state_per_stream_block_counts_its_own_removals() {
    let controls = controls();
    let mut first = MarkdownState::default();
    let mut second = MarkdownState::default();
    let _ = controls.push(&mut first, "![x](https://attacker.test/");
    let _ = controls.push(&mut second, "[a](https://attacker.test/)");
    let _ = controls.push(&mut first, "p) ok");
    let _ = controls.finish(&mut first);
    let _ = controls.finish(&mut second);
    assert_eq!(first.removed(), removals(1, 0));
    assert_eq!(second.removed(), removals(0, 1));
}
