//! What happens to a response before the application sees it (ADR 0014): scanning, the
//! policy decision and the response controls, for whole responses and for streams.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Instant;

use resguardo_core::{BlockCode, DataClass, Decision, Principal, StreamMode};
use resguardo_egress::UpstreamResponse;
use resguardo_proto::{
    ApiFormat, Block, MarkdownState, SseParser, StreamEvent, TextKind, analyze_event, flush_event,
    parse_strict, replace_strings, response_texts, rewrite_event,
};
use serde_json::{Value, json};

use crate::receipt::{class_counts, micros, outcome_in_background};
use crate::server::{App, Failure, error_body};

/// Annex H: the class, never the value.
fn blocked_message(class: Option<DataClass>) -> String {
    match class {
        Some(class) => {
            format!("Response blocked: data class '{class}' is not allowed in the response.")
        }
        None => "Response blocked: some encoded content could not be fully inspected.".to_owned(),
    }
}

/// Scans a whole response and applies the response controls. Provider errors (non-2xx) are
/// returned unchanged. CPU work: called from Tokio's blocking pool.
pub(crate) fn guard_whole(
    app: &App,
    principal: &Principal,
    format: ApiFormat,
    mut response: UpstreamResponse,
) -> Result<(UpstreamResponse, Value), Failure> {
    if !response.status.is_success() {
        return Ok((response, json!({})));
    }
    let unreadable = || {
        Failure::block(
            BlockCode::UpstreamError,
            "the provider response could not be read",
        )
    };
    let raw = parse_strict(&response.body).map_err(|_| unreadable())?;
    let texts = response_texts(format, &raw);
    let scan_texts: Vec<_> = texts.iter().map(|t| t.to_scan_text()).collect();
    let report = app.pipeline.scan(&scan_texts).map_err(|error| {
        eprintln!("response scanning: {error}");
        Failure::block(BlockCode::ScanError, "the response could not be scanned")
    })?;
    if let Decision::Block { class, .. } = app.policy.decide(principal, &report) {
        return Err(Failure::block(
            BlockCode::SensitiveData,
            blocked_message(class),
        ));
    }
    let mut changes = BTreeMap::new();
    for text in texts.iter().filter(|t| t.kind == TextKind::Text) {
        let controlled = app.controls.apply(&text.text);
        if controlled != text.text {
            changes.insert(text.pointer.clone(), controlled);
        }
    }
    response.body = replace_strings(&response.body, &raw, &changes).map_err(|error| {
        eprintln!("response controls: {error}");
        Failure::block(BlockCode::ScanError, "the response could not be rewritten")
    })?;
    Ok((response, class_counts(&report)))
}

/// What to send after a chunk of the provider's stream.
pub(crate) enum Step {
    /// Bytes to send now (possibly none); the stream goes on.
    Continue(Vec<u8>),
    /// Last bytes to send (an error event); the stream ends.
    Stop(Vec<u8>),
}

/// Follows one SSE response (Annex F.7): every text is scanned with the tail of its block,
/// a blocking finding ends the stream with an error event, response controls rewrite the
/// text deltas, and in `buffer` mode events wait for the end of a sentence.
pub(crate) struct StreamGuard {
    app: Arc<App>,
    principal: Principal,
    format: ApiFormat,
    request_id: String,
    parser: SseParser,
    /// The last `overlap_bytes` of each block's texts.
    tails: HashMap<Block, String>,
    /// Text held by the response controls, per block.
    held_text: HashMap<Block, MarkdownState>,
    /// The last event of each text block, to build the event that releases held text.
    templates: HashMap<Block, StreamEvent>,
    /// `buffer` mode: scanned events not yet released, and their text length.
    held_events: Vec<u8>,
    held_bytes: usize,
    buffer: bool,
    stopped: bool,
    /// For the outcome entry.
    started: Instant,
    upstream_started: Instant,
    response_findings: BTreeMap<DataClass, u64>,
}

impl StreamGuard {
    pub(crate) fn new(
        app: Arc<App>,
        principal: Principal,
        format: ApiFormat,
        request_id: String,
        started: Instant,
        upstream_started: Instant,
    ) -> Self {
        let parser = SseParser::new(app.stream.max_event_bytes);
        let buffer = principal.stream_mode == StreamMode::Buffer;
        Self {
            app,
            principal,
            format,
            request_id,
            parser,
            tails: HashMap::new(),
            held_text: HashMap::new(),
            templates: HashMap::new(),
            held_events: Vec::new(),
            held_bytes: 0,
            buffer,
            stopped: false,
            started,
            upstream_started,
            response_findings: BTreeMap::new(),
        }
    }

    /// The outcome entry of the stream, written once when it ends.
    fn record(&self, outcome: &str, status: u16) {
        let upstream_us = micros(self.upstream_started);
        let total = micros(self.started);
        let findings: BTreeMap<String, u64> = self
            .response_findings
            .iter()
            .map(|(class, n)| (class.as_str().to_owned(), *n))
            .collect();
        let fields = BTreeMap::from([
            ("status".to_owned(), json!(status)),
            ("outcome".to_owned(), json!(outcome)),
            ("stream".to_owned(), json!(true)),
            ("upstream_us".to_owned(), json!(upstream_us)),
            (
                "overhead_us".to_owned(),
                json!(total.saturating_sub(upstream_us)),
            ),
            ("response_findings".to_owned(), json!(findings)),
        ]);
        outcome_in_background(&self.app, &self.request_id, fields);
    }

    pub(crate) fn chunk(&mut self, chunk: &[u8]) -> Step {
        if self.stopped {
            return Step::Stop(Vec::new());
        }
        let events = match self.parser.push(chunk) {
            Ok(events) => events,
            Err(error) => {
                eprintln!("response stream: {error}");
                return self.stop(
                    BlockCode::ScanError,
                    "the response stream could not be read".to_owned(),
                );
            }
        };
        let mut out = Vec::new();
        for sse in events {
            if let Err(step) = self.event(sse, &mut out) {
                return step;
            }
        }
        Step::Continue(out)
    }

    /// The provider closed the stream: the last complete event, held text and held events
    /// are released.
    pub(crate) fn end(&mut self) -> Vec<u8> {
        if self.stopped {
            return Vec::new();
        }
        let mut out = Vec::new();
        if let Some(sse) = self.parser.finish()
            && let Err(step) = self.event(sse, &mut out)
        {
            return match step {
                Step::Continue(bytes) | Step::Stop(bytes) => bytes,
            };
        }
        let blocks: Vec<Block> = self.held_text.keys().cloned().collect();
        let mut flushed = Vec::new();
        if let Err(step) = self.release_blocks(&blocks, &mut flushed) {
            return match step {
                Step::Continue(bytes) | Step::Stop(bytes) => bytes,
            };
        }
        self.emit(flushed, true, &mut out);
        self.stopped = true;
        self.record("completed", 200);
        out
    }

    /// The provider stream failed (timeout, size limit, connection): held events are
    /// dropped and the application gets an error event.
    pub(crate) fn fail(&mut self) -> Vec<u8> {
        match self.stop(
            BlockCode::UpstreamError,
            "the provider stream failed or exceeded its limits".to_owned(),
        ) {
            Step::Continue(bytes) | Step::Stop(bytes) => bytes,
        }
    }

    fn event(&mut self, sse: resguardo_proto::SseEvent, out: &mut Vec<u8>) -> Result<(), Step> {
        let event = analyze_event(self.format, sse).map_err(|error| {
            eprintln!("response stream: {error}");
            self.stop(
                BlockCode::ScanError,
                "the response stream could not be read".to_owned(),
            )
        })?;
        self.scan(&event)?;

        let ending = self.ending_blocks(&event);
        let mut bytes = Vec::new();
        // Blocks that end here without text of their own release what they held first.
        let silent: Vec<Block> = ending
            .iter()
            .filter(|b| !event.texts.iter().any(|t| t.block.as_ref() == Some(*b)))
            .cloned()
            .collect();
        self.release_blocks(&silent, &mut bytes)?;

        let mut changes = Vec::new();
        for text in event.texts.iter().filter(|t| t.kind == TextKind::Text) {
            let Some(block) = &text.block else {
                continue;
            };
            let held = self.held_text.entry(block.clone()).or_default();
            let mut controlled = self.app.controls.push(held, &text.text);
            if ending.contains(block) {
                controlled.push_str(&self.app.controls.finish(held));
                self.held_text.remove(block);
            } else {
                self.templates.insert(block.clone(), event.clone());
            }
            if controlled != text.text {
                changes.push((text.pointer.clone(), controlled));
            }
        }
        if changes.is_empty() {
            bytes.extend_from_slice(&event.sse.raw);
        } else {
            let rewritten = rewrite_event(&event, &changes).map_err(|_| {
                self.stop(
                    BlockCode::ScanError,
                    "the response stream could not be rewritten".to_owned(),
                )
            })?;
            bytes.extend_from_slice(&rewritten);
        }

        let text_len: usize = event
            .texts
            .iter()
            .filter(|t| t.block.is_some())
            .map(|t| t.text.len())
            .sum();
        let sentence_ends = event
            .texts
            .iter()
            .filter(|t| t.block.is_some())
            .any(|t| t.text.contains(['.', '!', '?', '\n']));
        self.held_bytes += text_len;
        let release = text_len == 0
            || sentence_ends
            || event.done
            || self.held_bytes >= self.app.stream.buffer_flush_bytes;
        self.emit(bytes, release, out);
        Ok(())
    }

    /// Scans each text with the tail of its block; a blocking finding stops the stream.
    fn scan(&mut self, event: &StreamEvent) -> Result<(), Step> {
        for text in &event.texts {
            let window = match &text.block {
                Some(block) => {
                    let mut window = self.tails.get(block).cloned().unwrap_or_default();
                    window.push_str(&text.text);
                    window
                }
                None => text.text.clone(),
            };
            let tail_len = window.len() - text.text.len();
            let report = self
                .app
                .pipeline
                .scan_text(&text.pointer, &window)
                .map_err(|error| {
                    eprintln!("response scanning: {error}");
                    self.stop(
                        BlockCode::ScanError,
                        "the response could not be scanned".to_owned(),
                    )
                })?;
            for finding in report.findings.iter().filter(|f| f.span.end > tail_len) {
                *self.response_findings.entry(finding.class).or_default() += 1;
            }
            if let Decision::Block { class, .. } = self.app.policy.decide(&self.principal, &report)
            {
                return Err(self.stop(BlockCode::SensitiveData, blocked_message(class)));
            }
            if let Some(block) = &text.block {
                self.tails.insert(
                    block.clone(),
                    last_bytes(&window, self.app.stream.overlap_bytes).to_owned(),
                );
            }
        }
        Ok(())
    }

    /// The blocks with held text or a template that end with this event.
    fn ending_blocks(&self, event: &StreamEvent) -> Vec<Block> {
        let known: Vec<&Block> = self
            .held_text
            .keys()
            .chain(self.templates.keys())
            .chain(event.texts.iter().filter_map(|t| t.block.as_ref()))
            .collect();
        let mut ending: Vec<Block> = known
            .into_iter()
            .filter(|block| {
                event.done
                    || match block {
                        Block::Choice { index, .. } | Block::Content(index) => {
                            event.ends.contains(index)
                        }
                    }
            })
            .cloned()
            .collect();
        ending.sort();
        ending.dedup();
        ending
    }

    /// Sends what the response controls still hold for `blocks`, as new text deltas.
    fn release_blocks(&mut self, blocks: &[Block], bytes: &mut Vec<u8>) -> Result<(), Step> {
        for block in blocks {
            let Some(mut held) = self.held_text.remove(block) else {
                continue;
            };
            let rest = self.app.controls.finish(&mut held);
            let template = self.templates.remove(block);
            if rest.is_empty() {
                continue;
            }
            let Some(template) = template else {
                continue;
            };
            let event = flush_event(self.format, &template, block, &rest).map_err(|_| {
                self.stop(
                    BlockCode::ScanError,
                    "the response stream could not be rewritten".to_owned(),
                )
            })?;
            bytes.extend_from_slice(&event);
        }
        Ok(())
    }

    /// `passthrough_abort` sends at once; `buffer` holds until `release`.
    fn emit(&mut self, bytes: Vec<u8>, release: bool, out: &mut Vec<u8>) {
        if !self.buffer {
            out.extend_from_slice(&bytes);
            return;
        }
        self.held_events.extend_from_slice(&bytes);
        if release {
            out.append(&mut self.held_events);
            self.held_bytes = 0;
        }
    }

    /// Ends the stream with an error event in the API's error shape. Events held in
    /// `buffer` mode are dropped, so nothing after the last release reaches the application.
    fn stop(&mut self, code: BlockCode, message: String) -> Step {
        if !self.stopped {
            let outcome = match code {
                BlockCode::UpstreamError | BlockCode::UpstreamRedirect => "upstream_error",
                _ => "aborted",
            };
            self.record(outcome, 200);
        }
        self.stopped = true;
        self.held_events.clear();
        let status = axum::http::StatusCode::from_u16(code.http_status())
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        let body: Value = error_body(
            Some(self.format),
            status,
            code.as_str(),
            &message,
            &self.request_id,
        );
        Step::Stop(format!("event: error\ndata: {body}\n\n").into_bytes())
    }
}

/// The last `n` bytes of `text`, starting on a char boundary.
fn last_bytes(text: &str, n: usize) -> &str {
    let mut start = text.len().saturating_sub(n);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text.get(start..).unwrap_or_default()
}
