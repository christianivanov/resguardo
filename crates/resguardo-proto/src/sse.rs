//! Incremental parser of Server-Sent Events (WHATWG HTML, "Server-sent events"; ADR 0014).
//!
//! Bytes arrive in arbitrary chunks. Lines end in `\n`, `\r\n` or `\r`, and a blank line
//! ends an event. Each event keeps its exact bytes in [`SseEvent::raw`], so an event that is
//! not changed is forwarded as it came. Values are decoded as UTF-8 with replacement
//! characters, as clients do, so the scanner reads what the application will read.

/// One event: a block of lines ended by a blank line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// The exact bytes of the block, blank line included.
    pub raw: Vec<u8>,
    /// The `event` field, if any.
    pub event: Option<String>,
    /// The `data` lines joined with `\n`, or `None` if the block had none (a comment-only
    /// keep-alive, for example).
    pub data: Option<String>,
    pub id: Option<String>,
}

/// Why a stream could not be parsed. The stream is cut (closed by default, ADR 0002).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SseError {
    #[error("an event of the response stream is larger than {0} bytes")]
    EventTooLarge(usize),
}

/// Holds at most `max_event_bytes` between calls: the current event and its unfinished line.
#[derive(Debug)]
pub struct SseParser {
    max_event_bytes: usize,
    /// Bytes not yet split into lines.
    pending: Vec<u8>,
    /// Prefix of `pending` already searched for a line ending.
    searched: usize,
    /// Complete lines of the current event, with their endings.
    raw: Vec<u8>,
    event: Option<String>,
    data: Option<String>,
    id: Option<String>,
    /// A byte order mark is ignored only at the very start of the stream.
    first_line: bool,
}

impl SseParser {
    pub fn new(max_event_bytes: usize) -> Self {
        Self {
            max_event_bytes,
            pending: Vec::new(),
            searched: 0,
            raw: Vec::new(),
            event: None,
            data: None,
            id: None,
            first_line: true,
        }
    }

    /// Bytes held: the current event and its unfinished line.
    pub fn buffered(&self) -> usize {
        self.raw.len() + self.pending.len()
    }

    /// Adds a chunk and returns the events it completed.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, SseError> {
        self.pending.extend_from_slice(chunk);
        let mut events = Vec::new();
        self.consume(false, &mut events)?;
        if self.buffered() > self.max_event_bytes {
            return Err(SseError::EventTooLarge(self.max_event_bytes));
        }
        Ok(events)
    }

    /// The stream ended. A `\r` waiting for a possible `\n` ends its line. An event without
    /// its closing blank line is dropped, as a client drops it, so it is never forwarded
    /// unscanned.
    pub fn finish(&mut self) -> Option<SseEvent> {
        let mut events = Vec::new();
        // Lines were already within the limit when they were buffered.
        let _ = self.consume(true, &mut events);
        self.pending.clear();
        self.searched = 0;
        self.raw.clear();
        self.event = None;
        self.data = None;
        self.id = None;
        events.pop()
    }

    fn consume(&mut self, at_end: bool, events: &mut Vec<SseEvent>) -> Result<(), SseError> {
        let pending = std::mem::take(&mut self.pending);
        let mut start = 0;
        let result = loop {
            let from = self.searched.max(start);
            let Some(offset) = pending
                .get(from..)
                .and_then(|rest| rest.iter().position(|&b| b == b'\n' || b == b'\r'))
            else {
                self.searched = pending.len();
                break Ok(());
            };
            let end = from + offset;
            let terminator = match (pending.get(end), pending.get(end + 1)) {
                (Some(b'\r'), Some(b'\n')) => 2,
                // A `\r` at the end of the data may be the first half of `\r\n`.
                (Some(b'\r'), None) if !at_end => {
                    self.searched = end;
                    break Ok(());
                }
                _ => 1,
            };
            let next = end + terminator;
            if self.raw.len() + (next - start) > self.max_event_bytes {
                break Err(SseError::EventTooLarge(self.max_event_bytes));
            }
            if let (Some(line), Some(full)) = (pending.get(start..end), pending.get(start..next)) {
                self.line(line, full, events);
            }
            start = next;
        };
        self.pending = pending;
        self.pending.drain(..start.min(self.pending.len()));
        self.searched = self.searched.saturating_sub(start);
        result
    }

    fn line(&mut self, line: &[u8], full: &[u8], events: &mut Vec<SseEvent>) {
        self.raw.extend_from_slice(full);
        let mut line = line;
        if std::mem::take(&mut self.first_line) {
            line = line.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(line);
        }
        if line.is_empty() {
            events.push(SseEvent {
                raw: std::mem::take(&mut self.raw),
                event: self.event.take(),
                data: self.data.take().map(|mut data| {
                    data.pop();
                    data
                }),
                id: self.id.take(),
            });
            return;
        }
        let text = String::from_utf8_lossy(line);
        if text.starts_with(':') {
            return;
        }
        let (field, value) = match text.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (text.as_ref(), ""),
        };
        match field {
            "event" => self.event = Some(value.to_owned()),
            "data" => {
                let data = self.data.get_or_insert_with(String::new);
                data.push_str(value);
                data.push('\n');
            }
            "id" if !value.contains('\0') => self.id = Some(value.to_owned()),
            _ => {}
        }
    }
}
