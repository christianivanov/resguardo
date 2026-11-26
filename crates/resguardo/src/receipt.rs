//! The two signed entries of each authenticated request (ADR 0003, ADR 0015): `decision`,
//! written before anything leaves, and `outcome`, written when the request ends.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use resguardo_core::{AuditKind, BlockCode, DataClass, Principal, ScanReport};
use resguardo_proto::Removals;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::server::{App, Failure};

/// What is known about a request so far, for its decision entry.
pub(crate) struct Receipt {
    pub(crate) request_id: String,
    pub(crate) started: Instant,
    fields: BTreeMap<String, Value>,
    /// The decision entry was written.
    decided: bool,
    /// Writing it failed: the request is already `AUDIT_UNAVAILABLE`.
    failed: bool,
}

impl Receipt {
    pub(crate) fn new(request_id: &str, principal: &Principal) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("principal".to_owned(), json!(principal.id.as_str()));
        if let Some(purpose) = &principal.purpose {
            fields.insert("purpose".to_owned(), json!(purpose));
        }
        Self {
            request_id: request_id.to_owned(),
            started: Instant::now(),
            fields,
            decided: false,
            failed: false,
        }
    }

    pub(crate) fn set(&mut self, name: &str, value: Value) {
        self.fields.insert(name.to_owned(), value);
    }

    pub(crate) fn body(&mut self, name: &str, bytes: &[u8]) {
        self.set(&format!("{name}_sha256"), json!(sha256_hex(bytes)));
    }

    /// Counts per class and per limit: never values.
    pub(crate) fn findings(&mut self, report: &ScanReport) {
        self.set("findings", class_counts(report));
        let mut flags: BTreeMap<String, u64> = BTreeMap::new();
        for flag in &report.flags {
            *flags.entry(flag.limit.as_str().to_owned()).or_default() += 1;
        }
        self.set("flags", json!(flags));
    }

    /// Writes the decision entry; on failure the request must not leave.
    pub(crate) async fn decide(&mut self, app: &Arc<App>) -> Result<(), Failure> {
        let fields = self.fields.clone();
        match write(app, AuditKind::Decision, &self.request_id, fields).await {
            Ok(()) => {
                self.decided = true;
                Ok(())
            }
            Err(failure) => {
                self.failed = true;
                Err(failure)
            }
        }
    }

    /// Records a request that ends with `failure`: its decision (a block) if none was
    /// written yet, then its outcome. A failed decision write turns the answer into
    /// `AUDIT_UNAVAILABLE`.
    pub(crate) async fn failed(&mut self, app: &Arc<App>, failure: Failure) -> Failure {
        if self.failed {
            return failure;
        }
        let code = failure.code();
        if !self.decided {
            self.set("decision", json!("block"));
            if let Some(code) = code {
                self.set("code", json!(code.as_str()));
            }
            if let Err(audit) = self.decide(app).await {
                return audit;
            }
        }
        let status = code.map_or(404, BlockCode::http_status);
        let outcome = match code {
            Some(BlockCode::UpstreamError | BlockCode::UpstreamRedirect) => "upstream_error",
            _ => "blocked",
        };
        let fields = BTreeMap::from([
            ("status".to_owned(), json!(status)),
            ("outcome".to_owned(), json!(outcome)),
            ("overhead_us".to_owned(), json!(micros(self.started))),
        ]);
        outcome_entry(app, &self.request_id, fields).await;
        failure
    }
}

/// Writes an entry on the blocking pool: `fsync` must not hold an async worker.
async fn write(
    app: &Arc<App>,
    kind: AuditKind,
    request_id: &str,
    fields: BTreeMap<String, Value>,
) -> Result<(), Failure> {
    let app = Arc::clone(app);
    let request_id = request_id.to_owned();
    let written =
        tokio::task::spawn_blocking(move || app.audit.append(kind, Some(&request_id), fields))
            .await;
    match written {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => {
            // Names the file and cause, never entry content.
            eprintln!("audit: {error}");
            Err(audit_unavailable())
        }
        Err(_) => Err(audit_unavailable()),
    }
}

/// An outcome cannot stop a response that already left: a failure is printed, and the next
/// decision write fails if the log is still broken.
pub(crate) async fn outcome_entry(
    app: &Arc<App>,
    request_id: &str,
    fields: BTreeMap<String, Value>,
) {
    let _ = write(app, AuditKind::Outcome, request_id, fields).await;
}

/// The same, from code that cannot wait (a stream ending).
pub(crate) fn outcome_in_background(
    app: &Arc<App>,
    request_id: &str,
    fields: BTreeMap<String, Value>,
) {
    let app = Arc::clone(app);
    let request_id = request_id.to_owned();
    tokio::task::spawn_blocking(move || {
        if let Err(error) = app
            .audit
            .append(AuditKind::Outcome, Some(&request_id), fields)
        {
            eprintln!("audit: {error}");
        }
    });
}

fn audit_unavailable() -> Failure {
    Failure::block(
        BlockCode::AuditUnavailable,
        "the receipt could not be written, so the request was not sent",
    )
}

pub(crate) fn class_counts(report: &ScanReport) -> Value {
    let mut counts: BTreeMap<DataClass, u64> = BTreeMap::new();
    for finding in &report.findings {
        *counts.entry(finding.class).or_default() += 1;
    }
    json!(
        counts
            .into_iter()
            .map(|(class, n)| (class.as_str().to_owned(), n))
            .collect::<BTreeMap<_, _>>()
    )
}

/// What the response controls removed (ADR 0017): `images_removed` and `links_removed`,
/// each only when above zero, so an untouched response has `{}`. Counts only, never URLs.
pub(crate) fn removals_json(removed: Removals) -> Value {
    let mut counts = BTreeMap::new();
    if removed.images > 0 {
        counts.insert("images_removed", removed.images);
    }
    if removed.links > 0 {
        counts.insert("links_removed", removed.links);
    }
    json!(counts)
}

/// Integer microseconds since `since` (no floats in the log).
pub(crate) fn micros(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
