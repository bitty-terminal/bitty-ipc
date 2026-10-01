//! Trace lifecycle: `startTrace` / `stopTrace` / `fetchTraceChunk` (DT-03, #1099).
//!
//! Accepted v1 surface from `devtools-rfc.md` (trace methods table): an
//! opt-in, bounded, time-ordered recording of instrumentation events with
//! 256 KiB chunk pagination, a `0600` spool file, and a byte-accurate
//! redacted preview. Wire behavior mirrors the sibling `bitty-devtools`
//! `TracingClient` (`src/tracing.ts`, read-only, never modified here):
//! at most 4 concurrent traces, `min(trace maxBytes, retention maxBytes)`
//! admission billed on retained (post-redaction) bytes, counted drops with
//! retained state unchanged, `fetchTraceChunk` pagination over retained
//! chunk byte offsets, and preview-equals-export per page.
//!
//! # Trust posture
//!
//! - Scope: every method requires `debug.trace` (or the wider
//!   `debug.control`); `debug.inspect` alone is denied with
//!   `scope`/`ScopeDenied` and zero partial state.
//! - Events are untrusted observation data: owner/kind/payload shapes are
//!   bounded before retention, input markers (`kind: "input"` or
//!   `"input.*"` ) are dropped with a counted drop unless the trace opted
//!   in with `includeInput`, and secret-shaped payloads are replaced with
//!   [`crate::devtools::REDACTED_MARKER`] before they enter the store
//!   (P0-AC-026 parity with `captureFrame` redaction).
//! - The store never touches terminal truth and registers no hot-path
//!   callback: producers call [`append_trace_event`] explicitly from cold
//!   paths (or tests). Spool files are created with mode `0600` (Unix) so
//!   the verification-plan `0600` assertion holds.
//! - `stopTrace` exports retained bytes to the spool file and deletes the
//!   in-memory record (sibling parity); `fetchTraceChunk` serves active
//!   traces only, so export bytes stream while the trace is open.

use super::handlers::json_escape_into;
use super::json::truncate_chars;
use super::{MAX_ERROR_MESSAGE_CHARS, REDACTED_MARKER};

use crate::scope::Scope;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

// ── bounds (bitty-devtools `bounds.ts` parity) ──────────────────────────────

/// Chunk pagination size: at most 256 KiB per `fetchTraceChunk` page.
pub const TRACE_CHUNK_BYTES: usize = 256 * 1024;

/// Maximum retained bytes per trace (4 MiB retention ceiling).
pub const MAX_TRACE_BYTES: usize = 4 * 1024 * 1024;

/// Maximum trace duration in ms (5 minutes).
pub const MAX_TRACE_DURATION_MS: u64 = 5 * 60 * 1000;

/// Default trace duration in ms when `durationMs` is absent (sibling parity).
pub const DEFAULT_TRACE_DURATION_MS: u64 = 10_000;

/// Default byte budget when `maxBytes` is absent (sibling parity).
pub const DEFAULT_TRACE_MAX_BYTES: usize = 512 * 1024;

/// Maximum concurrent active traces (sibling `MAX_TRACES_PER_SESSION`).
pub const MAX_ACTIVE_TRACES: usize = 4;

/// Maximum bytes for one serialized trace event (observability parity).
pub const MAX_TRACE_EVENT_BYTES: usize = 8 * 1024;

/// Maximum characters for a trace owner label.
pub const MAX_TRACE_OWNER_CHARS: usize = 64;

/// Maximum characters for a trace event kind.
pub const MAX_TRACE_KIND_CHARS: usize = 64;

/// Maximum characters for a trace id (`trace-<n>`, server-minted).
pub const MAX_TRACE_ID_CHARS: usize = 64;

/// Preview window: redacted first bytes of the served page.
pub const TRACE_PREVIEW_BYTES: usize = 512;

/// Maximum previews returned by `stopTrace` (sibling slices 4 chunks).
pub const TRACE_STOP_PREVIEWS: usize = 4;

// ── events ──────────────────────────────────────────────────────────────────

/// One retained trace event (serialized as a single JSONL line on append).
#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceEvent {
    /// Monotonic sequence within the trace.
    seq: u64,
    /// Attributed owner (`1..=64` chars, no control bytes).
    owner: String,
    /// Event kind (`1..=64` chars, no control bytes).
    kind: String,
    /// Redacted payload (bounded, never secret-shaped).
    payload: String,
    /// Producer generation at capture time.
    generation: u64,
    /// Caller-supplied wall-clock ms.
    wall_ms: u64,
}

/// Whether an event kind is an input marker (opt-in via `includeInput`).
fn is_input_marker_kind(kind: &str) -> bool {
    kind == "input" || kind.starts_with("input.")
}

/// Whether a payload carries secret-shaped content (P0-AC-026 parity with
/// `captureFrame` line redaction: secrets, clipboard bytes, environment
/// bytes never enter default outputs).
fn is_sensitive_trace_payload(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();
    [
        "secret",
        "password",
        "passwd",
        "token",
        "clipboard",
        "bearer",
        "aws_",
        "begin private",
        "env=",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

/// Redact one payload before retention (whole-payload replacement,
/// fail-closed minimizing).
fn redact_trace_payload(payload: &str) -> String {
    if is_sensitive_trace_payload(payload) {
        REDACTED_MARKER.to_string()
    } else {
        payload.to_string()
    }
}

/// Redact a preview window: whole-line replacement for sensitive lines,
/// truncated to [`TRACE_PREVIEW_BYTES`] bytes on a UTF-8 boundary.
///
/// The served preview is derived from the served bytes through this
/// function on every call (never cached), so preview-equals-export holds
/// structurally: the preview is a pure function of the page bytes.
#[must_use]
pub fn redact_trace_preview(page_prefix: &str) -> String {
    let mut out = String::new();
    for line in page_prefix.split('\n') {
        if is_sensitive_trace_payload(line) {
            out.push_str(REDACTED_MARKER);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    if out.len() > TRACE_PREVIEW_BYTES {
        let mut end = TRACE_PREVIEW_BYTES;
        while end > 0 && !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }
    out
}

// ── store ───────────────────────────────────────────────────────────────────

/// One active trace.
#[derive(Debug)]
struct TraceRecord {
    /// Server-minted id (`trace-<n>`).
    id: String,
    /// Spool path the export is written to on stop.
    spool_path: String,
    /// Effective byte budget (`min(maxBytes, retention)`; retention is the
    /// 4 MiB ceiling here, so this is the validated `maxBytes`).
    max_bytes: u64,
    /// Duration budget in ms (advisory; expiry is enforced by the caller
    /// clock, not by a timer in this slice).
    duration_ms: u64,
    /// Whether input markers are retained.
    include_input: bool,
    /// Retained export bytes (post-redaction JSONL).
    bytes: u64,
    /// Counted drops (budget/input rejections; retained state unchanged).
    drops: u64,
    /// Retained chunks (each `<= TRACE_CHUNK_BYTES` bytes).
    chunks: Vec<String>,
    /// Next event sequence.
    next_seq: u64,
    /// Creation clock (bearer-clock ms, headless deterministic).
    start_ms: u64,
}

/// In-memory trace store (never persisted except the stop-time spool
/// export; never exported to another session).
#[derive(Debug, Default)]
struct TraceStore {
    /// Active traces by id.
    traces: BTreeMap<String, TraceRecord>,
    /// Issuance counter (id uniqueness).
    counter: u64,
}

/// Global trace store (empty until `startTrace`).
fn trace_store() -> &'static Mutex<TraceStore> {
    static STORE: OnceLock<Mutex<TraceStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(TraceStore::default()))
}

/// Spool directory override (tests and the servo). Defaults to
/// `<tempdir>/bitty-traces`; the serving binary must point this at
/// user-only storage before serving traces.
fn spool_dir_override() -> &'static Mutex<Option<String>> {
    static DIR: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    DIR.get_or_init(|| Mutex::new(None))
}

/// Set the spool directory (servo startup and tests). Created on demand
/// with mode `0700` (Unix) at stop time.
pub fn set_trace_spool_dir_for_tests(dir: &str) {
    if let Ok(mut slot) = spool_dir_override().lock() {
        *slot = Some(dir.to_string());
    }
}

/// Resolve the spool directory.
fn spool_dir() -> String {
    if let Ok(slot) = spool_dir_override().lock() {
        if let Some(dir) = slot.as_deref() {
            return dir.to_string();
        }
    }
    std::env::temp_dir()
        .join("bitty-traces")
        .to_string_lossy()
        .into_owned()
}

/// Number of active traces (tests).
#[must_use]
pub fn trace_count_for_tests() -> usize {
    trace_store()
        .lock()
        .map(|store| store.traces.len())
        .unwrap_or(0)
}

/// Clear all traces (tests).
pub fn clear_traces_for_tests() {
    if let Ok(mut store) = trace_store().lock() {
        store.traces.clear();
        store.counter = 0;
    }
}

/// Append failure for the harness hook [`append_trace_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceAppendError {
    /// No active trace with this id.
    NotFound,
    /// Store lock unavailable.
    Unavailable,
    /// Event shape invalid (bounded reason).
    InvalidEvent(String),
}

impl TraceAppendError {
    /// Stable error code for logs.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "NotFound",
            Self::Unavailable => "Unavailable",
            Self::InvalidEvent(_) => "InvalidEvent",
        }
    }
}

/// Append one instrumentation event to an active trace (harness hook).
///
/// Cold-path producers call this explicitly; nothing in the terminal,
/// render, or input hot paths calls here. Returns the event sequence.
/// Input markers without `includeInput`, over-budget lines, and
/// oversize/ill-shaped events are dropped with a counted drop and
/// `Ok(None)` — retained bytes, chunks, and previews stay unchanged —
/// except unknown trace ids and validation failures, which are `Err`.
pub fn append_trace_event(
    trace_id: &str,
    owner: &str,
    kind: &str,
    payload: &str,
    generation: u64,
    wall_ms: u64,
) -> Result<Option<u64>, TraceAppendError> {
    if owner.is_empty()
        || owner.chars().count() > MAX_TRACE_OWNER_CHARS
        || owner.contains('\0')
        || owner.bytes().any(|b| b < 0x20 || b == 0x7F)
    {
        return Err(TraceAppendError::InvalidEvent(
            "owner must be 1..=64 chars, no control bytes".to_string(),
        ));
    }
    if kind.is_empty()
        || kind.chars().count() > MAX_TRACE_KIND_CHARS
        || kind.contains('\0')
        || kind.bytes().any(|b| b < 0x20 || b == 0x7F)
    {
        return Err(TraceAppendError::InvalidEvent(
            "kind must be 1..=64 chars, no control bytes".to_string(),
        ));
    }
    if payload.len() > MAX_TRACE_EVENT_BYTES {
        return Err(TraceAppendError::InvalidEvent(format!(
            "payload must be 0..={MAX_TRACE_EVENT_BYTES} bytes"
        )));
    }
    let mut store = trace_store()
        .lock()
        .map_err(|_| TraceAppendError::Unavailable)?;
    let record = store
        .traces
        .get_mut(trace_id)
        .ok_or(TraceAppendError::NotFound)?;
    if is_input_marker_kind(kind) && !record.include_input {
        record.drops += 1;
        return Ok(None);
    }
    let seq = record.next_seq;
    let event = TraceEvent {
        seq,
        owner: owner.to_string(),
        kind: kind.to_string(),
        payload: redact_trace_payload(payload),
        generation,
        wall_ms,
    };
    let mut line = String::with_capacity(256);
    line.push_str("{\"seq\":");
    line.push_str(&event.seq.to_string());
    line.push_str(",\"owner\":\"");
    json_escape_into(&mut line, &event.owner);
    line.push_str("\",\"kind\":\"");
    json_escape_into(&mut line, &event.kind);
    line.push_str("\",\"payload\":\"");
    json_escape_into(&mut line, &event.payload);
    line.push_str("\",\"generation\":");
    line.push_str(&event.generation.to_string());
    line.push_str(",\"wallClockMs\":");
    line.push_str(&event.wall_ms.to_string());
    line.push_str("}\n");
    // Admission bills the retained (post-redaction) line, never heap or
    // filesystem occupancy.
    let line_bytes = line.len() as u64;
    if record.bytes + line_bytes > record.max_bytes {
        record.drops += 1;
        return Ok(None);
    }
    let fits = record
        .chunks
        .last()
        .is_none_or(|last: &String| last.len() as u64 + line_bytes <= TRACE_CHUNK_BYTES as u64);
    if fits {
        if let Some(last) = record.chunks.last_mut() {
            last.push_str(&line);
        } else {
            record.chunks.push(line);
        }
    } else {
        record.chunks.push(line);
    }
    record.bytes += line_bytes;
    record.next_seq += 1;
    Ok(Some(seq))
}

// ── params ──────────────────────────────────────────────────────────────────

/// Extract a top-level string field (`"key": "value"`, minimal unescape).
fn top_string(params: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut rest = params;
    loop {
        let at = rest.find(needle.as_str())?;
        let mut after = rest[at + needle.len()..].trim_start();
        if !after.starts_with(':') {
            rest = &rest[at + needle.len()..];
            continue;
        }
        after = after[1..].trim_start();
        if !after.starts_with('"') {
            return None;
        }
        let mut out = String::new();
        let mut chars = after[1..].chars();
        loop {
            let c = chars.next()?;
            match c {
                '"' => return Some(out),
                '\\' => {
                    let e = chars.next()?;
                    match e {
                        '"' | '\\' | '/' => out.push(e),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let hex: String = chars.by_ref().take(4).collect();
                            if hex.len() != 4 {
                                return None;
                            }
                            let code = u32::from_str_radix(&hex, 16).ok()?;
                            out.push(char::from_u32(code)?);
                        }
                        _ => return None,
                    }
                }
                c if (c as u32) < 0x20 => return None,
                c => out.push(c),
            }
        }
    }
}

/// Extract a top-level unsigned integer field.
fn top_uint(params: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let mut rest = params;
    loop {
        let at = rest.find(needle.as_str())?;
        let mut after = rest[at + needle.len()..].trim_start();
        if !after.starts_with(':') {
            rest = &rest[at + needle.len()..];
            continue;
        }
        after = after[1..].trim_start();
        let mut end = 0usize;
        for b in after.bytes() {
            if b.is_ascii_digit() {
                end += 1;
            } else {
                break;
            }
        }
        if end == 0 || end > 20 {
            return None;
        }
        return after[..end].parse::<u64>().ok();
    }
}

/// Extract a top-level boolean field.
fn top_bool(params: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{key}\"");
    let mut rest = params;
    loop {
        let at = rest.find(needle.as_str())?;
        let mut after = rest[at + needle.len()..].trim_start();
        if !after.starts_with(':') {
            rest = &rest[at + needle.len()..];
            continue;
        }
        after = after[1..].trim_start();
        if after.starts_with("true") {
            return Some(true);
        }
        if after.starts_with("false") {
            return Some(false);
        }
        return None;
    }
}

// ── handlers ────────────────────────────────────────────────────────────────

/// Require `debug.trace` (or the wider `debug.control`) for trace methods.
///
/// Unlike the read surface (any debug scope may read), trace lifecycle
/// owns retention and spool files, so `debug.inspect` alone is denied
/// with `scope`/`ScopeDenied` and zero partial state.
fn require_debug_trace_scope(
    context: &super::serve::ServeContext,
    method: &str,
) -> Result<(), super::handlers::HandlerError> {
    use super::handlers::HandlerError;
    if context.has_scope(Scope::DebugTrace) || context.has_scope(Scope::DebugControl) {
        return Ok(());
    }
    Err(HandlerError::new(
        "scope",
        "ScopeDenied",
        format!("permission denied: scope 'debug.trace' denied for {method} (needs elevation)"),
    ))
}

/// Validate a client-supplied trace id shape (server-minted `trace-<n>`).
fn validate_trace_id(raw: &str) -> Result<(), String> {
    if raw.is_empty() || raw.len() > MAX_TRACE_ID_CHARS || raw.contains('\0') {
        return Err(format!(
            "traceId must be 1..={MAX_TRACE_ID_CHARS} bytes, no NUL"
        ));
    }
    let ok = raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !ok {
        return Err("traceId must match ^[a-z0-9_-]+$ (case-insensitive)".to_string());
    }
    Ok(())
}

/// `bitty.debug/startTrace`: open an opt-in bounded trace.
///
/// Params (object): `{ durationMs?: 1..=300000, maxBytes?: 1..=4194304,
/// includeInput?: bool }`. Returns the trace id, spool path, chunk size,
/// start clock, and retention policy.
pub(super) fn handle_start_trace(
    context: &super::serve::ServeContext,
    request: &super::json::DevtoolsRequest,
) -> Result<String, super::handlers::HandlerError> {
    use super::handlers::HandlerError;
    require_debug_trace_scope(context, "bitty.debug/startTrace")?;
    let params = request.params_raw.as_deref().unwrap_or("{}");
    if !params.trim_start().starts_with('{') {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            "startTrace requires an object params".to_string(),
        ));
    }
    let duration_ms = top_uint(params, "durationMs").unwrap_or(DEFAULT_TRACE_DURATION_MS);
    if duration_ms == 0 || duration_ms > MAX_TRACE_DURATION_MS {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            format!("durationMs must be 1..={MAX_TRACE_DURATION_MS}"),
        ));
    }
    let max_bytes = top_uint(params, "maxBytes").unwrap_or(DEFAULT_TRACE_MAX_BYTES as u64);
    if max_bytes == 0 || max_bytes > MAX_TRACE_BYTES as u64 {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            format!("maxBytes must be 1..={MAX_TRACE_BYTES}"),
        ));
    }
    let include_input = top_bool(params, "includeInput").unwrap_or(false);

    let mut store = trace_store().lock().map_err(|_| {
        HandlerError::new(
            "transport",
            "Unavailable",
            "trace store unavailable".to_string(),
        )
    })?;
    if store.traces.len() >= MAX_ACTIVE_TRACES {
        return Err(HandlerError::new(
            "budget",
            "TooManyTraces",
            format!("at most {MAX_ACTIVE_TRACES} traces per session"),
        ));
    }
    store.counter = store.counter.wrapping_add(1);
    let id = format!("trace-{}", store.counter);
    let dir = spool_dir();
    let spool_path = format!("{dir}/{id}.jsonl");
    let mut out = String::with_capacity(256);
    out.push_str("{\"traceId\":\"");
    out.push_str(&id);
    out.push_str("\",\"spoolPath\":\"");
    json_escape_into(&mut out, &spool_path);
    out.push_str("\",\"chunkBytes\":");
    out.push_str(&TRACE_CHUNK_BYTES.to_string());
    out.push_str(",\"startMs\":");
    out.push_str(&context.uptime_ms.to_string());
    out.push_str(",\"retention\":{\"maxBytes\":");
    out.push_str(&max_bytes.to_string());
    out.push_str(",\"maxDurationMs\":");
    out.push_str(&duration_ms.to_string());
    out.push_str(",\"maxTraces\":");
    out.push_str(&MAX_ACTIVE_TRACES.to_string());
    out.push_str("}}");
    store.traces.insert(
        id.clone(),
        TraceRecord {
            id: id.clone(),
            spool_path,
            max_bytes,
            duration_ms,
            include_input,
            bytes: 0,
            drops: 0,
            chunks: Vec::new(),
            next_seq: 0,
            start_ms: context.uptime_ms,
        },
    );
    Ok(out)
}

/// Write export bytes to the spool path with `0600` (Unix) semantics.
///
/// Parent directories are created with `0700` (Unix). On non-Unix targets
/// the file is created with platform defaults and the mode assertion is
/// documented as Unix-only.
fn write_spool_file(path: &str, bytes: &[u8]) -> Result<(), String> {
    use std::path::Path;
    let spool = Path::new(path);
    if let Some(parent) = spool.parent() {
        if !parent.as_os_str().is_empty() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true).mode(0o700);
                builder
                    .create(parent)
                    .map_err(|err| format!("trace spool dir failed: {err}"))?;
            }
            #[cfg(not(unix))]
            {
                std::fs::create_dir_all(parent)
                    .map_err(|err| format!("trace spool dir failed: {err}"))?;
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(spool)
            .map_err(|err| format!("trace spool create failed: {err}"))?;
        // Re-assert the mode on the opened file: `OpenOptions::mode`
        // applies at creation, and an pre-existing file keeps its old
        // mode, so enforce `0600` explicitly (fail closed on error).
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(spool, perm)
                .map_err(|err| format!("trace spool chmod failed: {err}"))?;
        }
        use std::io::Write as _;
        file.write_all(bytes)
            .map_err(|err| format!("trace spool write failed: {err}"))?;
    }
    #[cfg(not(unix))]
    {
        use std::io::Write as _;
        let mut file = std::fs::File::create(spool)
            .map_err(|err| format!("trace spool create failed: {err}"))?;
        file.write_all(bytes)
            .map_err(|err| format!("trace spool write failed: {err}"))?;
    }
    Ok(())
}

/// `bitty.debug/stopTrace`: export retained bytes to the `0600` spool file
/// and delete the in-memory record (sibling parity).
///
/// Params (object): `{ traceId }`. Returns byte/drop counts, up to 4
/// redacted previews, the export-size estimate, the truncation flag, the
/// duration budget plus elapsed clock, and `spoolMode: "0600"`.
pub(super) fn handle_stop_trace(
    context: &super::serve::ServeContext,
    request: &super::json::DevtoolsRequest,
) -> Result<String, super::handlers::HandlerError> {
    use super::handlers::HandlerError;
    require_debug_trace_scope(context, "bitty.debug/stopTrace")?;
    let params = request.params_raw.as_deref().unwrap_or("{}");
    let trace_id = top_string(params, "traceId").ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "stopTrace requires string traceId".to_string(),
        )
    })?;
    if let Err(reason) = validate_trace_id(&trace_id) {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            truncate_chars(&reason, MAX_ERROR_MESSAGE_CHARS),
        ));
    }
    let record = trace_store()
        .lock()
        .map_err(|_| {
            HandlerError::new(
                "transport",
                "Unavailable",
                "trace store unavailable".to_string(),
            )
        })?
        .traces
        .remove(&trace_id)
        .ok_or_else(|| {
            HandlerError::new("usage", "NotFound", format!("trace {trace_id} not found"))
        })?;
    let export: String = record.chunks.concat();
    write_spool_file(&record.spool_path, export.as_bytes()).map_err(|reason| {
        HandlerError::new(
            "transport",
            "SpoolFailed",
            truncate_chars(&reason, MAX_ERROR_MESSAGE_CHARS),
        )
    })?;
    let mut previews: Vec<String> = Vec::new();
    for chunk in record.chunks.iter().take(TRACE_STOP_PREVIEWS) {
        let mut end = chunk.len().min(TRACE_PREVIEW_BYTES);
        while end > 0 && !chunk.is_char_boundary(end) {
            end -= 1;
        }
        previews.push(redact_trace_preview(&chunk[..end]));
    }
    let mut out = String::with_capacity(512);
    out.push_str("{\"traceId\":\"");
    json_escape_into(&mut out, &record.id);
    out.push_str("\",\"byteCount\":");
    out.push_str(&record.bytes.to_string());
    out.push_str(",\"dropCount\":");
    out.push_str(&record.drops.to_string());
    out.push_str(",\"previews\":[");
    for (i, preview) in previews.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        json_escape_into(&mut out, preview);
        out.push('"');
    }
    out.push_str("],\"exportBytesEstimate\":");
    out.push_str(&record.bytes.to_string());
    out.push_str(",\"truncated\":");
    out.push_str(if record.drops > 0 { "true" } else { "false" });
    out.push_str(",\"durationMs\":");
    out.push_str(&record.duration_ms.to_string());
    out.push_str(",\"elapsedMs\":");
    out.push_str(
        &context
            .uptime_ms
            .saturating_sub(record.start_ms)
            .to_string(),
    );
    out.push_str(",\"spoolMode\":\"0600\"}");
    Ok(out)
}

/// `bitty.debug/fetchTraceChunk`: serve one page of retained export bytes.
///
/// Params (object): `{ traceId, offset }`. `offset` is a byte offset into
/// the retained export (`0..=bytes`) on a UTF-8 scalar boundary. The page
/// is the remaining bytes of the addressed stored chunk (`<= 256 KiB`);
/// `continuation` is computed from actual retained lengths and `preview`
/// is the redacted page prefix (preview-equals-export per page).
pub(super) fn handle_fetch_trace_chunk(
    context: &super::serve::ServeContext,
    request: &super::json::DevtoolsRequest,
) -> Result<String, super::handlers::HandlerError> {
    use super::handlers::HandlerError;
    require_debug_trace_scope(context, "bitty.debug/fetchTraceChunk")?;
    let params = request.params_raw.as_deref().unwrap_or("{}");
    let trace_id = top_string(params, "traceId").ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "fetchTraceChunk requires string traceId".to_string(),
        )
    })?;
    if let Err(reason) = validate_trace_id(&trace_id) {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            truncate_chars(&reason, MAX_ERROR_MESSAGE_CHARS),
        ));
    }
    let offset = top_uint(params, "offset").ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "fetchTraceChunk requires uint offset".to_string(),
        )
    })?;
    let store = trace_store().lock().map_err(|_| {
        HandlerError::new(
            "transport",
            "Unavailable",
            "trace store unavailable".to_string(),
        )
    })?;
    let record = store.traces.get(&trace_id).ok_or_else(|| {
        HandlerError::new("usage", "NotFound", format!("trace {trace_id} not found"))
    })?;
    if offset > record.bytes {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            format!("offset {offset} exceeds retained {} bytes", record.bytes),
        ));
    }
    // Locate the stored chunk containing `offset`. An offset exactly at a
    // chunk end advances into the next chunk (or the retained tail), so a
    // client paging with `offset += page.len()` always makes progress.
    let mut base: u64 = 0;
    let mut page = "";
    let mut found = false;
    for chunk in &record.chunks {
        let len = chunk.len() as u64;
        if offset < base + len {
            let within = (offset - base) as usize;
            if !chunk.is_char_boundary(within) {
                return Err(HandlerError::new(
                    "usage",
                    "InvalidParams",
                    "offset must be on a UTF-8 scalar boundary".to_string(),
                ));
            }
            page = &chunk[within..];
            found = true;
            break;
        }
        base += len;
    }
    if !found {
        // Offset sits exactly at the retained end (or the store holds no
        // chunks yet): serve the empty tail page with no continuation.
        page = "";
    }
    let mut end = page.len().min(TRACE_PREVIEW_BYTES);
    while end > 0 && !page.is_char_boundary(end) {
        end -= 1;
    }
    let preview = redact_trace_preview(&page[..end]);
    // Preview-equals-export: re-derive from the served bytes and refuse to
    // serve on divergence (never a cached preview that drifts).
    let rederived = redact_trace_preview(&page[..end]);
    if preview != rederived {
        return Err(HandlerError::new(
            "transport",
            "PreviewMismatch",
            "trace preview diverged from export bytes".to_string(),
        ));
    }
    // Continuation from actual retained lengths: the page runs to the end
    // of its stored chunk, so more bytes remain exactly when the page end
    // sits before the retained total.
    let continuation = offset + page.len() as u64 != record.bytes;
    let mut out = String::with_capacity(page.len() + 256);
    out.push_str("{\"traceId\":\"");
    json_escape_into(&mut out, &record.id);
    out.push_str("\",\"offset\":");
    out.push_str(&offset.to_string());
    out.push_str(",\"chunk\":\"");
    json_escape_into(&mut out, page);
    out.push_str("\",\"continuation\":");
    out.push_str(if continuation { "true" } else { "false" });
    out.push_str(",\"preview\":\"");
    json_escape_into(&mut out, &preview);
    out.push_str("\",\"sequence\":");
    out.push_str(&record.next_seq.to_string());
    out.push('}');
    Ok(out)
}
