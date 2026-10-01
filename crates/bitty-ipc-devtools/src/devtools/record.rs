//! Deterministic record/replay hooks, staged v1 (DT-08, #1104).
//!
//! Accepted staging from `devtools-rfc.md` (record/replay section): v1
//! provides deterministic capture hooks for parser inputs, semantic
//! actions, configuration diagnostics, and lifecycle transitions. The
//! hooks are present but **disabled by default**; enabling them requires
//! explicit opt-in ([`set_recording_opt_in`], which the serving path gates
//! behind a `debug.trace` session), recordings are redacted before
//! retention (P0-AC-026 parity), and input markers need an additional
//! per-recording `include_input` opt-in.
//!
//! Replay runs only inside the headless harness and the test suite: the
//! [`replay_recording`] driver takes a caller-supplied closure, so the
//! harness decides how each entry is applied. There is no automatic
//! in-application re-execution path, and this module can never execute
//! plugin code by construction — it depends only on `std` and carries
//! data (bytes and labels), never callbacks into the plugin host.
//!
//! Every accepted synthetic entry carries an indelible synthetic-origin
//! marker ([`RecordEntry::synthetic`]), so a replay can always
//! distinguish harness input from user input (test-automation semantics
//! parity).

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

// ── bounds ──────────────────────────────────────────────────────────────────

/// Maximum active recordings at once.
pub const MAX_ACTIVE_RECORDINGS: usize = 4;

/// Maximum entries retained per recording.
pub const MAX_RECORD_ENTRIES: usize = 1024;

/// Maximum retained bytes per recording (observability per-plugin parity).
pub const MAX_RECORD_BYTES: usize = 256 * 1024;

/// Maximum bytes for one recorded detail line.
pub const MAX_RECORD_DETAIL_BYTES: usize = 8 * 1024;

/// Maximum characters for a recording owner label.
pub const MAX_RECORD_OWNER_CHARS: usize = 64;

/// Maximum characters for a record action/transition label.
pub const MAX_RECORD_LABEL_CHARS: usize = 128;

/// Maximum characters for a recording id (`rec-<n>`, server-minted).
pub const MAX_RECORD_ID_CHARS: usize = 64;

/// Redaction marker replacing sensitive details (P0-AC-026 parity with
/// the trace and frame-capture paths).
pub const RECORD_REDACTED_MARKER: &str = "[redacted]";

// ── types ───────────────────────────────────────────────────────────────────

/// What was captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// Parser input bytes (hex-encoded at the boundary, deterministic).
    ParserInput,
    /// One semantic action label.
    SemanticAction,
    /// Configuration diagnostic line.
    ConfigDiagnostic,
    /// Lifecycle transition label.
    LifecycleTransition,
    /// Harness input marker (synthetic origin, `include_input`-gated).
    InputMarker,
}

impl RecordKind {
    /// Stable name for output.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::ParserInput => "parser-input",
            Self::SemanticAction => "semantic-action",
            Self::ConfigDiagnostic => "config-diagnostic",
            Self::LifecycleTransition => "lifecycle-transition",
            Self::InputMarker => "input-marker",
        }
    }
}

/// One retained record entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEntry {
    /// Monotonic sequence within the recording.
    pub seq: u64,
    /// What was captured.
    pub kind: RecordKind,
    /// Redacted detail (hex bytes, label, or marker).
    pub detail: String,
    /// Indelible synthetic-origin marker: always true for input markers
    /// and harness-recorded parser inputs, false for passive observations.
    pub synthetic: bool,
}

/// An immutable finished recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recording {
    /// Server-minted id.
    pub id: String,
    /// Owner label from [`start_recording`] (audit attribution).
    pub owner: String,
    /// Retained entries in sequence order.
    pub entries: Vec<RecordEntry>,
    /// Retained detail bytes.
    pub bytes: usize,
    /// Counted drops (budget/input rejections during capture).
    pub drops: u64,
    /// Whether input markers were retained.
    pub include_input: bool,
}

/// Record failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// Capture hooks are disabled (default): opt in first.
    NotOptedIn,
    /// No active recording with this id.
    NotFound,
    /// Store lock unavailable.
    Unavailable,
    /// Detail shape invalid (bounded reason).
    InvalidDetail(String),
    /// Too many active recordings.
    TooMany,
}

impl RecordError {
    /// Stable error code for logs.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotOptedIn => "NotOptedIn",
            Self::NotFound => "NotFound",
            Self::Unavailable => "Unavailable",
            Self::InvalidDetail(_) => "InvalidDetail",
            Self::TooMany => "TooMany",
        }
    }
}

// ── redaction ───────────────────────────────────────────────────────────────

/// Whether a detail carries secret-shaped content (P0-AC-026 parity:
/// seeded secrets, clipboard bytes, environment bytes never appear in
/// default outputs).
fn is_sensitive_record_detail(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
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

// ── store ───────────────────────────────────────────────────────────────────

/// Global opt-in (disabled by default; the serving path enables it only
/// for an explicit `debug.trace` session).
static RECORD_OPT_IN: OnceLock<std::sync::atomic::AtomicBool> = OnceLock::new();

fn record_opt_in_flag() -> &'static std::sync::atomic::AtomicBool {
    use std::sync::atomic::AtomicBool;
    RECORD_OPT_IN.get_or_init(|| AtomicBool::new(false))
}

/// Enable or disable the capture hooks (serving path and tests).
///
/// Disabled by default. There is deliberately no environment-variable,
/// flag, or configuration path that enables this (no-bypass parity).
pub fn set_recording_opt_in(enabled: bool) {
    record_opt_in_flag().store(enabled, std::sync::atomic::Ordering::SeqCst);
}

/// Whether the capture hooks are currently enabled.
#[must_use]
pub fn is_recording_opt_in() -> bool {
    record_opt_in_flag().load(std::sync::atomic::Ordering::SeqCst)
}

/// One active recording.
#[derive(Debug)]
struct ActiveRecording {
    /// Server-minted id.
    id: String,
    /// Owner label.
    owner: String,
    /// Whether input markers are retained.
    include_input: bool,
    /// Retained entries.
    entries: Vec<RecordEntry>,
    /// Retained detail bytes.
    bytes: usize,
    /// Counted drops.
    drops: u64,
    /// Next entry sequence.
    next_seq: u64,
}

/// In-memory recording store (never persisted, never exported).
#[derive(Debug, Default)]
struct RecordStore {
    /// Active recordings by id.
    recordings: BTreeMap<String, ActiveRecording>,
    /// Issuance counter.
    counter: u64,
}

fn record_store() -> &'static Mutex<RecordStore> {
    static STORE: OnceLock<Mutex<RecordStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(RecordStore::default()))
}

/// Number of active recordings (tests).
#[must_use]
pub fn recording_count_for_tests() -> usize {
    record_store()
        .lock()
        .map(|store| store.recordings.len())
        .unwrap_or(0)
}

/// Clear all recordings and reset opt-in (tests).
pub fn clear_recordings_for_tests() {
    if let Ok(mut store) = record_store().lock() {
        store.recordings.clear();
        store.counter = 0;
    }
    set_recording_opt_in(false);
}

fn validate_owner(owner: &str) -> Result<(), RecordError> {
    if owner.is_empty()
        || owner.chars().count() > MAX_RECORD_OWNER_CHARS
        || owner.contains('\0')
        || owner.bytes().any(|b| b < 0x20 || b == 0x7F)
    {
        return Err(RecordError::InvalidDetail(
            "owner must be 1..=64 chars, no control bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), RecordError> {
    if label.is_empty()
        || label.chars().count() > MAX_RECORD_LABEL_CHARS
        || label.contains('\0')
        || label.bytes().any(|b| b < 0x20 || b == 0x7F)
    {
        return Err(RecordError::InvalidDetail(
            "label must be 1..=128 chars, no control bytes".to_string(),
        ));
    }
    Ok(())
}

/// Start one recording (requires opt-in).
///
/// Returns the server-minted id (`rec-<n>`).
///
/// # Errors
///
/// Returns [`RecordError::NotOptedIn`] when the hooks are disabled,
/// [`RecordError::TooMany`] past [`MAX_ACTIVE_RECORDINGS`], and
/// [`RecordError::InvalidDetail`] for an ill-shaped owner.
pub fn start_recording(owner: &str, include_input: bool) -> Result<String, RecordError> {
    if !is_recording_opt_in() {
        return Err(RecordError::NotOptedIn);
    }
    validate_owner(owner)?;
    let mut store = record_store()
        .lock()
        .map_err(|_| RecordError::Unavailable)?;
    if store.recordings.len() >= MAX_ACTIVE_RECORDINGS {
        return Err(RecordError::TooMany);
    }
    store.counter = store.counter.wrapping_add(1);
    let id = format!("rec-{}", store.counter);
    store.recordings.insert(
        id.clone(),
        ActiveRecording {
            id: id.clone(),
            owner: owner.to_string(),
            include_input,
            entries: Vec::new(),
            bytes: 0,
            drops: 0,
            next_seq: 0,
        },
    );
    Ok(id)
}

/// Retain one entry (shared admission: redaction, budget, bounds).
///
/// Returns `Ok(true)` when retained and `Ok(false)` when dropped with a
/// counted drop (input gating, per-recording budget); retained bytes and
/// entries stay unchanged on a drop.
fn retain_entry(
    record: &mut ActiveRecording,
    kind: RecordKind,
    detail: &str,
    synthetic: bool,
) -> Result<bool, RecordError> {
    if detail.len() > MAX_RECORD_DETAIL_BYTES {
        return Err(RecordError::InvalidDetail(format!(
            "detail must be 0..={MAX_RECORD_DETAIL_BYTES} bytes"
        )));
    }
    if kind == RecordKind::InputMarker && !record.include_input {
        record.drops += 1;
        return Ok(false);
    }
    if record.entries.len() >= MAX_RECORD_ENTRIES || record.bytes + detail.len() > MAX_RECORD_BYTES
    {
        record.drops += 1;
        return Ok(false);
    }
    let kept = if is_sensitive_record_detail(detail) {
        RECORD_REDACTED_MARKER.to_string()
    } else {
        detail.to_string()
    };
    let seq = record.next_seq;
    record.bytes += kept.len();
    record.entries.push(RecordEntry {
        seq,
        kind,
        detail: kept,
        synthetic,
    });
    record.next_seq += 1;
    Ok(true)
}

fn with_recording(
    id: &str,
    f: impl FnOnce(&mut ActiveRecording) -> Result<bool, RecordError>,
) -> Result<bool, RecordError> {
    if !is_recording_opt_in() {
        return Err(RecordError::NotOptedIn);
    }
    let mut store = record_store()
        .lock()
        .map_err(|_| RecordError::Unavailable)?;
    let record = store.recordings.get_mut(id).ok_or(RecordError::NotFound)?;
    f(record)
}

/// Record parser input bytes (hex-encoded, synthetic origin).
///
/// Bytes are hex-encoded at the boundary so retention is deterministic
/// text and never raw terminal output.
pub fn record_parser_input(id: &str, bytes: &[u8]) -> Result<bool, RecordError> {
    if bytes.len() * 2 > MAX_RECORD_DETAIL_BYTES {
        return Err(RecordError::InvalidDetail(format!(
            "input must be 0..={} bytes",
            MAX_RECORD_DETAIL_BYTES / 2
        )));
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0x0F) as usize] as char);
    }
    with_recording(id, |record| {
        retain_entry(record, RecordKind::ParserInput, &hex, true)
    })
}

/// Record one semantic action label (passive observation).
pub fn record_action(id: &str, action: &str) -> Result<bool, RecordError> {
    validate_label(action)?;
    with_recording(id, |record| {
        retain_entry(record, RecordKind::SemanticAction, action, false)
    })
}

/// Record one configuration diagnostic line (passive observation).
pub fn record_config_diagnostic(id: &str, detail: &str) -> Result<bool, RecordError> {
    validate_label(detail)?;
    with_recording(id, |record| {
        retain_entry(record, RecordKind::ConfigDiagnostic, detail, false)
    })
}

/// Record one lifecycle transition label (passive observation).
pub fn record_lifecycle(id: &str, transition: &str) -> Result<bool, RecordError> {
    validate_label(transition)?;
    with_recording(id, |record| {
        retain_entry(record, RecordKind::LifecycleTransition, transition, false)
    })
}

/// Record one harness input marker (synthetic origin, `include_input`-gated).
pub fn record_input_marker(id: &str, marker: &str) -> Result<bool, RecordError> {
    validate_label(marker)?;
    with_recording(id, |record| {
        retain_entry(record, RecordKind::InputMarker, marker, true)
    })
}

/// Stop a recording and return the immutable result.
pub fn stop_recording(id: &str) -> Result<Recording, RecordError> {
    if !is_recording_opt_in() {
        return Err(RecordError::NotOptedIn);
    }
    if id.is_empty() || id.len() > MAX_RECORD_ID_CHARS {
        return Err(RecordError::InvalidDetail(
            "id must be 1..=64 bytes".to_string(),
        ));
    }
    let mut store = record_store()
        .lock()
        .map_err(|_| RecordError::Unavailable)?;
    let record = store.recordings.remove(id).ok_or(RecordError::NotFound)?;
    Ok(Recording {
        id: record.id,
        owner: record.owner,
        entries: record.entries,
        bytes: record.bytes,
        drops: record.drops,
        include_input: record.include_input,
    })
}

// ── replay ──────────────────────────────────────────────────────────────────

/// What the headless driver did with one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// The driver applied the entry.
    Applied,
    /// The driver skipped the entry (e.g. input markers in a passive run).
    Skipped,
}

/// Determinism report for one replay run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayReport {
    /// Entries the driver applied.
    pub applied: usize,
    /// Entries the driver skipped.
    pub skipped: usize,
    /// FNV-1a digest over the applied `(seq, kind, detail)` triplets:
    /// the same recording plus the same driver decisions always yields
    /// the same digest.
    pub digest_hex: String,
}

/// Replay a finished recording through a headless driver.
///
/// The driver closure receives every entry in sequence order and returns
/// whether it applied it. This function executes no plugin code and
/// re-executes nothing by itself: it only walks data and digests the
/// driver's decisions, so replay stays a harness-and-test-suite path.
pub fn replay_recording(
    recording: &Recording,
    mut driver: impl FnMut(&RecordEntry) -> ReplayVerdict,
) -> ReplayReport {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET;
    let mut mix = |bytes: &[u8]| {
        for b in bytes {
            hash ^= u64::from(*b);
            hash = hash.wrapping_mul(PRIME);
        }
    };
    let mut applied = 0usize;
    let mut skipped = 0usize;
    for entry in &recording.entries {
        match driver(entry) {
            ReplayVerdict::Applied => {
                applied += 1;
                mix(&entry.seq.to_le_bytes());
                mix(entry.kind.name().as_bytes());
                mix(entry.detail.as_bytes());
            }
            ReplayVerdict::Skipped => {
                skipped += 1;
            }
        }
    }
    ReplayReport {
        applied,
        skipped,
        digest_hex: format!("{hash:016x}"),
    }
}
