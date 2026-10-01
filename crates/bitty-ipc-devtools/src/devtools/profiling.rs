use super::*;

use super::handlers::{json_escape_into, parse_optional_uint_param};

use std::sync::{Mutex, OnceLock};

// ── live profiling (CTX-0189, Amendment A1 candidate) ───────────────────────
//
// Read-only observation of process and rendering health through the same
// versioned debug protocol. Metric definitions and measurement conditions
// are reused from the Performance Budget RFC (PB-2 idle memory, PB-3
// typical-session memory and growth, PB-4 input latency, PB-7 idle
// resources); this surface observes those budgets and changes no number.
//
// Sampling is the only posture: the host publishes pre-aggregated counters
// on the cold path (`publish_process_stats` / `publish_frame_stats`,
// `&self`-style side-effect-free entry points the runtime drives from its
// sampler); this module retains the latest [`MAX_PROF_SAMPLES`] records per
// family (drop-oldest, counted) and serves point-in-time getters plus
// cursor-based stream drains over the accepted batching (32 records or
// 8 KiB per wakeup, sequence plus drop-count headers). No profiler code
// runs on the parser, render, or input hot paths; no per-frame tracing and
// no sub-100 ms cadence exists in this scope.
//
// Privacy: records carry zero terminal bytes (no PTY output, no clipboard,
// no environment maps, no frame text). The only string is the
// renderer-supplied backend label, bounded to [`MAX_PROF_LABEL_CHARS`]
// characters with control bytes stripped at publish time, and every
// frame-stats response carries `"trust":"untrusted-observation"` (T-10
// parity). No profiling state crosses the v1 MCP adapter.
//
// Authorization: getters require `debug.inspect`; streams require
// `debug.trace`. Scope checks run before any state is touched; unscoped
// callers get `scope`/`ScopeDenied` with zero partial state (fail closed).
// Reads are in-memory bounded ring reads under the transport RC-9 rate
// limits, so no per-method rate ceiling applies; the declared stream
// cadence is validated against the 100 ms floor instead (client-paced
// polling, server-enforced floor).

/// Process health counters published by the host sampler (numeric only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessStatsPublish {
    /// Resident set size in bytes (PB-2/PB-3 conditions).
    pub rss_bytes: u64,
    /// Average CPU over `window_ms`, fixed-point percent x100 (PB-7
    /// conditions; e.g. 1% reads as 100). Multi-core hosts may exceed 100%.
    pub cpu_avg_pct_x100: u32,
    /// Live task count (PB-7 conditions).
    pub tasks: u64,
    /// Live timer count (PB-7 conditions).
    pub timers: u64,
    /// Window the CPU average covers, in ms (bounded to
    /// [`MAX_PROF_WINDOW_MS`]).
    pub window_ms: u64,
}

/// Rendering health counters published by the host sampler (numeric only,
/// plus one bounded renderer label).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameStatsPublish {
    /// Frame-time p50 in microseconds (PB-4 conditions).
    pub frame_p50_us: u64,
    /// Frame-time p99 in microseconds (PB-4 conditions).
    pub frame_p99_us: u64,
    /// Presented frames per second.
    pub presented_fps: u32,
    /// Missed-present (dropped vsync) count, monotonic.
    pub missed_presents: u64,
    /// GPU memory in bytes where the renderer exposes it (`None` omits the
    /// field rather than fabricating a zero).
    pub gpu_bytes: Option<u64>,
    /// Renderer backend label (e.g. `"wgpu-vulkan"`); truncated to
    /// [`MAX_PROF_LABEL_CHARS`] characters, control bytes stripped, never
    /// terminal content.
    pub backend: String,
}

/// One retained process sample (monotonic `seq`, host clock `now_ms`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ProcessSample {
    /// Monotonic per-family sequence (starts at 1).
    seq: u64,
    /// Host monotonic clock at sampling time (ms; matches the
    /// `ServeContext::uptime_ms` base, never wall-clock).
    now_ms: u64,
    /// Resident set size in bytes.
    rss_bytes: u64,
    /// Average CPU percent x100 over `window_ms`.
    cpu_avg_pct_x100: u32,
    /// Live task count.
    tasks: u64,
    /// Live timer count.
    timers: u64,
    /// CPU-average window in ms.
    window_ms: u64,
}

/// One retained frame sample (monotonic `seq`, host clock `now_ms`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct FrameSample {
    /// Monotonic per-family sequence (starts at 1).
    seq: u64,
    /// Host monotonic clock at sampling time (ms).
    now_ms: u64,
    /// Frame-time p50 in microseconds.
    frame_p50_us: u64,
    /// Frame-time p99 in microseconds.
    frame_p99_us: u64,
    /// Presented frames per second.
    presented_fps: u32,
    /// Missed-present count, monotonic.
    missed_presents: u64,
    /// GPU memory in bytes, when exposed.
    gpu_bytes: Option<u64>,
    /// Bounded renderer backend label (untrusted observation data).
    backend: String,
}

/// Profiling store: two bounded latest-wins rings with counted drops.
#[derive(Debug, Default)]
struct ProfilingStore {
    /// Retained process samples (drop-oldest at [`MAX_PROF_SAMPLES`]).
    process: std::collections::VecDeque<ProcessSample>,
    /// Retained frame samples (drop-oldest at [`MAX_PROF_SAMPLES`]).
    frame: std::collections::VecDeque<FrameSample>,
    /// Next process sequence (monotonic, never reused).
    process_seq: u64,
    /// Process samples dropped at the bound (cumulative).
    process_dropped: u64,
    /// Next frame sequence (monotonic, never reused).
    frame_seq: u64,
    /// Frame samples dropped at the bound (cumulative).
    frame_dropped: u64,
}

/// Live profiling store (empty until the host sampler publishes).
fn live_profiling_store() -> &'static Mutex<ProfilingStore> {
    static STORE: OnceLock<Mutex<ProfilingStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(ProfilingStore::default()))
}

/// Sanitize a renderer label: strip NUL/control bytes, truncate to
/// [`MAX_PROF_LABEL_CHARS`] characters (char-boundary safe, no ellipsis so
/// the bound holds exactly).
fn sanitize_prof_label(raw: &str) -> String {
    let clean: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_PROF_LABEL_CHARS)
        .collect();
    clean
}

/// Publish one process sample (called by the host sampler on the cold path).
///
/// The ring is latest-wins: beyond [`MAX_PROF_SAMPLES`] the oldest sample
/// is dropped and the drop counter increments (consumers converge to latest
/// state). `window_ms` is clamped to `1..=[`MAX_PROF_WINDOW_MS`]`; a
/// poisoned mutex fails closed by dropping the publish (the next tick
/// republishes).
pub fn publish_process_stats(now_ms: u64, stats: ProcessStatsPublish) {
    let Ok(mut store) = live_profiling_store().lock() else {
        return;
    };
    store.process_seq = store.process_seq.saturating_add(1);
    let seq = store.process_seq;
    if store.process.len() >= MAX_PROF_SAMPLES {
        store.process.pop_front();
        store.process_dropped = store.process_dropped.saturating_add(1);
    }
    store.process.push_back(ProcessSample {
        seq,
        now_ms,
        rss_bytes: stats.rss_bytes,
        cpu_avg_pct_x100: stats.cpu_avg_pct_x100,
        tasks: stats.tasks,
        timers: stats.timers,
        window_ms: stats.window_ms.clamp(1, MAX_PROF_WINDOW_MS),
    });
}

/// Publish one frame sample (called by the host sampler on the cold path).
///
/// Same latest-wins ring discipline as [`publish_process_stats`]. The
/// backend label is sanitized (control bytes stripped, truncated to
/// [`MAX_PROF_LABEL_CHARS`] characters) so no terminal content can enter
/// the store through a renderer string.
pub fn publish_frame_stats(now_ms: u64, stats: FrameStatsPublish) {
    let Ok(mut store) = live_profiling_store().lock() else {
        return;
    };
    store.frame_seq = store.frame_seq.saturating_add(1);
    let seq = store.frame_seq;
    if store.frame.len() >= MAX_PROF_SAMPLES {
        store.frame.pop_front();
        store.frame_dropped = store.frame_dropped.saturating_add(1);
    }
    store.frame.push_back(FrameSample {
        seq,
        now_ms,
        frame_p50_us: stats.frame_p50_us,
        frame_p99_us: stats.frame_p99_us,
        presented_fps: stats.presented_fps,
        missed_presents: stats.missed_presents,
        gpu_bytes: stats.gpu_bytes,
        backend: sanitize_prof_label(&stats.backend),
    });
}

/// Clear the live profiling store (test helper only; production never calls
/// it). Tests publish known samples and must not leak them into parallel
/// tests sharing the process-global store.
pub fn clear_profiling_for_tests() {
    if let Ok(mut store) = live_profiling_store().lock() {
        store.process.clear();
        store.frame.clear();
        store.process_seq = 0;
        store.process_dropped = 0;
        store.frame_seq = 0;
        store.frame_dropped = 0;
    }
}

/// Require one debug scope for a profiling call (fail-closed).
///
/// Scope checks run before any state is touched; denial carries the typed
/// `scope`/`ScopeDenied` shape with zero partial state.
fn require_profiling_scope(
    context: &super::serve::ServeContext,
    scope: bitty_ipc_api::scope::Scope,
) -> Result<(), HandlerError> {
    if context.has_scope(scope) {
        return Ok(());
    }
    Err(HandlerError::new(
        "scope",
        "ScopeDenied",
        format!(
            "permission denied: scope '{}' denied for profiling (needs elevation)",
            scope.as_str()
        ),
    ))
}

/// Parse the declared stream cadence `intervalMs` (default
/// [`DEFAULT_PROF_INTERVAL_MS`]; fail-closed outside
/// `MIN_PROF_INTERVAL_MS..=MAX_PROF_INTERVAL_MS` or when present but not a
/// plain non-negative integer).
fn parse_interval_ms_param(params_raw: Option<&str>) -> Result<u64, HandlerError> {
    let invalid = || {
        HandlerError::new(
            "usage",
            "InvalidParams",
            format!("params intervalMs must be {MIN_PROF_INTERVAL_MS}..={MAX_PROF_INTERVAL_MS}"),
        )
    };
    let Some(params) = params_raw else {
        return Ok(DEFAULT_PROF_INTERVAL_MS);
    };
    let needle = "\"intervalMs\"";
    let Some(key_pos) = params.find(needle) else {
        return Ok(DEFAULT_PROF_INTERVAL_MS);
    };
    let after_key = &params[key_pos + needle.len()..];
    let Some(colon) = after_key.find(':') else {
        return Err(invalid());
    };
    let mut value_part = after_key[colon + 1..].trim_start();
    if value_part.starts_with('"')
        || value_part.starts_with('{')
        || value_part.starts_with('[')
        || value_part.starts_with('-')
        || value_part.starts_with('+')
    {
        return Err(invalid());
    }
    let mut len = 0usize;
    for b in value_part.bytes() {
        if b.is_ascii_digit() {
            len += 1;
        } else {
            break;
        }
    }
    if len == 0 || len > 6 {
        return Err(invalid());
    }
    value_part = &value_part[..len];
    let value: u64 = value_part.parse().map_err(|_| invalid())?;
    if !(MIN_PROF_INTERVAL_MS..=MAX_PROF_INTERVAL_MS).contains(&value) {
        return Err(invalid());
    }
    Ok(value)
}

/// Parse the stream cursor `afterSeq` (default 0: drain from the oldest
/// retained sample; fail-closed when present but not a plain non-negative
/// integer).
fn parse_after_seq_param(params_raw: Option<&str>) -> Result<u64, HandlerError> {
    let invalid = || {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "params afterSeq must be a non-negative integer".to_string(),
        )
    };
    let Some(params) = params_raw else {
        return Ok(0);
    };
    let needle = "\"afterSeq\"";
    let Some(key_pos) = params.find(needle) else {
        return Ok(0);
    };
    let after_key = &params[key_pos + needle.len()..];
    let Some(colon) = after_key.find(':') else {
        return Err(invalid());
    };
    let mut value_part = after_key[colon + 1..].trim_start();
    if value_part.starts_with('"')
        || value_part.starts_with('{')
        || value_part.starts_with('[')
        || value_part.starts_with('-')
        || value_part.starts_with('+')
    {
        return Err(invalid());
    }
    let mut len = 0usize;
    for b in value_part.bytes() {
        if b.is_ascii_digit() {
            len += 1;
        } else {
            break;
        }
    }
    if len == 0 || len > 20 {
        return Err(invalid());
    }
    value_part = &value_part[..len];
    value_part.parse().map_err(|_| invalid())
}

/// Encode one process sample as a JSON object (numeric fields only; zero
/// terminal bytes by construction).
fn encode_process_sample(out: &mut String, sample: &ProcessSample) {
    out.push_str("{\"seq\":");
    out.push_str(&sample.seq.to_string());
    out.push_str(",\"nowMs\":");
    out.push_str(&sample.now_ms.to_string());
    out.push_str(",\"rssBytes\":");
    out.push_str(&sample.rss_bytes.to_string());
    out.push_str(",\"cpuAvgPctX100\":");
    out.push_str(&sample.cpu_avg_pct_x100.to_string());
    out.push_str(",\"cpuWindowMs\":");
    out.push_str(&sample.window_ms.to_string());
    out.push_str(",\"tasks\":");
    out.push_str(&sample.tasks.to_string());
    out.push_str(",\"timers\":");
    out.push_str(&sample.timers.to_string());
    out.push('}');
}

/// Encode one frame sample as a JSON object (numeric fields plus the
/// bounded renderer label; zero terminal bytes by construction).
fn encode_frame_sample(out: &mut String, sample: &FrameSample) {
    out.push_str("{\"seq\":");
    out.push_str(&sample.seq.to_string());
    out.push_str(",\"nowMs\":");
    out.push_str(&sample.now_ms.to_string());
    out.push_str(",\"frameP50Us\":");
    out.push_str(&sample.frame_p50_us.to_string());
    out.push_str(",\"frameP99Us\":");
    out.push_str(&sample.frame_p99_us.to_string());
    out.push_str(",\"presentedFps\":");
    out.push_str(&sample.presented_fps.to_string());
    out.push_str(",\"missedPresents\":");
    out.push_str(&sample.missed_presents.to_string());
    if let Some(gpu) = sample.gpu_bytes {
        out.push_str(",\"gpuBytes\":");
        out.push_str(&gpu.to_string());
    }
    out.push_str(",\"backend\":\"");
    json_escape_into(out, &sample.backend);
    out.push_str("\"}");
}

/// `bitty.debug/getProcessStats`: latest process health snapshot.
///
/// Requires `debug.inspect`. Returns numeric aggregates only (RSS, average
/// CPU over a bounded window, task/timer counts); an empty store returns
/// `"sample":"none"` with no numeric fields rather than fabricated zeros.
pub(super) fn handle_get_process_stats(
    context: &ServeContext,
    _request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    use bitty_ipc_api::scope::Scope::DebugInspect;
    require_profiling_scope(context, DebugInspect)?;
    let guard = live_profiling_store().lock().map_err(|_| {
        HandlerError::new(
            "transport",
            "Unavailable",
            "profiling store unavailable".to_string(),
        )
    })?;
    let mut out = String::with_capacity(256);
    out.push_str("{\"version\":\"");
    out.push_str(DEVTOOLS_PROTOCOL_VERSION);
    out.push_str("\",\"snapshot\":\"process-stats\"");
    let Some(latest) = guard.process.back() else {
        out.push_str(",\"sample\":\"none\"}");
        return Ok(out);
    };
    out.push_str(",\"sample\":\"latest\",\"seq\":");
    out.push_str(&latest.seq.to_string());
    out.push_str(",\"nowMs\":");
    out.push_str(&latest.now_ms.to_string());
    out.push_str(",\"rssBytes\":");
    out.push_str(&latest.rss_bytes.to_string());
    out.push_str(",\"cpuAvgPctX100\":");
    out.push_str(&latest.cpu_avg_pct_x100.to_string());
    out.push_str(",\"cpuWindowMs\":");
    out.push_str(&latest.window_ms.to_string());
    out.push_str(",\"tasks\":");
    out.push_str(&latest.tasks.to_string());
    out.push_str(",\"timers\":");
    out.push_str(&latest.timers.to_string());
    out.push('}');
    Ok(out)
}

/// `bitty.debug/getFrameStats`: latest rendering health snapshot.
///
/// Requires `debug.inspect`. Returns numeric aggregates plus the bounded
/// renderer backend label (`gpuBytes` present only when the renderer
/// exposes it); every response carries `"trust":"untrusted-observation"`.
/// An empty store returns `"sample":"none"` with no numeric fields.
pub(super) fn handle_get_frame_stats(
    context: &ServeContext,
    _request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    use bitty_ipc_api::scope::Scope::DebugInspect;
    require_profiling_scope(context, DebugInspect)?;
    let guard = live_profiling_store().lock().map_err(|_| {
        HandlerError::new(
            "transport",
            "Unavailable",
            "profiling store unavailable".to_string(),
        )
    })?;
    let mut out = String::with_capacity(256);
    out.push_str("{\"version\":\"");
    out.push_str(DEVTOOLS_PROTOCOL_VERSION);
    out.push_str("\",\"snapshot\":\"frame-stats\"");
    let Some(latest) = guard.frame.back() else {
        out.push_str(",\"sample\":\"none\",\"trust\":\"untrusted-observation\"}");
        return Ok(out);
    };
    out.push_str(",\"sample\":\"latest\",\"seq\":");
    out.push_str(&latest.seq.to_string());
    out.push_str(",\"nowMs\":");
    out.push_str(&latest.now_ms.to_string());
    out.push_str(",\"frameP50Us\":");
    out.push_str(&latest.frame_p50_us.to_string());
    out.push_str(",\"frameP99Us\":");
    out.push_str(&latest.frame_p99_us.to_string());
    out.push_str(",\"presentedFps\":");
    out.push_str(&latest.presented_fps.to_string());
    out.push_str(",\"missedPresents\":");
    out.push_str(&latest.missed_presents.to_string());
    if let Some(gpu) = latest.gpu_bytes {
        out.push_str(",\"gpuBytes\":");
        out.push_str(&gpu.to_string());
    }
    out.push_str(",\"backend\":\"");
    json_escape_into(&mut out, &latest.backend);
    out.push_str("\",\"trust\":\"untrusted-observation\"}");
    Ok(out)
}

/// Drain retained process samples newer than `after_seq` (non-destructive
/// cursor read; at most `max` records and [`MAX_PROF_DRAIN_BYTES`] encoded
/// bytes). Returns the encoded array body, whether retained records were
/// omitted (`truncated`, i.e. re-poll with a newer cursor to continue), and
/// the current head sequence plus cumulative drops for the header.
/// Historical loss (dropped before the cursor window) surfaces via `dropped`
/// and the head `seq`, never via `truncated`: `truncated` is strictly "this
/// response omits records that are still retained".
fn drain_process_samples(after_seq: u64, max: usize) -> (String, bool, u64, u64) {
    let Ok(guard) = live_profiling_store().lock() else {
        return (String::new(), false, 0, 0);
    };
    let mut body = String::with_capacity(1024);
    let mut truncated = false;
    for (emitted, sample) in guard
        .process
        .iter()
        .filter(|s| s.seq > after_seq)
        .enumerate()
    {
        if emitted >= max {
            truncated = true;
            break;
        }
        let mut encoded = String::with_capacity(160);
        encode_process_sample(&mut encoded, sample);
        let add = encoded.len() + usize::from(emitted > 0);
        if body.len() + add > MAX_PROF_DRAIN_BYTES {
            truncated = true;
            break;
        }
        if emitted > 0 {
            body.push(',');
        }
        body.push_str(&encoded);
    }
    (
        body,
        truncated,
        store_head_seq_process(&guard),
        guard.process_dropped,
    )
}

/// Drain retained frame samples newer than `after_seq` (same cursor
/// discipline as [`drain_process_samples`]).
fn drain_frame_samples(after_seq: u64, max: usize) -> (String, bool, u64, u64) {
    let Ok(guard) = live_profiling_store().lock() else {
        return (String::new(), false, 0, 0);
    };
    let mut body = String::with_capacity(1024);
    let mut truncated = false;
    for (emitted, sample) in guard.frame.iter().filter(|s| s.seq > after_seq).enumerate() {
        if emitted >= max {
            truncated = true;
            break;
        }
        let mut encoded = String::with_capacity(192);
        encode_frame_sample(&mut encoded, sample);
        let add = encoded.len() + usize::from(emitted > 0);
        if body.len() + add > MAX_PROF_DRAIN_BYTES {
            truncated = true;
            break;
        }
        if emitted > 0 {
            body.push(',');
        }
        body.push_str(&encoded);
    }
    (
        body,
        truncated,
        store_head_seq_frame(&guard),
        guard.frame_dropped,
    )
}

/// Head process sequence (0 when the ring is empty).
fn store_head_seq_process(store: &ProfilingStore) -> u64 {
    store.process.back().map_or(0, |s| s.seq)
}

/// Head frame sequence (0 when the ring is empty).
fn store_head_seq_frame(store: &ProfilingStore) -> u64 {
    store.frame.back().map_or(0, |s| s.seq)
}

/// `bitty.debug/streamProcessStats`: sampled process-stats subscription.
///
/// Requires `debug.trace`. Params (all optional, fail-closed on malformed):
/// `{ "intervalMs": 100..=600000 (default 1000), "maxSamples": 1..=32
/// (default 32), "afterSeq": <cursor> (default 0) }`. The declared cadence
/// is client-paced polling; the server enforces the 100 ms floor on the
/// declaration and bounds every drain (32 records or 8 KiB, sequence plus
/// drop-count headers). Reads never consume: producers never block and
/// consumers converge to latest state.
pub(super) fn handle_stream_process_stats(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    use bitty_ipc_api::scope::Scope::DebugTrace;
    require_profiling_scope(context, DebugTrace)?;
    let interval_ms = parse_interval_ms_param(request.params_raw.as_deref())?;
    let max_samples = parse_optional_uint_param(
        request.params_raw.as_deref(),
        "maxSamples",
        MAX_PROF_SAMPLES,
        MAX_PROF_SAMPLES,
    )?;
    let after_seq = parse_after_seq_param(request.params_raw.as_deref())?;
    let (body, truncated, head_seq, dropped) = drain_process_samples(after_seq, max_samples);
    let mut out = String::with_capacity(1024 + body.len().min(MAX_PROF_DRAIN_BYTES));
    out.push_str("{\"version\":\"");
    out.push_str(DEVTOOLS_PROTOCOL_VERSION);
    out.push_str("\",\"subscription\":{\"family\":\"process-stats\",\"intervalMs\":");
    out.push_str(&interval_ms.to_string());
    out.push_str("},\"samples\":[");
    out.push_str(&body);
    out.push_str("],\"seq\":");
    out.push_str(&head_seq.to_string());
    out.push_str(",\"dropped\":");
    out.push_str(&dropped.to_string());
    out.push_str(",\"truncated\":");
    out.push_str(if truncated { "true" } else { "false" });
    out.push('}');
    Ok(out)
}

/// `bitty.debug/streamFrameStats`: sampled frame-stats subscription.
///
/// Requires `debug.trace`. Same cursor discipline as
/// [`handle_stream_process_stats`]; every response carries
/// `"trust":"untrusted-observation"` and zero terminal bytes.
pub(super) fn handle_stream_frame_stats(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    use bitty_ipc_api::scope::Scope::DebugTrace;
    require_profiling_scope(context, DebugTrace)?;
    let interval_ms = parse_interval_ms_param(request.params_raw.as_deref())?;
    let max_samples = parse_optional_uint_param(
        request.params_raw.as_deref(),
        "maxSamples",
        MAX_PROF_SAMPLES,
        MAX_PROF_SAMPLES,
    )?;
    let after_seq = parse_after_seq_param(request.params_raw.as_deref())?;
    let (body, truncated, head_seq, dropped) = drain_frame_samples(after_seq, max_samples);
    let mut out = String::with_capacity(1024 + body.len().min(MAX_PROF_DRAIN_BYTES));
    out.push_str("{\"version\":\"");
    out.push_str(DEVTOOLS_PROTOCOL_VERSION);
    out.push_str("\",\"subscription\":{\"family\":\"frame-stats\",\"intervalMs\":");
    out.push_str(&interval_ms.to_string());
    out.push_str("},\"samples\":[");
    out.push_str(&body);
    out.push_str("],\"seq\":");
    out.push_str(&head_seq.to_string());
    out.push_str(",\"dropped\":");
    out.push_str(&dropped.to_string());
    out.push_str(",\"truncated\":");
    out.push_str(if truncated { "true" } else { "false" });
    out.push_str(",\"trust\":\"untrusted-observation\"}");
    Ok(out)
}
