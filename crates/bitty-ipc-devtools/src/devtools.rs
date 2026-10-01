//! DevTools-facing socket contract (CTX-0144, Issue #236).
//!
//! This module is the headless, bounded core of the `BITTY_SOCKET` server that
//! `bitty-terminal` exposes for `bitty-devtools`. It owns no socket, spawns no
//! thread, and performs no ambient I/O beyond caller-supplied streams and the
//! socket-directory it is explicitly handed: the listener lifecycle lives in
//! `bitty-terminal/src/ipc_serve.rs` (the servo), which calls into this module.
//!
//! # Reference-first (DEC-0017)
//!
//! Wire behavior mirrors the sibling `bitty-devtools` repository (read-only,
//! never modified here):
//!
//! - Framing: length-prefixed `u32` big-endian + payload `<= 256 KiB`, per
//!   `bitty-devtools/src/transport.ts` (`encodeFrame` / `decodeFrame`,
//!   `MAX_FRAME_BYTES = 256 KiB`, `Framer`). Reuse here is
//!   [`bitty_ipc_api::frame::encode_frame`] / [`bitty_ipc_api::frame::decode_frame`].
//! - Envelope: versioned JSON with `version: "1.0"`, numeric `id`, and
//!   `method` starting with `bitty.debug/`, per
//!   `bitty-devtools/src/protocol.ts` (`RequestFrame` / `ResponseFrame`,
//!   `encodeRequest` / `decodeResponse`, `negotiateVersion`,
//!   `isValidMethodForScope`). Both shapes the sibling repo emits are
//!   accepted: with `jsonrpc: "2.0"` (`protocol.ts`) and without it
//!   (`transport.ts` `IpcRequest`). Responses always carry `jsonrpc: "2.0"`
//!   so both sibling decoders accept them.
//! - Endpoint: `BITTY_SOCKET` advisory override, else
//!   `$XDG_RUNTIME_DIR/bitty/<instance>.sock` with instance scoping and
//!   `0700` directory / `0600` socket modes plus peer-UID equality, per
//!   `bitty-devtools/src/auth.ts` (`resolveSocketPath`,
//!   `verifyUnixEndpoint`, `DIR_MODE`, `SOCKET_MODE`). `BITTY_SOCKET` and
//!   `BITTY_INSTANCE_ID` are advisory identifiers, never credentials: every
//!   connection still requires peer-credential equality and every request is
//!   evaluated against the dispatch table.
//! - Bounds: `RC-9` (100 req/s, 2x burst, 16 concurrent connections) via
//!   [`bitty_ipc_core::limits::RateLimiter`], per-frame 256 KiB via
//!   [`bitty_ipc_api::frame::MAX_FRAME_BYTES`], JSON depth `<= 32` via
//!   [`bitty_ipc_api::wire::validate_json_depth`].
//!
//! # Scope of this slice (CTX-0144 plus CTX-0159)
//!
//! Handshake plus a read-only round-trip: `bitty.debug/ping`
//! (version/handshake probe) and `bitty.debug/getSnapshot` (runtime-stats
//! snapshot: instance, pid, versions, grid geometry at startup, uptime).
//! CTX-0159 adds live read-only introspection so input probes need no
//! screenshots: `bitty.debug/getGridText` (bounded grid text plus cursor),
//! `bitty.debug/getInputRing` (bounded ring of keys, modifiers, and mouse
//! buttons with coordinates), `bitty.debug/getModifiers` (modifier/latch
//! state), and `bitty.debug/getFocus` (focus/window state). The live store is
//! published by `bitty-runtime/src/inspect.rs` (`&self` only, never mutating
//! terminal truth); every query is read-only. Per P0-AC-025, connection alone
//! grants no debug scope: `getSnapshot` and the four introspection methods
//! require a granted debug scope (`debug.inspect`, or the wider `debug.trace`
//! / `debug.control`) and deny an ungranted peer with `scope`/`ScopeDenied`.
//! The [`Dispatcher`] remains an extensible method table: new `bitty.debug/*`
//! handlers register via [`Dispatcher::register`] without reworking framing,
//! parsing, or the connection loop. CTX-0188 adds test automation
//! (`synthesizeInput` + `captureFrame`, bearer-scoped per Amendment A1):
//! key/mouse/wheel/paste synthesis and redacted frame capture for the
//! headless verify harness; profiling stays owned by CTX-0189.
//!
//! # Trust posture
//!
//! Every byte is treated as originating from an **untrusted local client**:
//! peer UID is verified before the first byte is parsed, each frame is
//! length-bounded before allocation, JSON depth is capped, `auth`/`scope`/
//! `role` envelope fields are rejected outright (no ambient authority), and
//! oversize or malformed input fails closed (counted error response or
//! connection close, never a panic, never an unauthenticated fallback).

// ── protocol constants ──────────────────────────────────────────────────────

/// DevTools protocol version served by this slice (`protocol.ts`
/// `PROTOCOL_VERSION`).
pub const DEVTOOLS_PROTOCOL_VERSION: &str = "1.0";

/// Required method prefix (`protocol.ts` `encodeRequest` rule).
pub const DEVTOOLS_METHOD_PREFIX: &str = "bitty.debug/";

/// Portable `AF_UNIX` socket-path ceiling in payload bytes (excl. NUL).
///
/// `sockaddr_un.sun_path` is 108 bytes incl. NUL on Linux and 104 bytes incl.
/// NUL on macOS/BSD (`SUN_LEN`; macOS limit documented in `sys/un.h`, Linux
/// in `unix(7)`). A 100-byte payload (101 incl. NUL) fits every target with
/// margin, including smaller historical limits (92). This intentionally
/// diverges from `auth.ts`'s 512-byte advisory check: 512 is wrong for
/// `bind`/`connect`, which fail with `EINVAL`/`InvalidInput` ("path must be
/// shorter than SUN_LEN") past the kernel bound. All socket paths produced or
/// accepted here must fit this portable bound.
pub const MAX_SOCKET_PATH_BYTES: usize = 100;

/// `sun_path` size incl. NUL on Linux (108) per `unix(7)`.
pub const SUN_LEN_LINUX: usize = 108;

/// `sun_path` size incl. NUL on macOS/BSD (104) per `sys/un.h`.
pub const SUN_LEN_MACOS: usize = 104;

/// Maximum length of an instance id (`auth.ts`: 1..64).
pub const MAX_INSTANCE_ID_LEN: usize = 64;

/// Maximum bytes for a `bitty.debug/*` method name (parity with
/// [`bitty_ipc_api::channel::MAX_METHOD_BYTES`]).
pub const MAX_DEVTOOLS_METHOD_BYTES: usize = 128;

/// Maximum bytes for the raw numeric `id` token echoed verbatim.
pub const MAX_ID_TOKEN_BYTES: usize = 32;

/// Maximum method-suffix length after `bitty.debug/` (camelCase verbs such as
/// `getSnapshot` are far shorter; the cap keeps dispatch total).
pub const MAX_METHOD_SUFFIX_LEN: usize = 64;

/// Maximum error-message characters echoed to the peer (`protocol.ts`
/// `decodeResponse` truncates to 512; we truncate at construction).
pub const MAX_ERROR_MESSAGE_CHARS: usize = 512;

/// Maximum message characters for echoed request fields inside errors.
pub const MAX_ECHO_CHARS: usize = 64;

/// Leaf directory name under the runtime dir (`<base>/bitty/<instance>.sock`).
pub const SOCKET_LEAF_DIR: &str = "bitty";

/// Default instance id (`auth.ts` falls back to `"default"`).
pub const DEFAULT_INSTANCE_ID: &str = "default";

/// Windows named-pipe namespace hosting instance endpoints (CTX-0196).
pub const WINDOWS_PIPE_NAMESPACE: &str = r"\\.\pipe\";

/// Windows pipe-name prefix scoping bitty instances (`\\.\pipe\bitty-<id>`).
///
/// Mirrors [`SOCKET_LEAF_DIR`]: the kernel pipe namespace is the Windows
/// registry the way the socket directory is the Unix registry. Only pipes
/// carrying this prefix are enumerated by `bitty list instances`; foreign
/// pipes are never touched.
pub const WINDOWS_PIPE_PREFIX: &str = "bitty-";

/// Map an instance id to its Windows named-pipe path (CTX-0196).
///
/// Pure string logic (no I/O, no `unsafe`): `\\.\pipe\bitty-<instance>`.
/// The caller must have validated `instance` against the shared grammar
/// (1..=[`MAX_INSTANCE_ID_LEN`], `^[a-z0-9_-]+$` case-insensitive); this
/// function maps verbatim so probes fail fast on malformed input rather
/// than inventing a second grammar.
#[must_use]
pub fn windows_pipe_name(instance: &str) -> String {
    format!("{WINDOWS_PIPE_NAMESPACE}{WINDOWS_PIPE_PREFIX}{instance}")
}

/// Parse an instance id out of a Windows pipe file name (CTX-0196).
///
/// Accepts the bare pipe name as listed from the pipe namespace (e.g.
/// `bitty-default`); the `.sock` suffix is never part of a pipe name.
/// Returns `None` for foreign pipes (wrong prefix) or ids violating the
/// shared grammar, so enumeration skips entries another application owns.
#[must_use]
pub fn windows_instance_from_pipe_name(pipe_name: &str) -> Option<String> {
    let id = pipe_name.strip_prefix(WINDOWS_PIPE_PREFIX)?;
    if id.is_empty() || id.len() > MAX_INSTANCE_ID_LEN {
        return None;
    }
    let ok = id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !ok {
        return None;
    }
    Some(id.to_string())
}

/// Read-idle timeout applied by the servo to each connection (seconds).
/// Candidate value for this slice; CTX-0159 may tune it with RFC numbers.
pub const CONN_IDLE_TIMEOUT_SECS: u64 = 60;

/// Write timeout applied by the servo to each connection (seconds).
/// Candidate value; bounds how long a stuck peer can pin a handler thread.
pub const CONN_WRITE_TIMEOUT_SECS: u64 = 10;

/// Poll interval of the servo accept loop (milliseconds). Keeps shutdown
/// latency low without busy-spinning.
pub const ACCEPT_POLL_INTERVAL_MS: u64 = 20;

// ── introspection bounds (CTX-0159) ─────────────────────────────────────────

/// Maximum grid rows per `getGridText` snapshot (deterministic top-first
/// truncation; mirrors `bitty-devtools/src/bounds.ts` preview caps).
pub const MAX_INSPECT_ROWS: usize = 64;

/// Maximum grid columns per row (char-boundary truncation).
pub const MAX_INSPECT_COLS: usize = 256;

/// Maximum grid text bytes retained in the live store (fail-closed bound for
/// the published snapshot, well under [`MAX_FRAME_BYTES`]).
pub const MAX_INSPECT_TEXT_BYTES: usize = 16 * 1024;

/// Maximum input-ring events retained and served (drop-oldest).
pub const MAX_INPUT_RING: usize = 64;

/// Maximum characters per input-event label echoed to the peer.
pub const MAX_INPUT_LABEL_CHARS: usize = 64;

/// Maximum bytes for the raw `params` object in a request envelope.
/// Method params are tiny (`rows`/`cols`/`limit`); anything larger fails
/// closed before dispatch.
pub const MAX_PARAMS_BYTES: usize = 4096;

/// Maximum rendered introspection JSON bytes per response (fail-closed; grid
/// text dominates and is truncated row-first to fit).
pub const MAX_INSPECT_JSON_BYTES: usize = 32 * 1024;

// ── test-automation bounds (CTX-0188, Amendment A1 candidate) ────────────────
//
// `synthesizeInput` (`debug.control` + bearer) and `captureFrame`
// (`debug.trace` + bearer) are the only keystroke-injection / frame-capture
// surface. Both require the debug scope, the terminal capability, and a
// per-session single-terminal bearer; unscoped callers get `ScopeDenied`
// with zero partial state (fail closed everywhere).

/// Wire method for `synthesizeInput` (key/mouse/wheel/paste synthesis).
pub const METHOD_SYNTHESIZE_INPUT: &str = "bitty.debug/synthesizeInput";

/// Wire method for `captureFrame` (bounded redacted frame capture).
pub const METHOD_CAPTURE_FRAME: &str = "bitty.debug/captureFrame";

/// Wire method for `frameHash` (CTX-0244: SHA-256 digest over canonical
/// `headless_rgba` + geometry header; 32-byte digest, zero pixel bytes).
pub const METHOD_FRAME_HASH: &str = "bitty.debug/frameHash";

/// Wire method for `startTrace` (DT-03, #1099: opt-in bounded trace).
pub const METHOD_START_TRACE: &str = "bitty.debug/startTrace";

/// Wire method for `stopTrace` (DT-03, #1099: export + delete).
pub const METHOD_STOP_TRACE: &str = "bitty.debug/stopTrace";

/// Wire method for `fetchTraceChunk` (DT-03, #1099: 256 KiB pages).
pub const METHOD_FETCH_TRACE_CHUNK: &str = "bitty.debug/fetchTraceChunk";

// ── plugin-runtime methods (devtools-rfc accepted v1, issue #1377) ──────────
//
// The six `inspect` readers, the `trace` event stream, and the three
// `control` lifecycle verbs. `bitty-ipc` owns no plugin host: no registry,
// VM, queue, or handle table lives in this crate (those live in
// `bitty-plugin-host` / `bitty-lua`, owned upstream by `bitty-runtime`),
// so every handler below enforces the RFC scope plus the RFC param grammar
// (generation ownership included) and then fails closed with a typed
// `capability` error naming the missing backend. Registration itself is the
// fix: callers get scope/param validation and an on-taxonomy verdict
// instead of `usage`/`UnknownMethod`.

/// Wire method for `listPlugins` (inspect: optional `generation` filter).
pub const METHOD_LIST_PLUGINS: &str = "bitty.debug/listPlugins";

/// Wire method for `getPlugin` (inspect: required `pluginId`).
pub const METHOD_GET_PLUGIN: &str = "bitty.debug/getPlugin";

/// Wire method for `listSubscriptions` (inspect: required `pluginId`).
pub const METHOD_LIST_SUBSCRIPTIONS: &str = "bitty.debug/listSubscriptions";

/// Wire method for `getBudgets` (inspect: required `pluginId` + `generation`).
pub const METHOD_GET_BUDGETS: &str = "bitty.debug/getBudgets";

/// Wire method for `getQueueSnapshot` (inspect: required `pluginId`).
pub const METHOD_GET_QUEUE_SNAPSHOT: &str = "bitty.debug/getQueueSnapshot";

/// Wire method for `listHandles` (inspect: required `pluginId`).
pub const METHOD_LIST_HANDLES: &str = "bitty.debug/listHandles";

/// Wire method for `streamEvents` (trace: `types[]` + `batch`).
pub const METHOD_STREAM_EVENTS: &str = "bitty.debug/streamEvents";

/// Wire method for `suspendHandler` (control: `pluginId` + `handlerId` + `cause`).
pub const METHOD_SUSPEND_HANDLER: &str = "bitty.debug/suspendHandler";

/// Wire method for `resumePlugin` (control: `pluginId` + `generation`).
pub const METHOD_RESUME_PLUGIN: &str = "bitty.debug/resumePlugin";

/// Wire method for `disposeGeneration` (control: `pluginId` + `generation`).
pub const METHOD_DISPOSE_GENERATION: &str = "bitty.debug/disposeGeneration";

/// Maximum synthetic events per `synthesizeInput` call (Amendment A1).
pub const MAX_SYNTH_EVENTS_PER_CALL: usize = 64;

/// Sustained `synthesizeInput` calls per second per bearer (Amendment A1).
pub const MAX_SYNTH_CALLS_PER_SEC: usize = 10;

/// Sustained `captureFrame` frames per second per bearer (Amendment A1).
pub const MAX_CAPTURE_FPS: usize = 10;

/// Wire method for `getProcessStats` (read-only process health snapshot).
pub const METHOD_GET_PROCESS_STATS: &str = "bitty.debug/getProcessStats";

/// Wire method for `getFrameStats` (read-only rendering health snapshot).
pub const METHOD_GET_FRAME_STATS: &str = "bitty.debug/getFrameStats";

/// Wire method for `streamProcessStats` (sampled process-stats drain).
pub const METHOD_STREAM_PROCESS_STATS: &str = "bitty.debug/streamProcessStats";

/// Wire method for `streamFrameStats` (sampled frame-stats drain).
pub const METHOD_STREAM_FRAME_STATS: &str = "bitty.debug/streamFrameStats";

/// Maximum retained samples per profiling family (CTX-0189; accepted
/// batching bound reused: at most 32 records per wakeup, drop-oldest with
/// counted drops so consumers converge to latest state).
pub const MAX_PROF_SAMPLES: usize = 32;

/// Maximum encoded sample bytes per stream drain (CTX-0189; accepted 8 KiB
/// aggregate reused: the drain stops before the next sample would exceed
/// this budget and reports `truncated: true`).
pub const MAX_PROF_DRAIN_BYTES: usize = 8 * 1024;

/// Sampling interval floor in ms (CTX-0189; Amendment A1 candidate: sampling
/// is the only profiling posture, cold-path counter snapshots, 100 ms
/// floor; per-frame tracing and sub-100 ms cadences are deferred).
pub const MIN_PROF_INTERVAL_MS: u64 = 100;

/// Default stream cadence in ms when `intervalMs` is absent.
pub const DEFAULT_PROF_INTERVAL_MS: u64 = 1_000;

/// Maximum declared stream cadence in ms (PB-7 ten-minute window parity).
pub const MAX_PROF_INTERVAL_MS: u64 = 600_000;

/// Maximum renderer-supplied label characters per frame sample (CTX-0189;
/// Amendment A1 candidate bound: at most 256 characters, never terminal
/// content, labeled untrusted observation data).
pub const MAX_PROF_LABEL_CHARS: usize = 256;

/// Maximum CPU-average window in ms (CTX-0189; PB-7 ten-minute window
/// parity: the average covers a bounded window, never an open-ended one).
pub const MAX_PROF_WINDOW_MS: u64 = 600_000;

/// Automation bearer TTL in ms (candidate default 10 minutes, never exceeds
/// the owning session lifetime; expiry revokes immediately).
pub const AUTOMATION_BEARER_TTL_MS: u64 = 600_000;

/// Maximum automation bearers tracked (parity with consent-ledger scale;
/// fail-closed at capacity, never evicted silently).
pub const MAX_AUTOMATION_BEARERS: usize = 64;

/// Maximum bytes for the raw automation `params` object (`synthesizeInput`
/// with 64 events needs more than the 4 KiB introspection bound; still well
/// under the 256 KiB frame bound).
pub const MAX_AUTOMATION_PARAMS_BYTES: usize = 32 * 1024;

/// Maximum characters for `originLabel` (audit attribution, required).
pub const MAX_ORIGIN_LABEL_CHARS: usize = 64;

/// Maximum bytes for one synthetic paste-text event (text-only, T-04 parity;
/// well under the frame bound).
pub const MAX_SYNTH_PASTE_BYTES: usize = 16 * 1024;

/// Maximum characters for a synthetic key name.
pub const MAX_SYNTH_KEY_CHARS: usize = 64;

/// Maximum characters for an automation bearer token (opaque, unguessable,
/// never persisted).
pub const MAX_BEARER_TOKEN_CHARS: usize = 128;

/// Maximum grid cells per axis for synthetic mouse coordinates (fail-closed).
pub const MAX_SYNTH_CELL: u16 = 1024;

/// Maximum absolute wheel delta rows/cols per event (fail-closed).
pub const MAX_SYNTH_WHEEL_DELTA: i32 = 64;

/// Redaction marker replacing sensitive frame lines (P0-AC-026 parity).
pub const REDACTED_MARKER: &str = "[redacted]";

// ── test-mode E2E surface (CTX-0506, research 043) ──────────────────────────
//
// `bitty --test-mode` runs the real Runtime without a display and serves a
// flag-gated E2E protocol surface for native tests (no VM). The surface
// reuses the existing `bitty.debug/*` framing, dispatcher, scope, and
// control-queue architecture; these two methods exist only while test mode
// is active, so a normal instance answers `NotFound` (default-deny).
//
// No new authority:
// - `testInfo` is read-only surface identity (no terminal content).
// - `testExit` routes through the existing control queue and requires the
//   accepted `debug.control` debug scope (elevation via the explicit
//   `BITTY_CTL_ELEVATE` allowlist, exactly like every other elevated verb).
//   It does not bypass any scope, bearer, rate, or redaction rule.

/// Wire method for the `--test-mode` E2E handshake (registered only while
/// test mode is active).
pub const METHOD_TEST_INFO: &str = "bitty.debug/testInfo";

/// Wire method for deterministic test-mode shutdown (registered only while
/// test mode is active; requires `debug.control`).
pub const METHOD_TEST_EXIT: &str = "bitty.debug/testExit";

/// E2E surface name advertised by `testInfo`.
pub const TEST_SURFACE_NAME: &str = "e2e";

/// E2E surface protocol version advertised by `testInfo`.
pub const TEST_SURFACE_PROTOCOL: &str = "1.0";

// ── submodules ──────────────────────────────────────────────────────────────

mod automation;
mod automation_ops;
mod continuation;
mod handlers;
mod json;
mod mcp_adapter;
mod plugin_runtime;
mod profiling;
mod record;
mod serve;
mod trace;

#[cfg(test)]
mod tests;

pub use automation::{
    AutomationFamily, FrameAuditEntry, automation_bearer_count_for_tests,
    clear_automation_for_tests, frame_audit_len_for_tests, frame_audit_snapshot_for_tests,
    frame_digest_publish_wanted, revoke_automation_bearer, synthetic_seq_for_tests,
};
#[cfg(any(test, feature = "test-support"))]
pub use automation::{issue_automation_bearer, issue_automation_bearer_with_ttl};
pub use continuation::{
    Accepted, CONTINUATION_CHUNK_BYTES, CONTINUATION_DEADLINE_MS, CONTINUATION_FLAG_FINAL,
    CONTINUATION_HEADER_BYTES, CONTINUATION_MAGIC, ContinuationError, MAX_LOGICAL_REQUEST_BYTES,
    Reassembler, encode_request_frames, is_fragment,
};
pub use handlers::{
    DevtoolsHandler, Dispatcher, FocusPublish, GridPublish, HandlerError, InputEventPublish,
    MAX_DIGEST_RGBA_BYTES, ModifiersPublish, clear_introspection_for_tests, publish_focus,
    publish_frame_rgba, publish_grid_text, publish_input_ring, publish_modifiers,
};
pub use json::{DevtoolsRequest, RequestFault, parse_request};
pub use mcp_adapter::{
    MCP_ADAPTER_VERSION, MCP_TOOL_PREFIX, debug_method_for_mcp_tool, is_mcp_exposed_debug_method,
    mcp_denied_debug_methods, mcp_list_tools_json, mcp_tool_for_debug_method, mcp_tool_names,
};
pub use profiling::{
    FrameStatsPublish, ProcessStatsPublish, clear_profiling_for_tests, publish_frame_stats,
    publish_process_stats,
};
pub use record::{
    MAX_ACTIVE_RECORDINGS, MAX_RECORD_BYTES, MAX_RECORD_DETAIL_BYTES, MAX_RECORD_ENTRIES,
    RECORD_REDACTED_MARKER, RecordEntry, RecordError, RecordKind, Recording, ReplayReport,
    ReplayVerdict, clear_recordings_for_tests, is_recording_opt_in, record_action,
    record_config_diagnostic, record_input_marker, record_lifecycle, record_parser_input,
    recording_count_for_tests, replay_recording, set_recording_opt_in, start_recording,
    stop_recording,
};
#[cfg(unix)]
pub use serve::serve_bound_connection;
#[cfg(unix)]
pub use serve::serve_bound_connection_with_endpoint_budget;
pub use serve::{
    ConnectedPeerProof, ConnectionStats, DirAttestation, HandleOutcome, ServeContext, ServerInfo,
    SocketEndpointIdentity, SocketEnv, attest_bound_socket, encode_error, encode_success,
    handle_envelope, id_zero_error, max_connections, prepare_socket_dir, resolve_socket_path,
    resolve_socket_path_from_env, verify_connected_endpoint, verify_socket_endpoint_for_connect,
};
pub use trace::{
    MAX_ACTIVE_TRACES, MAX_TRACE_BYTES, MAX_TRACE_DURATION_MS, TRACE_CHUNK_BYTES,
    TRACE_PREVIEW_BYTES, TraceAppendError, append_trace_event, clear_traces_for_tests,
    redact_trace_preview, set_trace_spool_dir_for_tests, trace_count_for_tests,
};
