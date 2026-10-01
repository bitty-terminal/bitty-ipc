use super::*;

use super::automation_ops::{handle_capture_frame, handle_frame_hash, handle_synthesize_input};
use super::json::{echo_snippet, truncate_chars, validate_method};
use super::plugin_runtime::{
    handle_dispose_generation, handle_get_budgets, handle_get_plugin, handle_get_queue_snapshot,
    handle_list_handles, handle_list_plugins, handle_list_subscriptions, handle_resume_plugin,
    handle_stream_events, handle_suspend_handler,
};
use super::profiling::{
    handle_get_frame_stats, handle_get_process_stats, handle_stream_frame_stats,
    handle_stream_process_stats,
};
use super::trace::{handle_fetch_trace_chunk, handle_start_trace, handle_stop_trace};

use bitty_ipc_api::error::IpcError;
use std::collections::BTreeMap;

// ── dispatch ────────────────────────────────────────────────────────────────

/// A handler failure rendered as a DevTools error object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerError {
    /// DevTools error category.
    pub category: &'static str,
    /// Stable error code.
    pub code: &'static str,
    /// Bounded human-readable reason.
    pub message: String,
}

impl HandlerError {
    /// Build a handler failure.
    #[must_use]
    pub fn new(category: &'static str, code: &'static str, message: String) -> Self {
        Self {
            category,
            code,
            message: truncate_chars(&message, MAX_ERROR_MESSAGE_CHARS),
        }
    }
}

/// Handler for one `bitty.debug/*` method.
///
/// Receives the per-request context and the parsed request, and returns the
/// `result` JSON value (already a bounded JSON document) or a
/// [`HandlerError`]. Handlers are pure `fn` pointers so the table stays
/// dependency-free and CTX-0159 can register new methods with one call.
pub type DevtoolsHandler = fn(&ServeContext, &DevtoolsRequest) -> Result<String, HandlerError>;

/// Extensible `bitty.debug/*` dispatch table.
///
/// CTX-0159 adds introspection methods via [`Dispatcher::register`] without
/// touching framing, parsing, or the connection loop.
#[derive(Debug, Default)]
pub struct Dispatcher {
    /// Method name to handler, keyed by full `bitty.debug/*` name.
    handlers: BTreeMap<&'static str, DevtoolsHandler>,
}

impl Dispatcher {
    /// Table with the round-trip surface plus CTX-0159 read-only
    /// introspection (`getGridText`, `getInputRing`, `getModifiers`,
    /// `getFocus`) plus CTX-0171 runtime control (`listWindows`,
    /// `listViews`, `listTerminals`, `spawnTerminal`, `closeTerminal`,
    /// `sendInput`, `getTerminalText`, `splitView`, `focusView`,
    /// `reloadConfig`) plus CTX-0257 workspace entry (`listWorkspaces`,
    /// `createWorkspace`, `closeWorkspace`, `focusWorkspace`) plus CTX-0259
    /// workspace move (`moveWorkspace`) plus issue #1333 switcher ops
    /// (`renameWorkspace`, `movePanel`) plus CTX-0188
    /// test automation (`synthesizeInput`,
    /// `captureFrame`, bearer-scoped per Amendment A1) plus DT-03 trace
    /// lifecycle (`startTrace`, `stopTrace`, `fetchTraceChunk`, requiring
    /// `debug.trace`) plus CTX-0189 live
    /// profiling (`getProcessStats`, `getFrameStats`, `streamProcessStats`,
    /// `streamFrameStats`; sampling-only, scope-gated per Amendment A1)
    /// plus issue #1377 plugin-runtime v1 (`listPlugins`, `getPlugin`,
    /// `listSubscriptions`, `getBudgets`, `getQueueSnapshot`, `listHandles`
    /// requiring `debug.inspect`; `streamEvents` requiring `debug.trace`;
    /// `suspendHandler`, `resumePlugin`, `disposeGeneration` requiring
    /// `debug.control`; scope- and param-gated fail-closed stubs until a
    /// plugin host publishes live data).
    ///
    /// Introspection handlers register via [`Dispatcher::register`] (the
    /// CTX-0159 hook) so the registration path itself is exercised here, not
    /// just in tests. Method names are statically valid, so a registration
    /// failure here is a programming error surfaced loudly rather than a
    /// silent partial table. Control handlers authorize against the
    /// connection's live authority on every request (and again at drain) and
    /// enqueue to the cross-thread queue for the main thread to apply (the
    /// connection thread never touches `Runtime`).
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut table = Self {
            handlers: BTreeMap::new(),
        };
        table.handlers.insert("bitty.debug/ping", handle_ping);
        table
            .handlers
            .insert("bitty.debug/getSnapshot", handle_get_snapshot);
        // CTX-0159 read-only introspection (fail-closed, bounded, no
        // injection). Names are statically valid per `validate_method`.
        let introspection: &[(&'static str, DevtoolsHandler)] = &[
            ("bitty.debug/getGridText", handle_get_grid_text),
            ("bitty.debug/getInputRing", handle_get_input_ring),
            ("bitty.debug/getModifiers", handle_get_modifiers),
            ("bitty.debug/getFocus", handle_get_focus),
        ];
        for (method, handler) in introspection {
            if table.register(method, *handler).is_err() {
                debug_assert!(false, "statically valid introspection method rejected");
            }
        }
        // CTX-0171 runtime control (scope-gated, main-thread applied).
        let control: &[(&'static str, DevtoolsHandler)] = &[
            (crate::ctl::METHOD_LIST_WINDOWS, handle_control),
            (crate::ctl::METHOD_LIST_VIEWS, handle_control),
            (crate::ctl::METHOD_LIST_TERMINALS, handle_control),
            (crate::ctl::METHOD_SPAWN_TERMINAL, handle_control),
            (crate::ctl::METHOD_CLOSE_TERMINAL, handle_control),
            (crate::ctl::METHOD_SEND_INPUT, handle_control),
            (crate::ctl::METHOD_GET_TERMINAL_TEXT, handle_control),
            (crate::ctl::METHOD_SPLIT_VIEW, handle_control),
            (crate::ctl::METHOD_FOCUS_VIEW, handle_control),
            (crate::ctl::METHOD_LIST_WORKSPACES, handle_control),
            (crate::ctl::METHOD_NEW_WORKSPACE, handle_control),
            (crate::ctl::METHOD_CLOSE_WORKSPACE, handle_control),
            (crate::ctl::METHOD_FOCUS_WORKSPACE, handle_control),
            (crate::ctl::METHOD_MOVE_WORKSPACE, handle_control),
            (crate::ctl::METHOD_RENAME_WORKSPACE, handle_control),
            (crate::ctl::METHOD_MOVE_PANEL, handle_control),
            (crate::ctl::METHOD_RELOAD_CONFIG, handle_control),
        ];
        for (method, handler) in control {
            if table.register(method, *handler).is_err() {
                debug_assert!(false, "statically valid control method rejected");
            }
        }
        // CTX-0188 test automation (bearer-scoped, rate-capped, redacted).
        // CTX-0244 adds `frameHash` (digest-only, new `FrameDigest` family;
        // the `Capture` family is never widened).
        let automation: &[(&'static str, DevtoolsHandler)] = &[
            (METHOD_SYNTHESIZE_INPUT, handle_synthesize_input),
            (METHOD_CAPTURE_FRAME, handle_capture_frame),
            (METHOD_FRAME_HASH, handle_frame_hash),
        ];
        for (method, handler) in automation {
            if table.register(method, *handler).is_err() {
                debug_assert!(false, "statically valid automation method rejected");
            }
        }
        // DT-03 trace lifecycle (opt-in, bounded, 256 KiB pages, 0600
        // spool; requires `debug.trace`, never `debug.inspect` alone).
        let traces: &[(&'static str, DevtoolsHandler)] = &[
            (METHOD_START_TRACE, handle_start_trace),
            (METHOD_STOP_TRACE, handle_stop_trace),
            (METHOD_FETCH_TRACE_CHUNK, handle_fetch_trace_chunk),
        ];
        for (method, handler) in traces {
            if table.register(method, *handler).is_err() {
                debug_assert!(false, "statically valid trace method rejected");
            }
        }
        // CTX-0189 live profiling (sampling-only, bounded, redacted;
        // getters need `debug.inspect`, streams need `debug.trace`).
        let profiling: &[(&'static str, DevtoolsHandler)] = &[
            (METHOD_GET_PROCESS_STATS, handle_get_process_stats),
            (METHOD_GET_FRAME_STATS, handle_get_frame_stats),
            (METHOD_STREAM_PROCESS_STATS, handle_stream_process_stats),
            (METHOD_STREAM_FRAME_STATS, handle_stream_frame_stats),
        ];
        for (method, handler) in profiling {
            if table.register(method, *handler).is_err() {
                debug_assert!(false, "statically valid profiling method rejected");
            }
        }
        // Issue #1377 plugin-runtime v1 (accepted devtools-rfc table):
        // inspect readers, the trace event stream, and the control
        // lifecycle verbs. Scope- and param-gated fail-closed stubs (no
        // plugin host lives in this crate); see `plugin_runtime`.
        let plugin_runtime: &[(&'static str, DevtoolsHandler)] = &[
            (METHOD_LIST_PLUGINS, handle_list_plugins),
            (METHOD_GET_PLUGIN, handle_get_plugin),
            (METHOD_LIST_SUBSCRIPTIONS, handle_list_subscriptions),
            (METHOD_GET_BUDGETS, handle_get_budgets),
            (METHOD_GET_QUEUE_SNAPSHOT, handle_get_queue_snapshot),
            (METHOD_LIST_HANDLES, handle_list_handles),
            (METHOD_STREAM_EVENTS, handle_stream_events),
            (METHOD_SUSPEND_HANDLER, handle_suspend_handler),
            (METHOD_RESUME_PLUGIN, handle_resume_plugin),
            (METHOD_DISPOSE_GENERATION, handle_dispose_generation),
        ];
        for (method, handler) in plugin_runtime {
            if table.register(method, *handler).is_err() {
                debug_assert!(false, "statically valid plugin-runtime method rejected");
            }
        }
        table
    }

    /// Dispatcher with the default table plus the `--test-mode` E2E surface
    /// (CTX-0506, research 043).
    ///
    /// The test surface is registered only by this constructor: a normal
    /// instance uses [`Dispatcher::with_defaults`] and answers
    /// `bitty.debug/testInfo` / `bitty.debug/testExit` with `NotFound`
    /// (fail-closed default-deny). Registration grants no authority —
    /// `testInfo` is read-only surface identity and `testExit` authorizes the
    /// accepted `debug.control` scope like every other elevated control verb.
    #[must_use]
    pub fn with_test_mode() -> Self {
        let mut table = Self::with_defaults();
        let test_surface: &[(&'static str, DevtoolsHandler)] = &[
            (super::METHOD_TEST_INFO, handle_test_info),
            (super::METHOD_TEST_EXIT, handle_control),
        ];
        for (method, handler) in test_surface {
            if table.register(method, *handler).is_err() {
                debug_assert!(false, "statically valid test-mode method rejected");
            }
        }
        table
    }

    /// Register a handler for a `bitty.debug/*` method (CTX-0159 hook).
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::InvalidMethod`] when `method` violates the
    /// `bitty.debug/*` grammar enforced by [`validate_method`].
    pub fn register(
        &mut self,
        method: &'static str,
        handler: DevtoolsHandler,
    ) -> Result<(), IpcError> {
        validate_method(method).map_err(|reason| IpcError::InvalidMethod {
            method: method.to_string(),
            reason,
        })?;
        self.handlers.insert(method, handler);
        Ok(())
    }

    /// Whether `method` has a handler.
    #[must_use]
    pub fn contains(&self, method: &str) -> bool {
        self.handlers.contains_key(method)
    }

    /// Number of registered methods.
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.handlers.len()
    }

    /// Dispatch a parsed request to its handler.
    ///
    /// # Errors
    ///
    /// Returns `UnknownMethod` (category `usage`) for well-formed but
    /// unregistered `bitty.debug/*` methods; no partial state is created.
    pub fn dispatch(
        &self,
        context: &ServeContext,
        request: &DevtoolsRequest,
    ) -> Result<String, HandlerError> {
        if context.recheck_before_dispatch().is_err() {
            return Err(HandlerError::new(
                "scope",
                "Unauthenticated",
                "connected peer recheck failed".into(),
            ));
        }
        match self.handlers.get(request.method.as_str()) {
            Some(handler) => handler(context, request),
            None => Err(HandlerError::new(
                "usage",
                "UnknownMethod",
                format!("unknown method {}", echo_snippet(&request.method)),
            )),
        }
    }
}

/// `bitty.debug/ping`: handshake probe echoing the protocol version.
fn handle_ping(
    _context: &ServeContext,
    _request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    Ok(format!(
        "{{\"version\":\"{DEVTOOLS_PROTOCOL_VERSION}\",\"ok\":true}}"
    ))
}

/// `bitty.debug/testInfo`: E2E surface handshake (CTX-0506, test-mode only).
///
/// Read-only surface identity for an automated harness: it lets a test assert
/// it is talking to a `--test-mode` instance before driving panel state. The
/// `instance` field is the validated discovery id (advisory identifier, never
/// a credential). No terminal content, no authority, no new scope: the only
/// gate is registration, so a normal instance answers `NotFound`.
fn handle_test_info(
    context: &ServeContext,
    _request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    let mut out = String::with_capacity(160);
    out.push_str("{\"test_mode\":true,\"surface\":\"");
    out.push_str(super::TEST_SURFACE_NAME);
    out.push_str("\",\"protocol\":\"");
    out.push_str(super::TEST_SURFACE_PROTOCOL);
    out.push_str("\",\"instance\":\"");
    json_escape_into(&mut out, &context.server.instance);
    out.push_str("\"}");
    Ok(out)
}

/// Gate for the terminal-reading debug surfaces (CTX-0792, #1404).
///
/// The accepted scope hierarchy is `debug.control ⊃ debug.trace ⊃
/// debug.inspect`, so any one debug scope may read. On top of that coarse
/// scope the read is intersected with the terminal capability
/// `terminal.inspect`. The published grid, input, focus, and modifier stores
/// are not attributed to one terminal, so the capability must hold for every
/// terminal ([`crate::ctl::AuthorizationSnapshot::allows_every_terminal`]): a
/// narrowed terminal entry denies the read, and a client-named terminal can
/// never select a looser entry. Every half fails closed — no authority, no
/// debug scope, or no terminal capability each deny with `ScopeDenied`.
fn require_debug_terminal_read(context: &ServeContext, method: &str) -> Result<(), HandlerError> {
    use bitty_ipc_api::scope::Scope;
    let authorization = context.current_authorization().map_err(|_| {
        HandlerError::new(
            "scope",
            "Unauthenticated",
            "connection authority is unavailable".into(),
        )
    })?;
    if !authorization.scopes.contains(Scope::DebugInspect)
        && !authorization.scopes.contains(Scope::DebugTrace)
        && !authorization.scopes.contains(Scope::DebugControl)
    {
        return Err(HandlerError::new(
            "scope",
            "ScopeDenied",
            format!(
                "permission denied: scope 'debug.inspect' denied for {method} (needs elevation)"
            ),
        ));
    }
    if !authorization.allows_every_terminal(Scope::TerminalInspect) {
        return Err(HandlerError::new(
            "scope",
            "ScopeDenied",
            format!("permission denied: terminal.inspect denied for {method}"),
        ));
    }
    Ok(())
}

/// Validate an optional `terminal_id`/`terminalId` on a read surface.
///
/// Delegates to the ctl params parser — the same one the control verbs use —
/// so a malformed or oversized id fails closed with `InvalidParams` instead of
/// being ignored.
fn request_terminal_id(params: Option<&str>) -> Result<Option<String>, HandlerError> {
    crate::ctl::parse_optional_terminal_id_params(params).map_err(|err| match err {
        bitty_ipc_api::error::IpcError::LimitExceeded { field, limit, .. } => HandlerError::new(
            "usage",
            "InvalidParams",
            format!("params {field} exceeds limit {limit}"),
        ),
        _ => HandlerError::new(
            "usage",
            "InvalidParams",
            "params terminal_id must match ^t:[0-9]+$".to_string(),
        ),
    })
}

/// Escape a string as a JSON string body (without surrounding quotes).
pub(super) fn json_escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7F => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

/// `bitty.debug/getSnapshot`: read-only runtime-stats snapshot.
///
/// Returns startup facts (instance, pid, versions, grid geometry, uptime).
/// Live terminal content is served by `bitty.debug/getGridText` (CTX-0159);
/// the `"snapshot":"runtime-stats"` marker keeps this response honest about
/// what it carries.
fn handle_get_snapshot(
    context: &ServeContext,
    _request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    require_debug_terminal_read(context, "bitty.debug/getSnapshot")?;
    let server = &context.server;
    let mut out = String::with_capacity(256);
    out.push_str("{\"version\":\"");
    out.push_str(DEVTOOLS_PROTOCOL_VERSION);
    out.push_str("\",\"snapshot\":\"runtime-stats\",\"instance\":\"");
    json_escape_into(&mut out, &server.instance);
    out.push_str("\",\"pid\":");
    out.push_str(&server.pid.to_string());
    out.push_str(",\"app\":\"bitty-terminal\",\"app_version\":\"");
    json_escape_into(&mut out, &server.app_version);
    out.push_str("\",\"cols\":");
    out.push_str(&server.cols.to_string());
    out.push_str(",\"rows\":");
    out.push_str(&server.rows.to_string());
    out.push_str(",\"uptime_ms\":");
    out.push_str(&context.uptime_ms.to_string());
    out.push_str(",\"started_unix_ms\":");
    out.push_str(&server.started_unix_ms.to_string());
    out.push_str(",\"socket\":\"");
    json_escape_into(&mut out, &server.socket_path);
    out.push_str("\"}");
    Ok(out)
}

// ── introspection live store (CTX-0159) ─────────────────────────────────────
//
// The live store is published by `bitty-runtime/src/inspect.rs` (`&self`
// only) and served read-only here. All stored values are bounded at publish
// time; all served slices are bounded per-request params. No socket query
// mutates the store, the runtime, or terminal truth. Scope: every method in
// this section requires only `debug.inspect` (read-only default per
// `bitty-devtools/src/inspection.ts`); no `debug.control` surface is exposed.

/// Grid text published by the runtime (bounded at publish time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GridPublish {
    /// Grid text rows (each already char-bounded and trailing-trimmed).
    pub lines: Vec<String>,
    /// Live cursor row (`0`-based).
    pub cursor_row: u16,
    /// Live cursor column (`0`-based).
    pub cursor_col: u16,
    /// Whether the cursor is visible.
    pub cursor_visible: bool,
    /// Damage generation at capture time.
    pub generation: u64,
    /// Grid width in columns at capture time.
    pub cols: usize,
    /// Grid height in rows at capture time.
    pub rows: usize,
}

/// One input event published by the runtime (bounded at publish time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputEventPublish {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Kind label (`"key"`, `"modifiers"`, `"mouse"`, `"wheel"`, `"focus"`).
    pub kind: String,
    /// Bounded human-readable summary.
    pub label: String,
    /// Whether Shift was held.
    pub shift: bool,
    /// Whether Control was held.
    pub control: bool,
    /// Whether Alt was held.
    pub alt: bool,
    /// Mouse button name when applicable.
    pub button: Option<String>,
    /// Cell column (`0`-based) when applicable.
    pub col: Option<u16>,
    /// Cell row (`0`-based) when applicable.
    pub row: Option<u16>,
    /// Pressed (`true`) or released (`false`) when applicable.
    pub pressed: Option<bool>,
}

/// Modifier/latch state published by the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModifiersPublish {
    /// Whether Shift is latched.
    pub shift: bool,
    /// Whether Control is latched.
    pub control: bool,
    /// Whether Alt is latched.
    pub alt: bool,
    /// Live Kitty keyboard flags (`0` means legacy).
    pub enhanced_keyboard_flags: u32,
}

/// Focus/window state published by the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FocusPublish {
    /// Whether the window holds keyboard focus.
    pub focused: bool,
    /// Focused view id when the layout has one.
    pub focused_view: Option<u64>,
    /// Whether mouse-event capture is active.
    pub mouse_capture: bool,
    /// Whether the alternate screen is active.
    pub alt_screen: bool,
    /// Whether bracketed paste (`2004`) is active.
    pub bracketed_paste: bool,
    /// Whether focus-event reporting (`1004`) is active.
    pub focus_events: bool,
}

/// Stored grid snapshot (private; published values are validated on entry).
#[derive(Debug, Clone, Default)]
pub(super) struct StoredGrid {
    /// Bounded grid lines.
    pub(super) lines: Vec<String>,
    /// Cursor row.
    pub(super) cursor_row: u16,
    /// Cursor column.
    pub(super) cursor_col: u16,
    /// Cursor visibility.
    pub(super) cursor_visible: bool,
    /// Generation.
    pub(super) generation: u64,
    /// Grid width.
    pub(super) cols: usize,
    /// Grid height.
    pub(super) rows: usize,
}

/// Stored modifier snapshot.
#[derive(Debug, Clone, Copy, Default)]
struct StoredModifiers {
    /// Shift latch.
    shift: bool,
    /// Control latch.
    control: bool,
    /// Alt latch.
    alt: bool,
    /// Kitty flags.
    enhanced_keyboard_flags: u32,
}

/// Stored focus snapshot.
#[derive(Debug, Clone, Copy, Default)]
struct StoredFocus {
    /// Window focus.
    focused: bool,
    /// Focused view.
    focused_view: Option<u64>,
    /// Mouse capture.
    mouse_capture: bool,
    /// Alt screen.
    alt_screen: bool,
    /// Bracketed paste.
    bracketed_paste: bool,
    /// Focus events.
    focus_events: bool,
}

use std::sync::{Mutex, OnceLock};

/// Live grid store (empty until the runtime publishes).
pub(super) fn live_grid_store() -> &'static Mutex<StoredGrid> {
    static STORE: OnceLock<Mutex<StoredGrid>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(StoredGrid::default()))
}

/// Live input-ring store (empty until the runtime publishes).
pub(super) fn live_input_store() -> &'static Mutex<Vec<InputEventPublish>> {
    static STORE: OnceLock<Mutex<Vec<InputEventPublish>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(Vec::new()))
}

/// Live modifier store (defaults to all-released).
fn live_modifiers_store() -> &'static Mutex<StoredModifiers> {
    static STORE: OnceLock<Mutex<StoredModifiers>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(StoredModifiers::default()))
}

/// Live focus store (defaults to unfocused; the runtime publishes `true` on
/// startup via its `focused: true` initial state on the next tick).
fn live_focus_store() -> &'static Mutex<StoredFocus> {
    static STORE: OnceLock<Mutex<StoredFocus>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(StoredFocus::default()))
}

/// Truncate a line to at most `max` characters (char-boundary safe).
pub(super) fn truncate_line(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect()
}

/// Publish grid text to the live store (called by `bitty-runtime`, `&self`
/// only).
///
/// Bounds are enforced deterministically: at most [`MAX_INSPECT_ROWS`] rows,
/// each at most [`MAX_INSPECT_COLS`] characters, total at most
/// [`MAX_INSPECT_TEXT_BYTES`] bytes (row-first truncation). A poisoned mutex
/// fails closed by dropping the publish (the next tick republishes).
pub fn publish_grid_text(
    lines: Vec<String>,
    cursor_row: u16,
    cursor_col: u16,
    cursor_visible: bool,
    generation: u64,
    cols: usize,
    rows: usize,
) {
    let mut bounded: Vec<String> = Vec::new();
    let mut bytes = 0usize;
    for line in lines.into_iter().take(MAX_INSPECT_ROWS) {
        let cut = truncate_line(&line, MAX_INSPECT_COLS);
        let len = cut.len();
        if bytes + len > MAX_INSPECT_TEXT_BYTES {
            break;
        }
        bytes += len;
        bounded.push(cut);
    }
    let stored = StoredGrid {
        lines: bounded,
        cursor_row,
        cursor_col,
        cursor_visible,
        generation,
        cols,
        rows,
    };
    if let Ok(mut guard) = live_grid_store().lock() {
        *guard = stored;
    }
}

/// Publish the input ring to the live store (called by `bitty-runtime`).
///
/// At most [`MAX_INPUT_RING`] events are retained; each `kind`/`label`/
/// `button` is truncated to its bound. Oversize input beyond the ring is
/// dropped oldest-first (never an error, never unbounded).
pub fn publish_input_ring(events: Vec<InputEventPublish>) {
    let mut bounded: Vec<InputEventPublish> = Vec::with_capacity(events.len().min(MAX_INPUT_RING));
    for mut e in events.into_iter().take(MAX_INPUT_RING) {
        e.kind = truncate_chars(&e.kind, 16);
        e.label = truncate_chars(&e.label, MAX_INPUT_LABEL_CHARS);
        if let Some(button) = e.button {
            e.button = Some(truncate_chars(&button, 16));
        }
        bounded.push(e);
    }
    if let Ok(mut guard) = live_input_store().lock() {
        *guard = bounded;
    }
}

/// Publish modifier/latch state to the live store (called by `bitty-runtime`).
pub fn publish_modifiers(snapshot: ModifiersPublish) {
    if let Ok(mut guard) = live_modifiers_store().lock() {
        *guard = StoredModifiers {
            shift: snapshot.shift,
            control: snapshot.control,
            alt: snapshot.alt,
            enhanced_keyboard_flags: snapshot.enhanced_keyboard_flags,
        };
    }
}

/// Publish focus/window state to the live store (called by `bitty-runtime`).
pub fn publish_focus(snapshot: FocusPublish) {
    if let Ok(mut guard) = live_focus_store().lock() {
        *guard = StoredFocus {
            focused: snapshot.focused,
            focused_view: snapshot.focused_view,
            mouse_capture: snapshot.mouse_capture,
            alt_screen: snapshot.alt_screen,
            bracketed_paste: snapshot.bracketed_paste,
            focus_events: snapshot.focus_events,
        };
    }
}

// ── frame-digest live store (CTX-0244) ──────────────────────────────────────
//
// The runtime publishes the last presented headless RGBA frame here (only
// while a `FrameDigest` bearer is live — see
// [`frame_digest_publish_wanted`]); `handle_frame_hash` digests it without
// ever placing pixel bytes in a response. Same `&self`-only, bounded,
// drop-on-poison posture as the grid store.

/// Hard cap on RGBA bytes retained for digesting (64 MiB): mirrors
/// `bitty-render`'s `MAX_HEADLESS_SURFACE_BYTES` (CR-RENDER-01 parity — the
/// canonical RGBA read reuses the present-path allocation cap, no new
/// unbounded surface allocation). A local const (not an import) keeps
/// `bitty-ipc` dependency-free; the value is pinned by the digest tests
/// against multi-megapixel frames.
pub const MAX_DIGEST_RGBA_BYTES: usize = 64 * 1024 * 1024;

/// Stored headless frame for digesting (private; validated on entry).
#[derive(Debug, Clone, Default)]
pub(super) struct StoredRgba {
    /// Frame width in physical pixels.
    pub(super) width_px: u32,
    /// Frame height in physical pixels.
    pub(super) height_px: u32,
    /// Present-path frame sequence bound into the digest.
    pub(super) frame_seq: u64,
    /// Premultiplied RGBA bytes (`width*height*4`), never served raw.
    pub(super) rgba: Vec<u8>,
}

/// Live RGBA store (empty until the runtime publishes after a present).
pub(super) fn live_rgba_store() -> &'static Mutex<StoredRgba> {
    static STORE: OnceLock<Mutex<StoredRgba>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(StoredRgba::default()))
}

/// Publish one presented headless frame for digesting (called by
/// `bitty-runtime` after a successful headless present, gated on
/// [`frame_digest_publish_wanted`] so idle production pays nothing).
///
/// Fail-closed validation: zero extents, `rgba.len() != w*h*4` (checked
/// arithmetic, no overflow), or `rgba.len() > MAX_DIGEST_RGBA_BYTES` all
/// drop the publish (the next present republishes). A poisoned mutex drops
/// the publish. Pixel bytes are stored, never served: only the digest
/// leaves over IPC.
pub fn publish_frame_rgba(width_px: u32, height_px: u32, frame_seq: u64, rgba: Vec<u8>) {
    if width_px == 0 || height_px == 0 {
        return;
    }
    let expect = u64::from(width_px)
        .checked_mul(u64::from(height_px))
        .and_then(|pixels| pixels.checked_mul(4));
    let Some(expect) = expect else {
        return;
    };
    if expect == 0 || expect > MAX_DIGEST_RGBA_BYTES as u64 || rgba.len() as u64 != expect {
        return;
    }
    if let Ok(mut guard) = live_rgba_store().lock() {
        *guard = StoredRgba {
            width_px,
            height_px,
            frame_seq,
            rgba,
        };
    }
}

/// Clear the live introspection store (test helper only).
///
/// Tests publish known snapshots and must not leak them into parallel tests:
/// clear before and after each global round-trip. Production never calls this.
pub fn clear_introspection_for_tests() {
    if let Ok(mut guard) = live_grid_store().lock() {
        *guard = StoredGrid::default();
    }
    if let Ok(mut guard) = live_input_store().lock() {
        guard.clear();
    }
    if let Ok(mut guard) = live_modifiers_store().lock() {
        *guard = StoredModifiers::default();
    }
    if let Ok(mut guard) = live_focus_store().lock() {
        *guard = StoredFocus::default();
    }
    if let Ok(mut guard) = live_rgba_store().lock() {
        *guard = StoredRgba::default();
    }
}

/// Parse an optional unsigned param from raw `params` JSON.
///
/// Returns `default` when `params` is absent or the key is absent (absent
/// means default scope). Fails closed with `InvalidParams` when the key is
/// present but not a plain non-negative integer, or when the value exceeds
/// `max`. Unknown keys are ignored (forward compatible). The scan is a
/// bounded substring search over at most [`MAX_PARAMS_BYTES`] bytes: no
/// allocation beyond the returned value, no recursion, no backtracking.
pub(super) fn parse_optional_uint_param(
    params_raw: Option<&str>,
    key: &str,
    default: usize,
    max: usize,
) -> Result<usize, HandlerError> {
    let Some(params) = params_raw else {
        return Ok(default);
    };
    let needle = format!("\"{key}\"");
    let Some(key_pos) = params.find(needle.as_str()) else {
        return Ok(default);
    };
    let after_key = &params[key_pos + needle.len()..];
    let Some(colon) = after_key.find(':') else {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            format!("params {key} must be a number"),
        ));
    };
    let mut value_part = after_key[colon + 1..].trim_start();
    // Reject quoted strings, objects, arrays, and signs up front.
    if value_part.starts_with('"')
        || value_part.starts_with('{')
        || value_part.starts_with('[')
        || value_part.starts_with('-')
        || value_part.starts_with('+')
    {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            format!("params {key} must be a number"),
        ));
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
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            format!("params {key} must be a number"),
        ));
    }
    value_part = &value_part[..len];
    let value: usize = value_part.parse().map_err(|_| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            format!("params {key} must be a number"),
        )
    })?;
    if value == 0 || value > max {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            format!("params {key} must be 1..={max}"),
        ));
    }
    Ok(value)
}

/// `bitty.debug/getGridText`: bounded grid text plus cursor.
///
/// Params scope (all optional, fail-closed on oversize/unknown types):
/// `{ "rows": 1..=64, "cols": 1..=256 }` (defaults: full bounded store).
/// Returns `{"snapshot":"grid-text","lines":[...],"cursor":{...},"cols",
/// `"rows","generation"}`. Empty store (never published) yields empty lines
/// with generation `0` rather than an error.
fn handle_get_grid_text(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    // A named terminal is validated (fail closed on malformed ids) but the
    // store is unattributed, so authorization covers every terminal.
    request_terminal_id(request.params_raw.as_deref())?;
    require_debug_terminal_read(context, "bitty.debug/getGridText")?;
    let rows = parse_optional_uint_param(
        request.params_raw.as_deref(),
        "rows",
        MAX_INSPECT_ROWS,
        MAX_INSPECT_ROWS,
    )?;
    let cols = parse_optional_uint_param(
        request.params_raw.as_deref(),
        "cols",
        MAX_INSPECT_COLS,
        MAX_INSPECT_COLS,
    )?;
    let guard = live_grid_store().lock().map_err(|_| {
        HandlerError::new(
            "transport",
            "Unavailable",
            "introspection store unavailable".to_string(),
        )
    })?;
    let take = rows.min(guard.lines.len());
    let mut out = String::with_capacity(1024.min(MAX_INSPECT_JSON_BYTES));
    out.push_str("{\"version\":\"");
    out.push_str(DEVTOOLS_PROTOCOL_VERSION);
    out.push_str("\",\"snapshot\":\"grid-text\",\"lines\":[");
    for (i, line) in guard.lines.iter().take(take).enumerate() {
        if i > 0 {
            out.push(',');
        }
        let cut = truncate_line(line, cols);
        out.push('"');
        json_escape_into(&mut out, &cut);
        out.push('"');
        if out.len() > MAX_INSPECT_JSON_BYTES {
            return Err(HandlerError::new(
                "transport",
                "PayloadTooLarge",
                "grid snapshot exceeds response bound".to_string(),
            ));
        }
    }
    out.push_str("],\"cursor\":{\"row\":");
    out.push_str(&guard.cursor_row.to_string());
    out.push_str(",\"col\":");
    out.push_str(&guard.cursor_col.to_string());
    out.push_str(",\"visible\":");
    out.push_str(if guard.cursor_visible {
        "true"
    } else {
        "false"
    });
    out.push_str("},\"cols\":");
    out.push_str(&guard.cols.to_string());
    out.push_str(",\"rows\":");
    out.push_str(&guard.rows.to_string());
    out.push_str(",\"generation\":");
    out.push_str(&guard.generation.to_string());
    out.push('}');
    if out.len() > MAX_INSPECT_JSON_BYTES {
        return Err(HandlerError::new(
            "transport",
            "PayloadTooLarge",
            "grid snapshot exceeds response bound".to_string(),
        ));
    }
    Ok(out)
}

/// `bitty.debug/getInputRing`: bounded last-input events.
///
/// Params scope: `{ "limit": 1..=64 }` (default: full ring). Returns
/// `{"snapshot":"input-ring","events":[{seq,kind,label,shift,control,alt,
/// button,col,row,pressed}],"dropped_notice":false}`. Empty store yields an
/// empty array rather than an error.
fn handle_get_input_ring(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    // A named terminal is validated (fail closed on malformed ids) but the
    // store is unattributed, so authorization covers every terminal.
    request_terminal_id(request.params_raw.as_deref())?;
    require_debug_terminal_read(context, "bitty.debug/getInputRing")?;
    let limit = parse_optional_uint_param(
        request.params_raw.as_deref(),
        "limit",
        MAX_INPUT_RING,
        MAX_INPUT_RING,
    )?;
    let guard = live_input_store().lock().map_err(|_| {
        HandlerError::new(
            "transport",
            "Unavailable",
            "introspection store unavailable".to_string(),
        )
    })?;
    let total = guard.len();
    let take = limit.min(total);
    let start = total - take;
    let mut out = String::with_capacity(512.min(MAX_INSPECT_JSON_BYTES));
    out.push_str("{\"version\":\"");
    out.push_str(DEVTOOLS_PROTOCOL_VERSION);
    out.push_str("\",\"snapshot\":\"input-ring\",\"events\":[");
    for (i, e) in guard.iter().skip(start).enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"seq\":");
        out.push_str(&e.seq.to_string());
        out.push_str(",\"kind\":\"");
        json_escape_into(&mut out, &truncate_chars(&e.kind, 16));
        out.push_str("\",\"label\":\"");
        json_escape_into(&mut out, &truncate_chars(&e.label, MAX_INPUT_LABEL_CHARS));
        out.push_str("\",\"shift\":");
        out.push_str(if e.shift { "true" } else { "false" });
        out.push_str(",\"control\":");
        out.push_str(if e.control { "true" } else { "false" });
        out.push_str(",\"alt\":");
        out.push_str(if e.alt { "true" } else { "false" });
        out.push_str(",\"button\":");
        match &e.button {
            Some(b) => {
                out.push('"');
                json_escape_into(&mut out, &truncate_chars(b, 16));
                out.push('"');
            }
            None => out.push_str("null"),
        }
        out.push_str(",\"col\":");
        match e.col {
            Some(c) => out.push_str(&c.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(",\"row\":");
        match e.row {
            Some(r) => out.push_str(&r.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(",\"pressed\":");
        match e.pressed {
            Some(true) => out.push_str("true"),
            Some(false) => out.push_str("false"),
            None => out.push_str("null"),
        }
        out.push('}');
        if out.len() > MAX_INSPECT_JSON_BYTES {
            return Err(HandlerError::new(
                "transport",
                "PayloadTooLarge",
                "input ring exceeds response bound".to_string(),
            ));
        }
    }
    out.push_str("],\"count\":");
    out.push_str(&take.to_string());
    out.push('}');
    Ok(out)
}

/// `bitty.debug/getModifiers`: modifier/latch state (no params).
fn handle_get_modifiers(
    context: &ServeContext,
    _request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    require_debug_terminal_read(context, "bitty.debug/getModifiers")?;
    let guard = live_modifiers_store().lock().map_err(|_| {
        HandlerError::new(
            "transport",
            "Unavailable",
            "introspection store unavailable".to_string(),
        )
    })?;
    let mut out = String::with_capacity(128);
    out.push_str("{\"version\":\"");
    out.push_str(DEVTOOLS_PROTOCOL_VERSION);
    out.push_str("\",\"snapshot\":\"modifiers\",\"shift\":");
    out.push_str(if guard.shift { "true" } else { "false" });
    out.push_str(",\"control\":");
    out.push_str(if guard.control { "true" } else { "false" });
    out.push_str(",\"alt\":");
    out.push_str(if guard.alt { "true" } else { "false" });
    out.push_str(",\"kitty_flags\":");
    out.push_str(&guard.enhanced_keyboard_flags.to_string());
    out.push('}');
    Ok(out)
}

/// `bitty.debug/getFocus`: focus/window state (no params).
fn handle_get_focus(
    context: &ServeContext,
    _request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    require_debug_terminal_read(context, "bitty.debug/getFocus")?;
    let guard = live_focus_store().lock().map_err(|_| {
        HandlerError::new(
            "transport",
            "Unavailable",
            "introspection store unavailable".to_string(),
        )
    })?;
    let mut out = String::with_capacity(192);
    out.push_str("{\"version\":\"");
    out.push_str(DEVTOOLS_PROTOCOL_VERSION);
    out.push_str("\",\"snapshot\":\"focus\",\"focused\":");
    out.push_str(if guard.focused { "true" } else { "false" });
    out.push_str(",\"focused_view\":");
    match guard.focused_view {
        Some(v) => out.push_str(&v.to_string()),
        None => out.push_str("null"),
    }
    out.push_str(",\"mouse_capture\":");
    out.push_str(if guard.mouse_capture { "true" } else { "false" });
    out.push_str(",\"alt_screen\":");
    out.push_str(if guard.alt_screen { "true" } else { "false" });
    out.push_str(",\"bracketed_paste\":");
    out.push_str(if guard.bracketed_paste {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"focus_events\":");
    out.push_str(if guard.focus_events { "true" } else { "false" });
    out.push('}');
    Ok(out)
}

// ── runtime control (CTX-0171) ─────────────────────────────────────────────
//
// Control handlers authorize against the connection's server-owned authority
// (CTX-0792, #1403: a per-connection principal/session, never
// client-asserted), carry that authorization snapshot in the queue item, and
// enqueue for the main thread — the sole `Runtime` owner — which re-validates
// the snapshot against the live authority immediately before mutation. The
// connection thread blocks up to one `CTL_TIMEOUT` for the reply; timeout
// becomes `Unavailable` (fail-closed, no partial state). List verbs
// (`listWindows`, `listViews`, `listTerminals`) also flow through the queue so
// `view`/`terminal` listings reflect live `Runtime` layout rather than stale
// startup facts.

/// Shared control handler for all fourteen `bitty.debug/*` control methods.
///
/// Validates params shape via `ctl` parsers (fail-closed `InvalidParams`
/// before enqueue), authorizes via the connection grant (scope plus terminal
/// capability, fail-closed `ScopeDenied`), then enqueues and waits. Hermetic
/// contexts without an authority (`authority_required == false`) fall back
/// to their explicit granted scopes.
fn handle_control(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    // Fail fast on malformed params before touching the queue: each verb's
    // parser enforces its bounds (ids, text, cwd, direction).
    if let Err(reason) = prevalidate_control_params(&request.method, request.params_raw.as_deref())
    {
        return Err(HandlerError::new("usage", "InvalidParams", reason));
    }
    let reply = if context.authority_required() {
        let Some(grant) = context.connection_grant() else {
            return Err(HandlerError::new(
                "scope",
                "Unauthenticated",
                "connection authority is unavailable".into(),
            ));
        };
        crate::ctl::enqueue_control_and_wait_with_connection(
            &request.method,
            request.params_raw.as_deref(),
            &request.id_raw,
            grant,
        )
    } else {
        crate::ctl::enqueue_control_and_wait(
            &request.method,
            request.params_raw.as_deref(),
            &request.id_raw,
            context.construction_scopes(),
        )
    };
    if reply.ok {
        Ok(reply.result_json)
    } else {
        Err(HandlerError::new(
            debug_error_category(reply.category),
            reply.code,
            reply.message,
        ))
    }
}

/// Map a control-reply category onto the accepted debug-protocol taxonomy.
///
/// The devtools-rfc fixes the wire category set to `usage`, `capability`,
/// `scope`, `budget`, `generation`, and `transport`. The internal
/// [`crate::ctl::ControlReply`] uses `auth` as a CLI exit-code class
/// (`bitty ctl` maps it to exit 7); `auth` is not a debug-protocol category,
/// so a permission failure is reported as `scope` on the wire. The stable
/// `code` (`ScopeDenied` / `Denied` / `Unauthenticated`) still distinguishes
/// the exact denial. Every other control category (`usage`, `budget`,
/// `transport`) is already on the accepted taxonomy and passes through.
fn debug_error_category(category: &'static str) -> &'static str {
    match category {
        "auth" => "scope",
        other => other,
    }
}

/// Pre-enqueue params shape check (bounds only; existence resolves at apply).
fn prevalidate_control_params(method: &str, params: Option<&str>) -> Result<(), String> {
    let res: Result<(), bitty_ipc_api::error::IpcError> = match method {
        m if m == crate::ctl::METHOD_CLOSE_TERMINAL
            || m == crate::ctl::METHOD_GET_TERMINAL_TEXT =>
        {
            crate::ctl::parse_terminal_id_params(params).map(|_| ())
        }
        m if m == crate::ctl::METHOD_SEND_INPUT => {
            crate::ctl::parse_send_params(params).map(|_| ())
        }
        m if m == crate::ctl::METHOD_SPAWN_TERMINAL => {
            crate::ctl::parse_spawn_params(params).map(|_| ())
        }
        m if m == crate::ctl::METHOD_SPLIT_VIEW => {
            crate::ctl::parse_split_params(params).map(|_| ())
        }
        m if m == crate::ctl::METHOD_FOCUS_VIEW => {
            crate::ctl::parse_focus_params(params).map(|_| ())
        }
        // listWindows/listViews/listTerminals/reloadConfig take no params.
        _ => Ok(()),
    };
    res.map_err(|err| format!("{err}"))
}
