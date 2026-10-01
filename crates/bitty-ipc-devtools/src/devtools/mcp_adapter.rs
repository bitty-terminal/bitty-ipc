//! MCP adapter over the debug protocol (DT-10, #1106).
//!
//! Thin read-only translation between `bitty.debug/*` and MCP tool names.
//! The adapter owns no socket, spawns no thread, and performs no I/O: it is
//! pure method-name mapping plus a bounded JSON tool listing for a
//! read-only MCP host to consume.
//!
//! # v1 default posture
//!
//! Under the v1 default only read-only observation methods are exposed:
//! `ping`, `getSnapshot`, the four CTX-0159 introspection readers, the four
//! CTX-0189 sampling profiling readers, and `fetchTraceChunk` (active-trace
//! export page). Everything that mutates, captures, or drives the terminal
//! stays hidden: `synthesizeInput` / `captureFrame` / `frameHash`
//! (Amendment A1 bearer surface), `startTrace` / `stopTrace` (trace
//! lifecycle writers), all `bitty ctl` control verbs, and the `--test-mode`
//! E2E surface (`testInfo` / `testExit`). A denied method maps to `None` in
//! both directions and never appears in [`mcp_list_tools_json`].
//!
//! Trust posture: mapping grants no authority. Serving still goes through
//! [`crate::devtools::Dispatcher`] with scope, bearer, rate, and redaction
//! checks; this module only answers "is this tool part of the v1
//! read-only surface?".

use super::{
    METHOD_CAPTURE_FRAME, METHOD_DISPOSE_GENERATION, METHOD_FETCH_TRACE_CHUNK, METHOD_FRAME_HASH,
    METHOD_GET_BUDGETS, METHOD_GET_FRAME_STATS, METHOD_GET_PLUGIN, METHOD_GET_PROCESS_STATS,
    METHOD_GET_QUEUE_SNAPSHOT, METHOD_LIST_HANDLES, METHOD_LIST_PLUGINS, METHOD_LIST_SUBSCRIPTIONS,
    METHOD_RESUME_PLUGIN, METHOD_START_TRACE, METHOD_STOP_TRACE, METHOD_STREAM_EVENTS,
    METHOD_STREAM_FRAME_STATS, METHOD_STREAM_PROCESS_STATS, METHOD_SUSPEND_HANDLER,
    METHOD_SYNTHESIZE_INPUT, METHOD_TEST_EXIT, METHOD_TEST_INFO,
};

/// MCP adapter protocol version (tracks [`super::DEVTOOLS_PROTOCOL_VERSION`]).
pub const MCP_ADAPTER_VERSION: &str = "1.0";

/// MCP tool-name prefix for the debug surface.
pub const MCP_TOOL_PREFIX: &str = "bitty_debug_";

/// Read-only debug methods exposed as MCP tools under the v1 default.
///
/// Order is stable (wire order in [`Dispatcher::with_defaults`]): handshake,
/// snapshot, introspection, profiling, then trace export.
const MCP_EXPOSED_DEBUG_METHODS: &[&str] = &[
    "bitty.debug/ping",
    "bitty.debug/getSnapshot",
    "bitty.debug/getGridText",
    "bitty.debug/getInputRing",
    "bitty.debug/getModifiers",
    "bitty.debug/getFocus",
    METHOD_GET_PROCESS_STATS,
    METHOD_GET_FRAME_STATS,
    METHOD_STREAM_PROCESS_STATS,
    METHOD_STREAM_FRAME_STATS,
    METHOD_FETCH_TRACE_CHUNK,
];

/// Debug methods that must never appear as MCP tools under the v1 default.
///
/// Automation (bearer) surface, trace lifecycle writers, test-mode surface.
/// Control verbs are covered separately via
/// [`crate::ctl::all_control_methods`] and are likewise denied.
/// The accepted plugin-runtime v1 methods (issue #1377) stay denied too:
/// they are scope- and param-gated fail-closed stubs with no plugin host
/// behind them, so advertising them as MCP tools would promise data the
/// server cannot serve.
const MCP_DENIED_DEBUG_METHODS: &[&str] = &[
    METHOD_SYNTHESIZE_INPUT,
    METHOD_CAPTURE_FRAME,
    METHOD_FRAME_HASH,
    METHOD_START_TRACE,
    METHOD_STOP_TRACE,
    METHOD_TEST_INFO,
    METHOD_TEST_EXIT,
    METHOD_LIST_PLUGINS,
    METHOD_GET_PLUGIN,
    METHOD_LIST_SUBSCRIPTIONS,
    METHOD_GET_BUDGETS,
    METHOD_GET_QUEUE_SNAPSHOT,
    METHOD_LIST_HANDLES,
    METHOD_STREAM_EVENTS,
    METHOD_SUSPEND_HANDLER,
    METHOD_RESUME_PLUGIN,
    METHOD_DISPOSE_GENERATION,
];

/// MCP tool names exposed under the v1 default (parallel to
/// [`MCP_EXPOSED_DEBUG_METHODS`], same order).
const MCP_EXPOSED_TOOL_NAMES: &[&str] = &[
    "bitty_debug_ping",
    "bitty_debug_getSnapshot",
    "bitty_debug_getGridText",
    "bitty_debug_getInputRing",
    "bitty_debug_getModifiers",
    "bitty_debug_getFocus",
    "bitty_debug_getProcessStats",
    "bitty_debug_getFrameStats",
    "bitty_debug_streamProcessStats",
    "bitty_debug_streamFrameStats",
    "bitty_debug_fetchTraceChunk",
];

/// Whether a `bitty.debug/*` method is part of the v1 MCP read-only surface.
#[must_use]
pub fn is_mcp_exposed_debug_method(method: &str) -> bool {
    MCP_EXPOSED_DEBUG_METHODS.contains(&method)
}

/// Map an MCP tool name to its debug method.
///
/// Returns `None` for unknown tools and for tools that would name a denied
/// (automation / control / test-mode / trace-writer) method.
#[must_use]
pub fn debug_method_for_mcp_tool(tool: &str) -> Option<&'static str> {
    for (index, name) in MCP_EXPOSED_TOOL_NAMES.iter().enumerate() {
        if *name == tool {
            return MCP_EXPOSED_DEBUG_METHODS.get(index).copied();
        }
    }
    None
}

/// Map a debug method to its MCP tool name.
///
/// Returns `None` when the method is not on the v1 read-only surface
/// (automation, control, test-mode, trace writers, or unknown).
#[must_use]
pub fn mcp_tool_for_debug_method(method: &str) -> Option<&'static str> {
    for (index, exposed) in MCP_EXPOSED_DEBUG_METHODS.iter().enumerate() {
        if *exposed == method {
            return MCP_EXPOSED_TOOL_NAMES.get(index).copied();
        }
    }
    None
}

/// MCP tool names exposed under the v1 default (stable order).
#[must_use]
pub fn mcp_tool_names() -> &'static [&'static str] {
    MCP_EXPOSED_TOOL_NAMES
}

/// Debug methods denied under the v1 default (automation + trace writers +
/// test-mode surface; control verbs are denied via the `ctl` contract).
#[must_use]
pub fn mcp_denied_debug_methods() -> &'static [&'static str] {
    MCP_DENIED_DEBUG_METHODS
}

/// Bounded JSON listing of the v1 MCP tool surface.
///
/// Shape: `{"version":"1.0","tools":[{"name":"...","debugMethod":"..."}]}`.
/// Contains only exposed read-only methods; automation, control, trace
/// writers, and test-mode names never appear.
#[must_use]
pub fn mcp_list_tools_json() -> String {
    let mut out = String::with_capacity(1024);
    out.push_str("{\"version\":\"");
    out.push_str(MCP_ADAPTER_VERSION);
    out.push_str("\",\"tools\":[");
    for (index, tool) in MCP_EXPOSED_TOOL_NAMES.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"name\":\"");
        out.push_str(tool);
        out.push_str("\",\"debugMethod\":\"");
        if let Some(method) = MCP_EXPOSED_DEBUG_METHODS.get(index) {
            out.push_str(method);
        }
        out.push_str("\"}");
    }
    out.push_str("]}");
    out
}
