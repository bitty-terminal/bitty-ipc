//! Accepted devtools-rfc v1 plugin-runtime methods (issue #1377).
//!
//! The six `inspect` readers (`listPlugins`, `getPlugin`,
//! `listSubscriptions`, `getBudgets`, `getQueueSnapshot`, `listHandles`),
//! the `trace` event stream (`streamEvents`), and the three `control`
//! lifecycle verbs (`suspendHandler`, `resumePlugin`, `disposeGeneration`).
//!
//! `bitty-ipc` owns no plugin host: the registry, VM budgets, queues, and
//! handle tables live in `bitty-plugin-host` / `bitty-lua`, owned upstream
//! by `bitty-runtime`, and this crate deliberately takes no dependency on
//! them (the runtime-to-IPC direction publishes live stores; the IPC layer
//! never reaches up). Each handler therefore enforces the RFC scope gate
//! plus the RFC param grammar — resources addressed as
//! `(pluginId, generation)` — and then fails closed with a typed
//! `capability`/`PluginRuntimeUnavailable` verdict naming the missing
//! backend. Scope denials stay `scope`/`ScopeDenied`, malformed params stay
//! `usage`/`InvalidParams`, and no partial state is ever created, so the
//! error taxonomy never leaves the accepted
//! (`usage`|`capability`|`scope`|`budget`|`generation`|`transport`) set.
//!
//! Wiring live data later means attaching a published plugin-runtime store
//! (the CTX-0159 introspection pattern) and replacing
//! [`plugin_runtime_unavailable`] at that point; the scope and param gates
//! below stay as-is.

use super::handlers::HandlerError;
use super::json::DevtoolsRequest;
use super::serve::ServeContext;
use crate::scope::Scope;

// ── bounds (mirror the `bitty-devtools` client guards) ─────────────────────
//
// The client validates these shapes before sending (`inspection.ts`:
// `pluginId` 1..128, `generation` integer >= 1; `control.ts`: `handlerId`
// 1..64, `cause` 1..256, `generation` integer >= 1; `tracing.ts`:
// `types[]` entries 1..64 chars, `batch` within `BUS_BATCH_MAX_EVENTS` 32 /
// `BUS_BATCH_MAX_BYTES` 8 KiB). The server re-checks every bound so a raw
// socket peer gets the same fail-closed verdicts.

/// Maximum `pluginId` bytes (client `InvalidPluginId` bound).
const MAX_PLUGIN_ID_BYTES: usize = 128;

/// Maximum `handlerId` bytes (`control.ts` bound).
const MAX_HANDLER_ID_BYTES: usize = 64;

/// Maximum `cause` bytes (`control.ts` bound).
const MAX_CAUSE_BYTES: usize = 256;

/// Maximum `streamEvents` event-type entries (`BUS_BATCH_MAX_EVENTS`).
const MAX_STREAM_TYPES: usize = 32;

/// Maximum event-type string bytes (`tracing.ts` per-type bound).
const MAX_EVENT_TYPE_BYTES: usize = 64;

/// Maximum `streamEvents` batch events (`BUS_BATCH_MAX_EVENTS`).
const MAX_BATCH_EVENTS: u64 = 32;

/// Maximum `streamEvents` batch bytes (`BUS_BATCH_MAX_BYTES`).
const MAX_BATCH_BYTES: u64 = 8 * 1024;

// ── scope gates ─────────────────────────────────────────────────────────────

/// Require any debug scope (the accepted read surface: `debug.inspect` or
/// the wider `debug.trace` / `debug.control`).
fn require_inspect_scope(context: &ServeContext, method: &str) -> Result<(), HandlerError> {
    if context.has_any_scope(&[Scope::DebugInspect, Scope::DebugTrace, Scope::DebugControl]) {
        return Ok(());
    }
    Err(HandlerError::new(
        "scope",
        "ScopeDenied",
        format!("permission denied: scope 'debug.inspect' denied for {method} (needs elevation)"),
    ))
}

/// Require `debug.trace` (or the wider `debug.control`) for the event
/// stream, mirroring the trace-lifecycle gate.
fn require_trace_scope(context: &ServeContext, method: &str) -> Result<(), HandlerError> {
    if context.has_scope(Scope::DebugTrace) || context.has_scope(Scope::DebugControl) {
        return Ok(());
    }
    Err(HandlerError::new(
        "scope",
        "ScopeDenied",
        format!("permission denied: scope 'debug.trace' denied for {method} (needs elevation)"),
    ))
}

/// Require exactly `debug.control` for lifecycle verbs (generation suspend,
/// resume, disposal affect live VM state).
fn require_control_scope(context: &ServeContext, method: &str) -> Result<(), HandlerError> {
    if context.has_scope(Scope::DebugControl) {
        return Ok(());
    }
    Err(HandlerError::new(
        "scope",
        "ScopeDenied",
        format!("permission denied: scope 'debug.control' denied for {method} (needs elevation)"),
    ))
}

// ── param helpers (dependency-free top-level scans) ─────────────────────────

/// Find the raw value span after a top-level `"key":` (caller decides shape).
fn top_value_span<'a>(params: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let pos = params.find(needle.as_str())?;
    let after_key = &params[pos + needle.len()..];
    let colon = after_key.find(':')?;
    Some(after_key[colon + 1..].trim_start())
}

/// Extract a top-level JSON string field with escape decoding; `None` when
/// the key is absent or the value is not a JSON string.
fn top_string(params: &str, key: &str) -> Option<String> {
    let mut value = top_value_span(params, key)?;
    if !value.starts_with('"') {
        return None;
    }
    value = &value[1..];
    let mut out = String::new();
    let mut chars = value.chars();
    loop {
        let c = chars.next()?;
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let mut code: u32 = 0;
                    for _ in 0..4 {
                        code = code * 16 + chars.next()?.to_digit(16)?;
                    }
                    out.push(char::from_u32(code)?);
                }
                _ => return None,
            },
            _ => out.push(c),
        }
    }
}

/// Extract a top-level unsigned integer field; `None` when absent or not a
/// bare non-negative integer.
fn top_uint(params: &str, key: &str) -> Option<u64> {
    let value = top_value_span(params, key)?;
    if value.starts_with('"') || value.starts_with('{') || value.starts_with('[') {
        return None;
    }
    let digits_len = value.bytes().take_while(u8::is_ascii_digit).count();
    if digits_len == 0 || digits_len > 20 {
        return None;
    }
    value[..digits_len].parse().ok()
}

/// Whether `params` carries an explicit JSON `null` for `key`
/// (`listPlugins` accepts `{ "generation": null }` per the RFC example).
fn top_is_null(params: &str, key: &str) -> bool {
    top_value_span(params, key).is_some_and(|value| value.starts_with("null"))
}

/// Validate a `pluginId` param: 1..=128 bytes, no NUL.
fn validate_plugin_id(raw: &str) -> Result<(), String> {
    if raw.is_empty() || raw.len() > MAX_PLUGIN_ID_BYTES || raw.contains('\0') {
        return Err(format!(
            "pluginId must be 1..={MAX_PLUGIN_ID_BYTES} bytes, no NUL"
        ));
    }
    Ok(())
}

/// Validate a `generation` param: integer >= 1 (generation ownership: every
/// lifecycle resource is addressed as `(pluginId, generation)`).
fn validate_generation(value: u64) -> Result<(), String> {
    if value < 1 {
        return Err("generation must be >= 1".to_string());
    }
    Ok(())
}

/// Require a `pluginId` string param from the envelope.
fn require_plugin_id(params: &str, method_short: &str) -> Result<String, HandlerError> {
    let plugin_id = top_string(params, "pluginId").ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            format!("{method_short} requires pluginId"),
        )
    })?;
    if let Err(reason) = validate_plugin_id(&plugin_id) {
        return Err(HandlerError::new("usage", "InvalidParams", reason));
    }
    Ok(plugin_id)
}

/// Require a `generation` uint param from the envelope.
fn require_generation(params: &str, method_short: &str) -> Result<u64, HandlerError> {
    let generation = top_uint(params, "generation").ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            format!("{method_short} requires generation >= 1"),
        )
    })?;
    if let Err(reason) = validate_generation(generation) {
        return Err(HandlerError::new("usage", "InvalidParams", reason));
    }
    Ok(generation)
}

/// Fail-closed verdict once scope and params pass: no plugin host is
/// attached to this IPC server slice, so nothing was read or mutated.
fn plugin_runtime_unavailable(method: &str) -> HandlerError {
    HandlerError::new(
        "capability",
        "PluginRuntimeUnavailable",
        format!(
            "{method}: plugin runtime not attached to this IPC server slice (no registry, budgets, queues, or handle tables; wire bitty-plugin-host/bitty-lua for live data)"
        ),
    )
}

// ── inspect readers ─────────────────────────────────────────────────────────

/// `bitty.debug/listPlugins`: optional `generation` filter (`null` or uint).
pub(super) fn handle_list_plugins(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    require_inspect_scope(context, super::METHOD_LIST_PLUGINS)?;
    let params = request.params_raw.as_deref().unwrap_or("{}");
    if !params.trim_start().starts_with('{') {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            "listPlugins requires an object params".to_string(),
        ));
    }
    if !top_is_null(params, "generation") {
        if let Some(generation) = top_uint(params, "generation") {
            if let Err(reason) = validate_generation(generation) {
                return Err(HandlerError::new("usage", "InvalidParams", reason));
            }
        } else if top_value_span(params, "generation").is_some() {
            return Err(HandlerError::new(
                "usage",
                "InvalidParams",
                "generation must be null or an integer >= 1".to_string(),
            ));
        }
    }
    Err(plugin_runtime_unavailable(super::METHOD_LIST_PLUGINS))
}

/// `bitty.debug/getPlugin`: required `pluginId`.
pub(super) fn handle_get_plugin(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    require_inspect_scope(context, super::METHOD_GET_PLUGIN)?;
    let params = request.params_raw.as_deref().unwrap_or("{}");
    let _plugin_id = require_plugin_id(params, "getPlugin")?;
    Err(plugin_runtime_unavailable(super::METHOD_GET_PLUGIN))
}

/// `bitty.debug/listSubscriptions`: required `pluginId`.
pub(super) fn handle_list_subscriptions(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    require_inspect_scope(context, super::METHOD_LIST_SUBSCRIPTIONS)?;
    let params = request.params_raw.as_deref().unwrap_or("{}");
    let _plugin_id = require_plugin_id(params, "listSubscriptions")?;
    Err(plugin_runtime_unavailable(super::METHOD_LIST_SUBSCRIPTIONS))
}

/// `bitty.debug/getBudgets`: required `(pluginId, generation)` (generation
/// ownership: budgets are per-generation counters).
pub(super) fn handle_get_budgets(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    require_inspect_scope(context, super::METHOD_GET_BUDGETS)?;
    let params = request.params_raw.as_deref().unwrap_or("{}");
    let _plugin_id = require_plugin_id(params, "getBudgets")?;
    let _generation = require_generation(params, "getBudgets")?;
    Err(plugin_runtime_unavailable(super::METHOD_GET_BUDGETS))
}

/// `bitty.debug/getQueueSnapshot`: required `pluginId`.
pub(super) fn handle_get_queue_snapshot(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    require_inspect_scope(context, super::METHOD_GET_QUEUE_SNAPSHOT)?;
    let params = request.params_raw.as_deref().unwrap_or("{}");
    let _plugin_id = require_plugin_id(params, "getQueueSnapshot")?;
    Err(plugin_runtime_unavailable(super::METHOD_GET_QUEUE_SNAPSHOT))
}

/// `bitty.debug/listHandles`: required `pluginId`.
pub(super) fn handle_list_handles(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    require_inspect_scope(context, super::METHOD_LIST_HANDLES)?;
    let params = request.params_raw.as_deref().unwrap_or("{}");
    let _plugin_id = require_plugin_id(params, "listHandles")?;
    Err(plugin_runtime_unavailable(super::METHOD_LIST_HANDLES))
}

// ── trace stream ────────────────────────────────────────────────────────────

/// Find the inner span of a top-level JSON array field (`"key": [...]`),
/// string-aware so `]` inside quoted event types does not end the scan.
fn find_array_inner(params: &str, key: &str) -> Option<(usize, usize)> {
    let needle = format!("\"{key}\"");
    let pos = params.find(needle.as_str())?;
    let after_key = &params[pos + needle.len()..];
    let colon = after_key.find(':')?;
    let mut i = pos + needle.len() + colon + 1;
    let bytes = params.as_bytes();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if bytes.get(i) != Some(&b'[') {
        return None;
    }
    i += 1;
    let inner_start = i;
    let mut depth = 1usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                let mut escape = false;
                while i < bytes.len() {
                    if escape {
                        escape = false;
                    } else if bytes[i] == b'\\' {
                        escape = true;
                    } else if bytes[i] == b'"' {
                        break;
                    }
                    i += 1;
                }
                if i >= bytes.len() {
                    return None;
                }
            }
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some((inner_start, i));
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Split top-level comma-separated JSON strings (event types are plain
/// strings; anything else fails closed).
fn split_top_strings(inner: &str) -> Result<Vec<String>, ()> {
    let mut out = Vec::new();
    if inner.trim().is_empty() {
        return Ok(out);
    }
    let mut current = String::new();
    let mut in_string = false;
    let mut escape = false;
    let mut seen_token = false;
    for c in inner.chars() {
        if in_string {
            if escape {
                current.push(c);
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            } else {
                current.push(c);
            }
            continue;
        }
        match c {
            '"' => {
                if seen_token {
                    return Err(());
                }
                in_string = true;
                seen_token = true;
            }
            ',' => {
                if !seen_token {
                    return Err(());
                }
                out.push(std::mem::take(&mut current));
                seen_token = false;
            }
            c if c.is_whitespace() => {}
            _ => return Err(()),
        }
    }
    if in_string || !seen_token {
        return Err(());
    }
    out.push(current);
    Ok(out)
}

/// Find the raw object span of a top-level `"key": {...}` field.
fn find_object_span(params: &str, key: &str) -> Option<(usize, usize)> {
    let needle = format!("\"{key}\"");
    let pos = params.find(needle.as_str())?;
    let after_key = &params[pos + needle.len()..];
    let colon = after_key.find(':')?;
    let mut i = pos + needle.len() + colon + 1;
    let bytes = params.as_bytes();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if bytes.get(i) != Some(&b'{') {
        return None;
    }
    let obj_start = i;
    let mut depth = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                let mut escape = false;
                while i < bytes.len() {
                    if escape {
                        escape = false;
                    } else if bytes[i] == b'\\' {
                        escape = true;
                    } else if bytes[i] == b'"' {
                        break;
                    }
                    i += 1;
                }
                if i >= bytes.len() {
                    return None;
                }
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((obj_start, i + 1));
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// `bitty.debug/streamEvents`: required `types[]` plus
/// `batch: { maxEvents, maxBytes }`, both bounded.
pub(super) fn handle_stream_events(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    require_trace_scope(context, super::METHOD_STREAM_EVENTS)?;
    let params = request.params_raw.as_deref().ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "streamEvents requires params".to_string(),
        )
    })?;
    let (start, end) = find_array_inner(params, "types").ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "streamEvents requires types array".to_string(),
        )
    })?;
    let types = split_top_strings(&params[start..end]).map_err(|()| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "types must be an array of strings".to_string(),
        )
    })?;
    if types.is_empty() || types.len() > MAX_STREAM_TYPES {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            format!("types must be 1..={MAX_STREAM_TYPES} entries"),
        ));
    }
    for event_type in &types {
        if event_type.is_empty()
            || event_type.len() > MAX_EVENT_TYPE_BYTES
            || event_type.contains('\0')
        {
            return Err(HandlerError::new(
                "usage",
                "InvalidParams",
                format!("event type must be 1..={MAX_EVENT_TYPE_BYTES} bytes, no NUL"),
            ));
        }
    }
    let (batch_start, batch_end) = find_object_span(params, "batch").ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "streamEvents requires batch { maxEvents, maxBytes }".to_string(),
        )
    })?;
    let batch = &params[batch_start..batch_end];
    let max_events = top_uint(batch, "maxEvents").ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "batch.maxEvents must be a positive integer".to_string(),
        )
    })?;
    if max_events == 0 || max_events > MAX_BATCH_EVENTS {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            format!("batch.maxEvents must be 1..={MAX_BATCH_EVENTS}"),
        ));
    }
    let max_bytes = top_uint(batch, "maxBytes").ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "batch.maxBytes must be a positive integer".to_string(),
        )
    })?;
    if max_bytes == 0 || max_bytes > MAX_BATCH_BYTES {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            format!("batch.maxBytes must be 1..={MAX_BATCH_BYTES}"),
        ));
    }
    Err(plugin_runtime_unavailable(super::METHOD_STREAM_EVENTS))
}

// ── control verbs ───────────────────────────────────────────────────────────

/// `bitty.debug/suspendHandler`: required `(pluginId, handlerId, cause)`.
pub(super) fn handle_suspend_handler(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    require_control_scope(context, super::METHOD_SUSPEND_HANDLER)?;
    let params = request.params_raw.as_deref().unwrap_or("{}");
    let _plugin_id = require_plugin_id(params, "suspendHandler")?;
    let handler_id = top_string(params, "handlerId").ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "suspendHandler requires handlerId".to_string(),
        )
    })?;
    if handler_id.is_empty() || handler_id.len() > MAX_HANDLER_ID_BYTES || handler_id.contains('\0')
    {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            format!("handlerId must be 1..={MAX_HANDLER_ID_BYTES} bytes, no NUL"),
        ));
    }
    let cause = top_string(params, "cause").ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "suspendHandler requires cause".to_string(),
        )
    })?;
    if cause.is_empty() || cause.len() > MAX_CAUSE_BYTES || cause.contains('\0') {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            format!("cause must be 1..={MAX_CAUSE_BYTES} bytes, no NUL"),
        ));
    }
    Err(plugin_runtime_unavailable(super::METHOD_SUSPEND_HANDLER))
}

/// `bitty.debug/resumePlugin`: required `(pluginId, generation)`; a resume
/// always addresses one owned generation.
pub(super) fn handle_resume_plugin(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    require_control_scope(context, super::METHOD_RESUME_PLUGIN)?;
    let params = request.params_raw.as_deref().unwrap_or("{}");
    let _plugin_id = require_plugin_id(params, "resumePlugin")?;
    let _generation = require_generation(params, "resumePlugin")?;
    Err(plugin_runtime_unavailable(super::METHOD_RESUME_PLUGIN))
}

/// `bitty.debug/disposeGeneration`: required `(pluginId, generation)`;
/// disposal always addresses one owned generation.
pub(super) fn handle_dispose_generation(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    require_control_scope(context, super::METHOD_DISPOSE_GENERATION)?;
    let params = request.params_raw.as_deref().unwrap_or("{}");
    let _plugin_id = require_plugin_id(params, "disposeGeneration")?;
    let _generation = require_generation(params, "disposeGeneration")?;
    Err(plugin_runtime_unavailable(super::METHOD_DISPOSE_GENERATION))
}
