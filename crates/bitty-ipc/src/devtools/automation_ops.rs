use super::*;

use super::automation::{authorize_automation, automation_store};
use super::handlers::{
    json_escape_into, live_grid_store, live_input_store, live_rgba_store,
    parse_optional_uint_param, truncate_line,
};
use super::json::{echo_snippet, truncate_chars};

// ── automation params parsing (bounded, no JSON deps) ───────────────────────

/// Extract a top-level string field from a flat params object (bounded,
/// quote-aware; nested objects for the key are rejected).
fn extract_top_string(params: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut search = 0usize;
    let bytes = params.as_bytes();
    while let Some(pos) = params[search..].find(&needle) {
        let abs = search + pos;
        let mut i = abs + needle.len();
        while i < bytes.len()
            && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n' || bytes[i] == b'\r')
        {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b':' {
            search = abs + needle.len();
            continue;
        }
        i += 1;
        while i < bytes.len()
            && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n' || bytes[i] == b'\r')
        {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'"' {
            return None;
        }
        i += 1;
        let mut out = String::new();
        while i < bytes.len() {
            match bytes[i] {
                b'"' => return Some(out),
                b'\\' => {
                    i += 1;
                    if i >= bytes.len() {
                        return None;
                    }
                    match bytes[i] {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            if i + 4 >= bytes.len() {
                                return None;
                            }
                            let hex = params.get(i + 1..i + 5)?;
                            let code = u32::from_str_radix(hex, 16).ok()?;
                            out.push(char::from_u32(code)?);
                            i += 4;
                        }
                        _ => return None,
                    }
                    i += 1;
                }
                _ => {
                    let ch = params[i..].chars().next()?;
                    out.push(ch);
                    i += ch.len_utf8();
                }
            }
        }
        return None;
    }
    None
}

/// Extract a top-level boolean field (`true`/`false`); `None` when absent or
/// not a bare boolean.
fn extract_top_bool(params: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{key}\"");
    let pos = params.find(&needle)?;
    let after = &params[pos + needle.len()..];
    let colon = after.find(':')?;
    let value = after[colon + 1..].trim_start();
    if value.starts_with("true") {
        Some(true)
    } else if value.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Extract a top-level signed integer field; `None` when absent or malformed.
fn extract_top_int(params: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{key}\"");
    let pos = params.find(&needle)?;
    let after = &params[pos + needle.len()..];
    let colon = after.find(':')?;
    let mut value = after[colon + 1..].trim_start();
    if value.starts_with('"') || value.starts_with('{') || value.starts_with('[') {
        return None;
    }
    let negative = value.starts_with('-');
    if negative || value.starts_with('+') {
        value = &value[1..];
    }
    let mut len = 0usize;
    for b in value.bytes() {
        if b.is_ascii_digit() {
            len += 1;
        } else {
            break;
        }
    }
    if len == 0 || len > 10 {
        return None;
    }
    let digits = &value[..len];
    let parsed: i64 = digits.parse().ok()?;
    Some(if negative { -parsed } else { parsed })
}

/// Extract a top-level unsigned integer field; `None` when absent/malformed.
fn extract_top_uint(params: &str, key: &str) -> Option<u64> {
    let value = extract_top_int(params, key)?;
    u64::try_from(value).ok()
}

/// Terminal id accepting Amendment A1 camelCase (`terminalId`) and the
/// CTX-0171 snake_case (`terminal_id`) harness shape.
fn extract_terminal_id(params: &str) -> Option<String> {
    extract_top_string(params, "terminalId").or_else(|| extract_top_string(params, "terminal_id"))
}

/// Origin label accepting `originLabel` (Amendment A1) and `origin_label`.
fn extract_origin_label(params: &str) -> Option<String> {
    extract_top_string(params, "originLabel").or_else(|| extract_top_string(params, "origin_label"))
}

/// Locate the `events` array span `(inner_start, inner_end)` inside `params`.
fn find_events_array(params: &str) -> Option<(usize, usize)> {
    let needle = "\"events\"";
    let pos = params.find(needle)?;
    let after_key = &params[pos + needle.len()..];
    let colon_rel = after_key.find(':')?;
    let mut i = pos + needle.len() + colon_rel + 1;
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
                // Skip strings (escape-aware).
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

/// Split top-level `{...}` objects inside an array inner slice.
fn split_top_objects(inner: &str) -> Result<Vec<String>, ()> {
    let bytes = inner.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        if bytes[i] != b'{' {
            return Err(());
        }
        let start = i;
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
                        return Err(());
                    }
                }
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        if depth != 0 {
            return Err(());
        }
        out.push(inner[start..i].to_string());
        if out.len() > MAX_SYNTH_EVENTS_PER_CALL {
            return Err(());
        }
    }
    Ok(out)
}

/// Validated synthetic event (headless; the servo maps it to input encoding).
#[derive(Debug, Clone, PartialEq, Eq)]
enum SyntheticEvent {
    /// Key press/release.
    Key {
        /// Key name (bounded).
        key: String,
        /// Modifier summary (bounded, e.g. `ctrl+shift`).
        mods: String,
        /// Pressed (`true`) or released (`false`).
        pressed: bool,
    },
    /// Mouse button action at a cell.
    Mouse {
        /// `Left`, `Right`, or `Middle`.
        button: String,
        /// `pressed`, `released`, `click`, `drag`, or `move`.
        action: String,
        /// Cell column.
        col: u16,
        /// Cell row.
        row: u16,
    },
    /// Wheel scroll delta (cells).
    Wheel {
        /// Row delta (-64..=64).
        delta_rows: i32,
        /// Column delta (-64..=64).
        delta_cols: i32,
        /// Optional cell column.
        col: Option<u16>,
        /// Optional cell row.
        row: Option<u16>,
    },
    /// Paste-text (T-04 text-only parity).
    Paste {
        /// Pasted text (bounded, no NUL).
        text: String,
    },
}

/// Validate one event object; fail-closed with a bounded reason.
fn validate_synthetic_event(obj: &str) -> Result<SyntheticEvent, String> {
    let kind = extract_top_string(obj, "type")
        .ok_or_else(|| "event.type must be key|mouse|wheel|paste".to_string())?;
    match kind.as_str() {
        "key" => {
            let key = extract_top_string(obj, "key")
                .ok_or_else(|| "key event requires string key".to_string())?;
            if key.is_empty() || key.chars().count() > MAX_SYNTH_KEY_CHARS {
                return Err(format!("key must be 1..={MAX_SYNTH_KEY_CHARS} chars"));
            }
            if key.contains('\0') || key.bytes().any(|b| b < 0x20 && b != b'\t') {
                return Err("key must not contain control bytes".to_string());
            }
            let mods = extract_top_string(obj, "mods").unwrap_or_default();
            if mods.chars().count() > 16 {
                return Err("key mods must be <= 16 chars".to_string());
            }
            if !mods
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'_')
            {
                return Err("key mods must be alphanumeric with +-|_".to_string());
            }
            let pressed = extract_top_bool(obj, "pressed").unwrap_or(true);
            Ok(SyntheticEvent::Key { key, mods, pressed })
        }
        "mouse" => {
            let button = extract_top_string(obj, "button")
                .ok_or_else(|| "mouse event requires button".to_string())?;
            if !matches!(button.as_str(), "Left" | "Right" | "Middle") {
                return Err("mouse button must be Left|Right|Middle".to_string());
            }
            let action = extract_top_string(obj, "action").unwrap_or_else(|| "click".to_string());
            if !matches!(
                action.as_str(),
                "pressed" | "released" | "click" | "drag" | "move"
            ) {
                return Err("mouse action must be pressed|released|click|drag|move".to_string());
            }
            let col = extract_top_uint(obj, "col")
                .ok_or_else(|| "mouse event requires col".to_string())?;
            let row = extract_top_uint(obj, "row")
                .ok_or_else(|| "mouse event requires row".to_string())?;
            if col > u64::from(MAX_SYNTH_CELL) || row > u64::from(MAX_SYNTH_CELL) {
                return Err(format!("mouse col/row must be 0..={MAX_SYNTH_CELL}"));
            }
            Ok(SyntheticEvent::Mouse {
                button,
                action,
                col: col as u16,
                row: row as u16,
            })
        }
        "wheel" => {
            let delta_rows = extract_top_int(obj, "deltaRows")
                .or_else(|| extract_top_int(obj, "delta_rows"))
                .ok_or_else(|| "wheel event requires deltaRows".to_string())?;
            let delta_cols = extract_top_int(obj, "deltaCols")
                .or_else(|| extract_top_int(obj, "delta_cols"))
                .unwrap_or(0);
            if delta_rows < i64::from(-MAX_SYNTH_WHEEL_DELTA)
                || delta_rows > i64::from(MAX_SYNTH_WHEEL_DELTA)
                || delta_cols < i64::from(-MAX_SYNTH_WHEEL_DELTA)
                || delta_cols > i64::from(MAX_SYNTH_WHEEL_DELTA)
            {
                return Err(format!(
                    "wheel delta must be -{MAX_SYNTH_WHEEL_DELTA}..={MAX_SYNTH_WHEEL_DELTA}"
                ));
            }
            if delta_rows == 0 && delta_cols == 0 {
                return Err("wheel delta must be non-zero".to_string());
            }
            let col = match extract_top_uint(obj, "col") {
                Some(v) => {
                    if v > u64::from(MAX_SYNTH_CELL) {
                        return Err(format!("wheel col must be 0..={MAX_SYNTH_CELL}"));
                    }
                    Some(v as u16)
                }
                None => None,
            };
            let row = match extract_top_uint(obj, "row") {
                Some(v) => {
                    if v > u64::from(MAX_SYNTH_CELL) {
                        return Err(format!("wheel row must be 0..={MAX_SYNTH_CELL}"));
                    }
                    Some(v as u16)
                }
                None => None,
            };
            Ok(SyntheticEvent::Wheel {
                delta_rows: delta_rows as i32,
                delta_cols: delta_cols as i32,
                col,
                row,
            })
        }
        "paste" => {
            let text = extract_top_string(obj, "text")
                .ok_or_else(|| "paste event requires string text".to_string())?;
            if text.is_empty() || text.len() > MAX_SYNTH_PASTE_BYTES {
                return Err(format!(
                    "paste text must be 1..={MAX_SYNTH_PASTE_BYTES} bytes"
                ));
            }
            if text.contains('\0') {
                return Err("paste text must not contain NUL".to_string());
            }
            Ok(SyntheticEvent::Paste { text })
        }
        other => Err(format!(
            "event.type must be key|mouse|wheel|paste, got {}",
            echo_snippet(other)
        )),
    }
}

/// Whether a frame line carries sensitive content (P0-AC-026 parity: secrets,
/// clipboard bytes, environment bytes never appear in default outputs).
fn is_sensitive_frame_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
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

/// Redact one frame line (whole-line replacement, fail-closed minimizing).
fn redact_frame_line(line: &str) -> String {
    if is_sensitive_frame_line(line) {
        REDACTED_MARKER.to_string()
    } else {
        line.to_string()
    }
}

/// `bitty.debug/synthesizeInput`: bearer-scoped input synthesis.
///
/// Params (object, `<= 32 KiB`): `{ terminalId|terminal_id: "t:N", bearer:
/// "<token>", originLabel|origin_label: "...", events: [...] }` with 1..=64
/// events of type key/mouse/wheel/paste. Requires `debug.control` +
/// `terminal.input` plus a live `synthesize` bearer for the addressed
/// terminal/session. Success publishes indelible `[synthetic]` markers into
/// the input ring (harness/user distinguishable) and returns a receipt with
/// `accepted`, `rejected: 0`, and the new `syntheticSeq`.
pub(super) fn handle_synthesize_input(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    use crate::scope::Scope::{DebugControl, TerminalInput};
    let params = request.params_raw.as_deref().ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "synthesizeInput requires params".to_string(),
        )
    })?;
    let terminal_id = extract_terminal_id(params).ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "synthesizeInput requires terminalId \"t:N\"".to_string(),
        )
    })?;
    if crate::ctl::parse_terminal_id(&terminal_id).is_err() {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            "terminalId must match ^t:[0-9]+$ (no wildcards)".to_string(),
        ));
    }
    let origin = extract_origin_label(params).ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "synthesizeInput requires originLabel".to_string(),
        )
    })?;
    if origin.is_empty() || origin.chars().count() > MAX_ORIGIN_LABEL_CHARS {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            format!("originLabel must be 1..={MAX_ORIGIN_LABEL_CHARS} chars"),
        ));
    }
    if origin.contains('\0') || origin.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            "originLabel must not contain control bytes".to_string(),
        ));
    }
    let bearer = extract_top_string(params, "bearer");
    let (inner_start, inner_end) = find_events_array(params).ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "synthesizeInput requires events array".to_string(),
        )
    })?;
    let inner = &params[inner_start..inner_end];
    let objects = split_top_objects(inner).map_err(|()| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "events must be objects".to_string(),
        )
    })?;
    if objects.is_empty() || objects.len() > MAX_SYNTH_EVENTS_PER_CALL {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            format!("events must be 1..={MAX_SYNTH_EVENTS_PER_CALL}"),
        ));
    }
    // Validate every event before touching any state (transactional: no
    // partial publish on a malformed call).
    let mut validated: Vec<SyntheticEvent> = Vec::with_capacity(objects.len());
    for obj in &objects {
        match validate_synthetic_event(obj) {
            Ok(event) => validated.push(event),
            Err(reason) => {
                return Err(HandlerError::new("usage", "InvalidParams", reason));
            }
        }
    }
    // Authorize (scope intersection + bearer binding + rate ceiling) before
    // any observable effect.
    let authorization = context.current_authorization().map_err(|_| {
        HandlerError::new(
            "scope",
            "Unauthenticated",
            "connection authority is unavailable".into(),
        )
    })?;
    authorize_automation(
        &authorization,
        &[DebugControl, TerminalInput],
        bearer.as_deref(),
        &terminal_id,
        AutomationFamily::Synthesize,
        context.uptime_ms,
    )?;
    // Publish indelible synthetic markers into the input ring (drop-oldest,
    // bounded). A poisoned mutex fails closed without a receipt.
    let accepted = validated.len();
    let synth_seq = {
        let mut store = automation_store().lock().map_err(|_| {
            HandlerError::new(
                "transport",
                "Unavailable",
                "automation store unavailable".to_string(),
            )
        })?;
        store.synth_seq = store.synth_seq.saturating_add(accepted as u64);
        store.synth_seq
    };
    {
        let mut ring = live_input_store().lock().map_err(|_| {
            HandlerError::new(
                "transport",
                "Unavailable",
                "introspection store unavailable".to_string(),
            )
        })?;
        for event in &validated {
            let (kind, label) = match event {
                SyntheticEvent::Key { key, mods, pressed } => (
                    "key".to_string(),
                    format!("[synthetic:{origin}] key:{key} mods:{mods} pressed:{pressed}"),
                ),
                SyntheticEvent::Mouse {
                    button,
                    action,
                    col,
                    row,
                } => (
                    "mouse".to_string(),
                    format!("[synthetic:{origin}] mouse:{button} {action} col={col} row={row}"),
                ),
                SyntheticEvent::Wheel {
                    delta_rows,
                    delta_cols,
                    col,
                    row,
                } => (
                    "wheel".to_string(),
                    format!(
                        "[synthetic:{origin}] wheel rows={delta_rows} cols={delta_cols} col={} row={}",
                        col.map_or(String::from("-"), |c| c.to_string()),
                        row.map_or(String::from("-"), |r| r.to_string()),
                    ),
                ),
                SyntheticEvent::Paste { text } => {
                    let preview: String = text.chars().take(32).collect();
                    (
                        "paste".to_string(),
                        format!("[synthetic:{origin}] paste:{preview}"),
                    )
                }
            };
            ring.push(InputEventPublish {
                seq: synth_seq,
                kind: truncate_chars(&kind, 16),
                label: truncate_chars(&label, MAX_INPUT_LABEL_CHARS),
                shift: false,
                control: false,
                alt: false,
                button: None,
                col: None,
                row: None,
                pressed: None,
            });
            while ring.len() > MAX_INPUT_RING {
                ring.remove(0);
            }
        }
    }
    let mut out = String::with_capacity(256);
    out.push_str("{\"version\":\"");
    out.push_str(DEVTOOLS_PROTOCOL_VERSION);
    out.push_str("\",\"receipt\":\"synthesize\",\"terminalId\":\"");
    json_escape_into(&mut out, &terminal_id);
    out.push_str("\",\"accepted\":");
    out.push_str(&accepted.to_string());
    out.push_str(",\"rejected\":0,\"syntheticSeq\":");
    out.push_str(&synth_seq.to_string());
    out.push_str(",\"originLabel\":\"");
    json_escape_into(&mut out, &origin);
    out.push_str("\",\"synthetic\":true}");
    Ok(out)
}

/// `bitty.debug/captureFrame`: bearer-scoped redacted frame capture.
///
/// Params (object, `<= 32 KiB`): `{ terminalId|terminal_id: "t:N", bearer:
/// "<token>", format: "semantic"|"pixels" (default semantic),
/// explicitOptIn: true (required for pixels), rows/cols viewport caps }.
/// Requires `debug.trace` + `terminal.inspect` plus a live `capture` bearer.
/// `semantic` returns redacted grid text; `pixels` returns a masked record
/// with zero text (audited with caller identity). Every response carries
/// `"trust":"untrusted-observation"` (T-10 parity).
pub(super) fn handle_capture_frame(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    use crate::scope::Scope::{DebugTrace, TerminalInspect};
    let params = request.params_raw.as_deref().ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "captureFrame requires params".to_string(),
        )
    })?;
    let terminal_id = extract_terminal_id(params).ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "captureFrame requires terminalId \"t:N\"".to_string(),
        )
    })?;
    if crate::ctl::parse_terminal_id(&terminal_id).is_err() {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            "terminalId must match ^t:[0-9]+$ (no wildcards)".to_string(),
        ));
    }
    let bearer = extract_top_string(params, "bearer");
    let format = extract_top_string(params, "format").unwrap_or_else(|| "semantic".to_string());
    if format != "semantic" && format != "pixels" {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            "format must be semantic|pixels".to_string(),
        ));
    }
    if format == "pixels" && extract_top_bool(params, "explicitOptIn") != Some(true) {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            "pixels capture requires explicitOptIn true".to_string(),
        ));
    }
    let authorization = context.current_authorization().map_err(|_| {
        HandlerError::new(
            "scope",
            "Unauthenticated",
            "connection authority is unavailable".into(),
        )
    })?;
    authorize_automation(
        &authorization,
        &[DebugTrace, TerminalInspect],
        bearer.as_deref(),
        &terminal_id,
        AutomationFamily::Capture,
        context.uptime_ms,
    )?;
    // Viewport caps reuse the introspection bounds (fail-closed).
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
    let grid_cols = if guard.cols == 0 {
        context.server.cols
    } else {
        guard.cols
    };
    let grid_rows = if guard.rows == 0 {
        context.server.rows
    } else {
        guard.rows
    };
    let frame_seq = guard.generation;
    // Audit every capture with caller identity (pixels mandatory, semantic
    // uniform). Bounded drop-oldest; poison fails closed without a record.
    {
        if let Ok(mut store) = automation_store().lock() {
            store.audit.push(FrameAuditEntry {
                session_id: context.session_id().to_string(),
                terminal_id: terminal_id.clone(),
                format: format.clone(),
                now_ms: context.uptime_ms,
                frame_seq,
                digest_hex: String::new(),
            });
            while store.audit.len() > MAX_AUTOMATION_BEARERS {
                store.audit.remove(0);
            }
        }
    }
    if format == "pixels" {
        let mut out = String::with_capacity(256);
        out.push_str("{\"version\":\"");
        out.push_str(DEVTOOLS_PROTOCOL_VERSION);
        out.push_str("\",\"snapshot\":\"frame\",\"format\":\"pixels\",\"terminalId\":\"");
        json_escape_into(&mut out, &terminal_id);
        out.push_str("\",\"masked\":true,\"cols\":");
        out.push_str(&grid_cols.to_string());
        out.push_str(",\"rows\":");
        out.push_str(&grid_rows.to_string());
        out.push_str(",\"frameSeq\":");
        out.push_str(&frame_seq.to_string());
        out.push_str(",\"trust\":\"untrusted-observation\",\"caller\":\"");
        json_escape_into(&mut out, context.session_id());
        out.push_str("\",\"audited\":true}");
        return Ok(out);
    }
    let take = rows.min(guard.lines.len());
    let mut out = String::with_capacity(1024.min(MAX_INSPECT_JSON_BYTES));
    out.push_str("{\"version\":\"");
    out.push_str(DEVTOOLS_PROTOCOL_VERSION);
    out.push_str("\",\"snapshot\":\"frame\",\"format\":\"semantic\",\"terminalId\":\"");
    json_escape_into(&mut out, &terminal_id);
    out.push_str("\",\"lines\":[");
    for (i, line) in guard.lines.iter().take(take).enumerate() {
        if i > 0 {
            out.push(',');
        }
        let cut = truncate_line(line, cols);
        let redacted = redact_frame_line(&cut);
        out.push('"');
        json_escape_into(&mut out, &redacted);
        out.push('"');
        if out.len() > MAX_INSPECT_JSON_BYTES {
            return Err(HandlerError::new(
                "transport",
                "PayloadTooLarge",
                "frame snapshot exceeds response bound".to_string(),
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
    out.push_str(&grid_cols.to_string());
    out.push_str(",\"rows\":");
    out.push_str(&grid_rows.to_string());
    out.push_str(",\"frameSeq\":");
    out.push_str(&frame_seq.to_string());
    out.push_str(",\"trust\":\"untrusted-observation\"}");
    if out.len() > MAX_INSPECT_JSON_BYTES {
        return Err(HandlerError::new(
            "transport",
            "PayloadTooLarge",
            "frame snapshot exceeds response bound".to_string(),
        ));
    }
    Ok(out)
}

/// Append one `digest` audit entry to the bounded log (64, drop-oldest).
///
/// Poisoned store fails closed without a record (existing parity). Called
/// for every attributable `frameHash` call — granted AND denied — so the
/// digest oracle leaves a per-call trace with caller identity, frame
/// sequence, and the served digest (uninvertible, safe to log).
fn audit_digest_attempt(
    session_id: &str,
    terminal_id: &str,
    now_ms: u64,
    frame_seq: u64,
    digest_hex: &str,
) {
    if let Ok(mut store) = automation_store().lock() {
        store.audit.push(FrameAuditEntry {
            session_id: session_id.to_string(),
            terminal_id: terminal_id.to_string(),
            format: String::from("digest"),
            now_ms,
            frame_seq,
            digest_hex: digest_hex.to_string(),
        });
        while store.audit.len() > MAX_AUTOMATION_BEARERS {
            store.audit.remove(0);
        }
    }
}

/// `bitty.debug/frameHash`: bearer-scoped lossless frame digest (CTX-0244).
///
/// Params (object, `<= 32 KiB`): `{ terminalId|terminal_id: "t:N", bearer:
/// "<token>" }`. Requires `debug.trace` + `terminal.inspect` plus a live
/// `frame-digest` bearer for the addressed terminal/session, a
/// local-attested transport (the bound peer marker, P0-AC-021 parity), and a
/// published headless frame. Returns the SHA-256 hex digest
/// over `canonical_frame_bytes(width_px, height_px, frame_seq, rgba)` — 32
/// bytes that prove frame equality with zero pixel bytes on the wire —
/// plus the bound geometry and `"trust":"untrusted-observation"` (T-10
/// parity). No `explicitOptIn`: nothing human-readable is returned, grant
/// possession IS the opt-in.
///
/// Fail-closed ordering (no oracle, zero partial state): params shape, then
/// local attestation, then scope+bearer+expiry+rate (all `ScopeDenied`),
/// then frame availability (`Unavailable` — never a hash of nothing, which
/// would read as false equality). A `Capture` bearer MUST NOT authorize
/// here (family-mismatch `ScopeDenied`, never widened).
pub(super) fn handle_frame_hash(
    context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    use crate::frame_digest::{FRAME_DIGEST_ALGO, frame_digest_hex};
    use crate::scope::Scope::{DebugTrace, TerminalInspect};
    let params = request.params_raw.as_deref().ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "frameHash requires params".to_string(),
        )
    })?;
    let terminal_id = extract_terminal_id(params).ok_or_else(|| {
        HandlerError::new(
            "usage",
            "InvalidParams",
            "frameHash requires terminalId \"t:N\"".to_string(),
        )
    })?;
    if crate::ctl::parse_terminal_id(&terminal_id).is_err() {
        return Err(HandlerError::new(
            "usage",
            "InvalidParams",
            "terminalId must match ^t:[0-9]+$ (no wildcards)".to_string(),
        ));
    }
    // Local-only transport, revalidated per call before any digest work:
    // the connected-stream binding or same-process dispatch must have marked
    // this context. Never over TCP (no listener exists) and never for a
    // foreign user.
    if !context.is_local_attested() {
        audit_digest_attempt(context.session_id(), &terminal_id, context.uptime_ms, 0, "");
        return Err(HandlerError::new(
            "scope",
            "ScopeDenied",
            "permission denied: frameHash requires a local attested transport".to_string(),
        ));
    }
    let bearer = extract_top_string(params, "bearer");
    let authorization = context.current_authorization().map_err(|_| {
        HandlerError::new(
            "scope",
            "Unauthenticated",
            "connection authority is unavailable".into(),
        )
    });
    if let Err(err) = authorization.and_then(|authorization| {
        authorize_automation(
            &authorization,
            &[DebugTrace, TerminalInspect],
            bearer.as_deref(),
            &terminal_id,
            AutomationFamily::FrameDigest,
            context.uptime_ms,
        )
    }) {
        audit_digest_attempt(context.session_id(), &terminal_id, context.uptime_ms, 0, "");
        return Err(err);
    }
    // Snapshot the published present source (clone under the lock, hash
    // after release). An empty/unpresented surface is `Unavailable`, which
    // reads as indeterminate — never as false equality.
    let (width_px, height_px, frame_seq, rgba) = {
        let guard = live_rgba_store().lock().map_err(|_| {
            HandlerError::new(
                "transport",
                "Unavailable",
                "frame store unavailable".to_string(),
            )
        })?;
        if guard.rgba.is_empty() {
            audit_digest_attempt(context.session_id(), &terminal_id, context.uptime_ms, 0, "");
            return Err(HandlerError::new(
                "transport",
                "Unavailable",
                "no presented frame to digest".to_string(),
            ));
        }
        (
            guard.width_px,
            guard.height_px,
            guard.frame_seq,
            guard.rgba.clone(),
        )
    };
    let digest = frame_digest_hex(width_px, height_px, frame_seq, &rgba);
    audit_digest_attempt(
        context.session_id(),
        &terminal_id,
        context.uptime_ms,
        frame_seq,
        &digest,
    );
    // Informational grid geometry (captureFrame parity: grid store, server
    // fallback on poison — the digest itself already binds pixel geometry
    // plus frameSeq, so no security decision depends on these numbers).
    let (grid_cols, grid_rows) =
        live_grid_store()
            .lock()
            .map_or((context.server.cols, context.server.rows), |guard| {
                (
                    if guard.cols == 0 {
                        context.server.cols
                    } else {
                        guard.cols
                    },
                    if guard.rows == 0 {
                        context.server.rows
                    } else {
                        guard.rows
                    },
                )
            });
    let mut out = String::with_capacity(256);
    out.push_str("{\"version\":\"");
    out.push_str(DEVTOOLS_PROTOCOL_VERSION);
    out.push_str("\",\"snapshot\":\"frameHash\",\"terminalId\":\"");
    json_escape_into(&mut out, &terminal_id);
    out.push_str("\",\"cols\":");
    out.push_str(&grid_cols.to_string());
    out.push_str(",\"rows\":");
    out.push_str(&grid_rows.to_string());
    out.push_str(",\"widthPx\":");
    out.push_str(&width_px.to_string());
    out.push_str(",\"heightPx\":");
    out.push_str(&height_px.to_string());
    out.push_str(",\"frameSeq\":");
    out.push_str(&frame_seq.to_string());
    out.push_str(",\"algo\":\"");
    out.push_str(FRAME_DIGEST_ALGO);
    out.push_str("\",\"digest\":\"");
    out.push_str(&digest);
    out.push_str("\",\"trust\":\"untrusted-observation\"}");
    Ok(out)
}
