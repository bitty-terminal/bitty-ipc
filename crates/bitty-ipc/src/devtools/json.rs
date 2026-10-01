use super::*;

use crate::error::IpcError;
use crate::wire::{MAX_JSON_DEPTH, validate_json_depth};
use std::collections::BTreeMap;

// ── request parsing ─────────────────────────────────────────────────────────

/// Parsed DevTools request: the only fields the dispatcher needs.
///
/// `id_raw` is the verbatim JSON number token so responses echo the exact id
/// the client sent (no float formatting drift). `params_raw` carries the raw
/// `params` object bytes when present (bounded to [`MAX_PARAMS_BYTES`]) so
/// CTX-0159 handlers can parse method-specific params (`rows`/`cols`/`limit`)
/// without a new dependency; v1 handlers (`ping`, `getSnapshot`) ignore it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevtoolsRequest {
    /// Verbatim numeric id token (e.g. `"1"`).
    pub id_raw: String,
    /// Method such as `"bitty.debug/ping"`.
    pub method: String,
    /// Whether the envelope carried `jsonrpc: "2.0"` (`protocol.ts` shape).
    pub has_jsonrpc: bool,
    /// Raw `params` object bytes when the envelope carried one.
    pub params_raw: Option<String>,
}

/// A parse failure that still maps to an error response.
///
/// Carries the best-known id so the peer can correlate the rejection;
/// `None` (rendered as `0`) when no usable id was recovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFault {
    /// Verbatim id token when recovered.
    pub id_raw: Option<String>,
    /// DevTools error category (`protocol.ts` `ErrorCategory`).
    pub category: &'static str,
    /// Stable error code.
    pub code: &'static str,
    /// Bounded human-readable reason.
    pub message: String,
}

impl RequestFault {
    /// Build a fault, truncating the message to the echo bound.
    fn new(
        id_raw: Option<String>,
        category: &'static str,
        code: &'static str,
        message: String,
    ) -> Self {
        Self {
            id_raw,
            category,
            code,
            message: truncate_chars(&message, MAX_ERROR_MESSAGE_CHARS),
        }
    }
}

/// Truncate to at most `max` characters (char-boundary safe).
pub(super) fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let truncated: String = s.chars().take(max).collect();
    format!("{truncated}...")
}

/// Truncate a request-echo snippet for error messages.
pub(super) fn echo_snippet(s: &str) -> String {
    truncate_chars(s, MAX_ECHO_CHARS)
}

/// Unescape a JSON string body (without surrounding quotes).
///
/// Supports the standard escapes plus `\uXXXX` BMP escapes. Surrogate halves
/// are rejected: method/version envelopes never need them.
fn unescape_json_string(body: &str) -> Result<String, ()> {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let esc = chars.next().ok_or(())?;
        match esc {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            '/' => out.push('/'),
            'b' => out.push('\u{0008}'),
            'f' => out.push('\u{000C}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'u' => {
                let mut code: u32 = 0;
                for _ in 0..4 {
                    let h = chars.next().ok_or(())?;
                    let digit = h.to_digit(16).ok_or(())?;
                    code = code * 16 + digit;
                }
                let decoded = char::from_u32(code).ok_or(())?;
                if (0xD800..0xE000).contains(&code) {
                    return Err(());
                }
                out.push(decoded);
            }
            _ => return Err(()),
        }
    }
    Ok(out)
}

/// Top-level JSON key spans collected in one pass (key -> raw value span).
struct EnvelopeKeys {
    /// Raw value spans by unescaped key name.
    values: BTreeMap<String, (usize, usize)>,
    /// Best-known id token for fault correlation, when recovered.
    id_raw: Option<String>,
}

/// Scan one JSON string starting at `bytes[i]` (where `bytes[i] == b'"'`).
/// Returns the inner byte range `(content_start, content_end)` and the index
/// just past the closing quote.
fn scan_string(bytes: &[u8], i: usize) -> Result<(usize, usize, usize), ()> {
    let mut j = i + 1;
    let mut escape = false;
    while j < bytes.len() {
        let b = bytes[j];
        if escape {
            escape = false;
        } else if b == b'\\' {
            escape = true;
        } else if b == b'"' {
            return Ok((i + 1, j, j + 1));
        } else if b < 0x20 {
            return Err(());
        }
        j += 1;
    }
    Err(())
}

/// Skip a balanced JSON value starting at `i`; return the index just past it.
fn skip_value(bytes: &[u8], mut i: usize) -> Result<usize, ()> {
    if i >= bytes.len() {
        return Err(());
    }
    match bytes[i] {
        b'"' => {
            let (_, _, end) = scan_string(bytes, i)?;
            Ok(end)
        }
        b'{' | b'[' => {
            let open = bytes[i];
            let close = if open == b'{' { b'}' } else { b']' };
            i += 1;
            let mut depth = 1usize;
            while i < bytes.len() {
                match bytes[i] {
                    b'"' => {
                        let (_, _, end) = scan_string(bytes, i)?;
                        i = end;
                        continue;
                    }
                    b if b == open => depth += 1,
                    b if b == close => {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(i + 1);
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            Err(())
        }
        _ => {
            // Number, true, false, null: run to the next delimiter.
            let start = i;
            while i < bytes.len() && !matches!(bytes[i], b',' | b'}' | b']') {
                i += 1;
            }
            if i == start {
                return Err(());
            }
            Ok(i)
        }
    }
}

/// Skip ASCII whitespace.
fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

/// Collect top-level key/value spans of a JSON object envelope.
fn collect_envelope_keys(text: &str) -> Result<EnvelopeKeys, ()> {
    let bytes = text.as_bytes();
    let mut i = skip_ws(bytes, 0);
    if bytes.get(i) != Some(&b'{') {
        return Err(());
    }
    i += 1;
    let mut values: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    loop {
        i = skip_ws(bytes, i);
        if i >= bytes.len() {
            return Err(());
        }
        if bytes[i] == b'}' {
            i += 1;
            i = skip_ws(bytes, i);
            if i != bytes.len() {
                return Err(());
            }
            break;
        }
        if bytes[i] != b'"' {
            return Err(());
        }
        let (ks, ke, after_key) = scan_string(bytes, i)?;
        let key = unescape_json_string(&text[ks..ke]).map_err(|_| ())?;
        i = skip_ws(bytes, after_key);
        if bytes.get(i) != Some(&b':') {
            return Err(());
        }
        i = skip_ws(bytes, i + 1);
        let value_start = i;
        i = skip_value(bytes, i)?;
        values.insert(key, (value_start, i));
        i = skip_ws(bytes, i);
        if i >= bytes.len() {
            return Err(());
        }
        if bytes[i] == b',' {
            i += 1;
            continue;
        }
        if bytes[i] == b'}' {
            continue;
        }
        return Err(());
    }
    Ok(EnvelopeKeys {
        values,
        id_raw: None,
    })
}

/// Extract a required string field by key.
fn required_string_field(
    text: &str,
    keys: &EnvelopeKeys,
    name: &str,
    missing_code: &'static str,
) -> Result<String, RequestFault> {
    let fault_id = keys.id_raw.clone();
    let (start, end) = keys.values.get(name).ok_or_else(|| {
        RequestFault::new(
            fault_id.clone(),
            "usage",
            missing_code,
            format!("envelope missing '{name}'"),
        )
    })?;
    let raw = text[*start..*end].trim().to_string();
    if !raw.starts_with('"') {
        return Err(RequestFault::new(
            fault_id,
            "usage",
            missing_code,
            format!("envelope '{name}' must be a string"),
        ));
    }
    let body = raw[1..raw.len().saturating_sub(1)].to_string();
    unescape_json_string(&body).map_err(|_| {
        RequestFault::new(
            fault_id,
            "usage",
            "InvalidJson",
            format!("envelope '{name}' has invalid string escapes"),
        )
    })
}

/// Validate a JSON number token shape (no float parsing, echo verbatim).
fn is_valid_number_token(token: &str) -> bool {
    if token.is_empty() || token.len() > MAX_ID_TOKEN_BYTES {
        return false;
    }
    let bytes = token.as_bytes();
    let mut i = 0;
    if bytes[i] == b'-' {
        i += 1;
        if i >= bytes.len() {
            return false;
        }
    }
    if bytes[i] == b'0' {
        i += 1;
    } else if bytes[i].is_ascii_digit() && bytes[i] != b'0' {
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
    } else {
        return false;
    }
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        let frac_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == frac_start {
            return false;
        }
    }
    if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
        i += 1;
        if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
            i += 1;
        }
        let exp_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == exp_start {
            return false;
        }
    }
    i == bytes.len()
}

/// Parse and validate a DevTools request envelope.
///
/// Accepts both sibling shapes (`transport.ts` without `jsonrpc`, and
/// `protocol.ts` with `jsonrpc: "2.0"`). Rejects ambient-authority fields,
/// wrong versions, bad methods, and non-numeric ids as [`RequestFault`]
/// values that the caller renders as error responses (never panics).
///
/// # Errors
///
/// Returns a [`RequestFault`] (renderable as an error response) for every
/// malformed or unauthorized envelope; the fault carries the best-known id.
pub fn parse_request(payload: &[u8]) -> Result<DevtoolsRequest, RequestFault> {
    // The envelope bound is the 1 MiB logical-request limit: a request above
    // one frame arrives reassembled from continuation fragments (Amendment A4,
    // #1482). Per-method `params` caps below still apply unchanged.
    if payload.len() > MAX_LOGICAL_REQUEST_BYTES {
        return Err(RequestFault::new(
            None,
            "transport",
            "FrameTooLarge",
            format!(
                "payload {} exceeds limit {MAX_LOGICAL_REQUEST_BYTES}",
                payload.len()
            ),
        ));
    }
    let text = std::str::from_utf8(payload).map_err(|_| {
        RequestFault::new(
            None,
            "transport",
            "InvalidJson",
            "envelope must be utf-8 json".to_string(),
        )
    })?;
    if let Err(ipc_err) = validate_json_depth(payload, MAX_JSON_DEPTH) {
        let (category, code) = match &ipc_err {
            IpcError::PayloadTooLarge { .. } => ("transport", "PayloadTooLarge"),
            _ => ("transport", "InvalidJson"),
        };
        return Err(RequestFault::new(
            None,
            category,
            code,
            format!("envelope rejected: {ipc_err}"),
        ));
    }
    let mut keys = collect_envelope_keys(text).map_err(|_| {
        RequestFault::new(
            None,
            "usage",
            "InvalidRequest",
            "envelope must be a single JSON object".to_string(),
        )
    })?;

    // Recover the id early so later faults correlate.
    if let Some((start, end)) = keys.values.get("id") {
        let token = text[*start..*end].trim().to_string();
        if is_valid_number_token(&token) {
            keys.id_raw = Some(token);
        }
    }

    // No ambient authority travels in the envelope: a client that inserts
    // scope/auth/role cannot escalate; reject explicitly and countably.
    for forbidden in ["auth", "scope", "role"] {
        if keys.values.contains_key(forbidden) {
            return Err(RequestFault::new(
                keys.id_raw.clone(),
                "usage",
                "ForbiddenField",
                format!("forbidden ambient authority field '{forbidden}' in envelope"),
            ));
        }
    }

    let version = required_string_field(text, &keys, "version", "MissingVersion")?;
    if version != DEVTOOLS_PROTOCOL_VERSION {
        return Err(RequestFault::new(
            keys.id_raw.clone(),
            "usage",
            "UnsupportedVersion",
            format!(
                "unsupported version {}, expected {DEVTOOLS_PROTOCOL_VERSION}",
                echo_snippet(&version)
            ),
        ));
    }

    let method = required_string_field(text, &keys, "method", "InvalidRequest")?;
    validate_method(&method).map_err(|reason| {
        RequestFault::new(keys.id_raw.clone(), "usage", "InvalidMethod", reason)
    })?;

    let mut has_jsonrpc = false;
    if keys.values.contains_key("jsonrpc") {
        let tag = required_string_field(text, &keys, "jsonrpc", "InvalidJsonRpc")?;
        if tag != "2.0" {
            return Err(RequestFault::new(
                keys.id_raw.clone(),
                "usage",
                "InvalidJsonRpc",
                format!("jsonrpc must be 2.0, got {}", echo_snippet(&tag)),
            ));
        }
        has_jsonrpc = true;
    }

    let id_raw = keys.id_raw.clone().ok_or_else(|| {
        RequestFault::new(
            None,
            "usage",
            "MissingId",
            "envelope id must be a JSON number".to_string(),
        )
    })?;

    // Capture the raw `params` object when present so method handlers can
    // parse per-method scopes (`rows`/`cols`/`limit`, automation payloads)
    // without a JSON dependency. The slice is bounded before retention:
    // oversize params fail closed here rather than reaching dispatch.
    // Automation methods (`synthesizeInput`, `captureFrame`, `frameHash`)
    // carry up to 64 events and allow 32 KiB; all other methods stay at 4 KiB.
    let params_raw = match keys.values.get("params") {
        None => None,
        Some((start, end)) => {
            let raw = text[*start..*end].trim().to_string();
            let cap = if method == METHOD_SYNTHESIZE_INPUT
                || method == METHOD_CAPTURE_FRAME
                || method == METHOD_FRAME_HASH
            {
                MAX_AUTOMATION_PARAMS_BYTES
            } else {
                MAX_PARAMS_BYTES
            };
            if raw.len() > cap {
                return Err(RequestFault::new(
                    keys.id_raw.clone(),
                    "transport",
                    "PayloadTooLarge",
                    format!("params {} exceeds limit {cap}", raw.len()),
                ));
            }
            // `params` must be an object or null; arrays and scalars are
            // rejected fail-closed (per-method handlers expect an object).
            if !(raw.starts_with('{') || raw == "null") {
                return Err(RequestFault::new(
                    keys.id_raw.clone(),
                    "usage",
                    "InvalidParams",
                    "envelope params must be an object".to_string(),
                ));
            }
            if raw == "null" { None } else { Some(raw) }
        }
    };

    Ok(DevtoolsRequest {
        id_raw,
        method,
        has_jsonrpc,
        params_raw,
    })
}

/// Validate a `bitty.debug/*` method name (bounded, ASCII, prefixed).
pub(super) fn validate_method(method: &str) -> Result<(), String> {
    if method.len() > MAX_DEVTOOLS_METHOD_BYTES {
        return Err(format!(
            "method too long ({} > {MAX_DEVTOOLS_METHOD_BYTES})",
            method.len()
        ));
    }
    let Some(suffix) = method.strip_prefix(DEVTOOLS_METHOD_PREFIX) else {
        return Err(format!(
            "method must start with {DEVTOOLS_METHOD_PREFIX}, got {}",
            echo_snippet(method)
        ));
    };
    if suffix.is_empty() || suffix.len() > MAX_METHOD_SUFFIX_LEN {
        return Err(format!(
            "method suffix must be 1..={MAX_METHOD_SUFFIX_LEN}, got {}",
            echo_snippet(suffix)
        ));
    }
    let ok = suffix
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !ok {
        return Err(format!(
            "method suffix must be ascii alphanumeric, got {}",
            echo_snippet(suffix)
        ));
    }
    Ok(())
}
