//! Versioned wire envelope (RFC OQ-018, wire protocol v1).
//!
//! The accepted wire envelope is versioned and self-describing, intentionally
//! small and auditable:
//!
//! ```jsonc
//! // Request (client -> runtime)
//! {
//!   "v": 1,                         // wire version, u16
//!   "id": "01H...ULID",             // correlation id, bounded 64 bytes
//!   "method": "terminal.text",      // bounded 128 bytes, see validation
//!   "params": { "terminal_id": "t:4" }, // bounded JSON value
//!   // no "auth" field: identity comes from the transport, not the payload
//! }
//! // Response (runtime -> client)
//! {
//!   "v": 1,
//!   "id": "01H...ULID",
//!   "ok": true,
//!   "result": { "text": "..." },    // bounded, or streamed via chunks
//!   // or
//!   "ok": false,
//!   "error": { "class": "Denied", "code": "ScopeViolation", "message": "..." }
//! }
//! // Streaming chunk (for snapshot/streaming reads, see RC-10)
//! {
//!   "v": 1,
//!   "id": "01H...ULID",
//!   "chunk": { "seq": 0, "total": 3, "bytes": "<base64, <=256 KiB decoded>" },
//!   "final": false
//! }
//! ```
//!
//! Rules (per RFC):
//! - `v` must be a supported version. A client offers the versions it speaks
//!   and [`negotiate_wire_version`] selects the highest mutual one (v1 today);
//!   versions outside [`SUPPORTED_WIRE_VERSIONS`] are rejected whole.
//! - `method` validation: non-empty, `<= 128` bytes, no control bytes
//!   (`0x00-0x1F`, `0x7F`), no interior whitespace, segments match
//!   `^[a-z][a-z0-9_]*$` separated by `.`.
//! - Parameter and result JSON values are bounded: the decoded frame is already
//!   `<= 256 KiB`, and the object-graph depth is capped at 32 to prevent stack
//!   exhaustion during parsing.
//! - No ambient authority travels inside the envelope. A client that inserts a
//!   `scope` or `role` field cannot escalate; the server ignores such fields
//!   and evaluates the caller's real scope.
//!
//! This module is headless, bounded, `forbid(unsafe)`, and keeps no
//! dependencies beyond `std`. Real JSON serialization belongs to the caller;
//! this module validates the envelope's metadata and JSON bounds.

use crate::error::IpcError;
use crate::frame::MAX_FRAME_BYTES;
use crate::scope::validate_method_name;

// ── constants ───────────────────────────────────────────────────────────────

/// Wire version v1 (the current contract version).
pub const WIRE_VERSION: u16 = 1;

/// Wire versions this runtime can speak, highest first.
///
/// This is the single source of truth for both envelope validation and
/// `hello`-style negotiation: the runtime advertises this set and selects the
/// highest version the client also supports (IPC and Agent RFC §Versioning).
/// A future wire version appends here without changing the selection logic.
pub const SUPPORTED_WIRE_VERSIONS: &[u16] = &[WIRE_VERSION];

/// Maximum bytes for correlation `id` (bounded 64 bytes).
pub const MAX_ID_BYTES: usize = 64;

/// Maximum JSON depth (cap object-graph depth at 32).
pub const MAX_JSON_DEPTH: usize = 32;

/// Maximum method bytes (re-export for convenience, matches `MAX_METHOD_BYTES`).
pub const MAX_METHOD_BYTES: usize = crate::channel::MAX_METHOD_BYTES;

// ── validation ─────────────────────────────────────────────────────────────

/// Validate wire version against the supported set.
///
/// # Errors
///
/// Returns `VersionMismatch` when `v` is not one of
/// [`SUPPORTED_WIRE_VERSIONS`]. Callers that receive a client's version list
/// should first run [`negotiate_wire_version`].
pub fn validate_wire_version(v: u16) -> Result<(), IpcError> {
    if SUPPORTED_WIRE_VERSIONS.contains(&v) {
        Ok(())
    } else {
        Err(IpcError::VersionMismatch {
            expected: WIRE_VERSION,
            actual: v,
        })
    }
}

/// Negotiate the wire version with a client advertising `client_versions`.
///
/// Returns the highest version supported by both peers. Fail-closed: a client
/// that offers no mutually supported version is rejected with
/// [`IpcError::VersionMismatch`] whose `actual` is the highest client version
/// offered (`0` when the client offered none). The runtime advertises
/// [`SUPPORTED_WIRE_VERSIONS`] in the discovery file and the `hello` response.
///
/// # Errors
///
/// Returns `VersionMismatch` when `client_versions` has no overlap with
/// [`SUPPORTED_WIRE_VERSIONS`].
pub fn negotiate_wire_version(client_versions: &[u16]) -> Result<u16, IpcError> {
    match SUPPORTED_WIRE_VERSIONS
        .iter()
        .copied()
        .find(|v| client_versions.contains(v))
    {
        Some(v) => Ok(v),
        None => Err(IpcError::VersionMismatch {
            expected: WIRE_VERSION,
            actual: client_versions.iter().copied().max().unwrap_or(0),
        }),
    }
}

/// Validate correlation id.
///
/// Rules: non-empty, `<= 64` bytes, no control bytes, no whitespace, not
/// containing `scope`/`auth` ambient authority hints (informational; real
/// authority check is server-side). Strictly bounded for framing.
pub fn validate_id(id: &str) -> Result<(), IpcError> {
    if id.is_empty() {
        return Err(IpcError::InvalidRequest {
            reason: "id must be non-empty".into(),
        });
    }
    if id.len() > MAX_ID_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "id".into(),
            limit: MAX_ID_BYTES,
            actual: id.len(),
        });
    }
    if id.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(IpcError::InvalidRequest {
            reason: "id must not contain control bytes".into(),
        });
    }
    if id
        .bytes()
        .any(|b| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r')
    {
        return Err(IpcError::InvalidRequest {
            reason: "id must not contain whitespace".into(),
        });
    }
    Ok(())
}

/// Validate a method name per wire rules (re-export of scope validation).
pub fn validate_method(method: &str) -> Result<(), IpcError> {
    validate_method_name(method)
}

/// Validate JSON depth is `<= MAX_JSON_DEPTH`.
///
/// This is a headless, bounded scan that counts nesting of `[...]` and
/// `{...}` while ignoring string literals and escapes. It prevents stack
/// exhaustion during parsing (T-01). The scan is `O(n)` with `n <= 256 KiB`.
///
/// Does not allocate; fails closed when depth exceeds the cap or when JSON
/// is structurally invalid in a way that would confuse depth (unclosed
/// string/ bracket). Callers may do a second full `serde_json` parse; this
/// check runs first as a cheap gate.
pub fn validate_json_depth(json: &[u8], max_depth: usize) -> Result<(), IpcError> {
    let mut depth = 0usize;
    let mut max_seen = 0usize;
    let mut in_str = false;
    let mut escape = false;

    for &b in json {
        if in_str {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max_depth {
                    return Err(IpcError::PayloadTooLarge {
                        field: "json.depth".into(),
                        limit: max_depth,
                        actual: depth,
                    });
                }
                if depth > max_seen {
                    max_seen = depth;
                }
            }
            b'}' | b']' => {
                if depth == 0 {
                    return Err(IpcError::InvalidFrame {
                        reason: "json: unexpected closing bracket".into(),
                    });
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    if in_str {
        return Err(IpcError::InvalidFrame {
            reason: "json: unclosed string".into(),
        });
    }
    if depth != 0 {
        return Err(IpcError::InvalidFrame {
            reason: "json: unclosed bracket".into(),
        });
    }
    let _ = max_seen;
    Ok(())
}

/// Validate that the top-level JSON object does not contain ambient authority
/// fields `auth`, `scope`, or `role` at depth 1.
///
/// A client that inserts `scope` or `role` cannot escalate; the server
/// ignores such fields and evaluates the caller's real scope. This check
/// makes the ignoring explicit and countable (FS-IP4 attribution).
///
/// The check is a lightweight string scan for `"auth"`, `"scope"`, `"role"`
/// as top-level keys (depth 1, before nesting into params). It does not
/// parse full JSON; it is conservative: if any of those substrings appear
/// as a key at depth 1, we reject the proposal (client should not send them).
/// Real validation is server-side scope evaluation, but rejecting suspicious
/// keys early helps tests assert the separation.
///
/// Returns `Ok` when no forbidden top-level key is present. To keep the
/// crate `forbid(unsafe)` and dependency-free, we do a naive but bounded
/// scan.
pub fn validate_no_ambient_auth(json: &[u8]) -> Result<(), IpcError> {
    // Quick bail: if none of the keywords appear at all, skip deeper scan.
    let s = match std::str::from_utf8(json) {
        Ok(s) => s,
        Err(_) => {
            return Err(IpcError::InvalidFrame {
                reason: "params must be utf-8 json".into(),
            });
        }
    };

    let mut container_stack: Vec<u8> = Vec::with_capacity(32);
    let mut in_str = false;
    let mut escape = false;
    let mut key_start: Option<usize> = None;

    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_str = false;
                // If we were tracking a candidate string at depth 1, inspect it.
                if let Some(start) = key_start.take() {
                    // Check if enclosing container at depth 1 is an Object `{`.
                    if container_stack.len() == 1 && container_stack.last() == Some(&b'{') {
                        // Skip whitespace after closing quote to check if string is a key.
                        let mut next_idx = i + 1;
                        while next_idx < bytes.len()
                            && matches!(bytes[next_idx], b' ' | b'\t' | b'\r' | b'\n')
                        {
                            next_idx += 1;
                        }
                        if next_idx < bytes.len() && bytes[next_idx] == b':' {
                            let key = &s[start..i];
                            if key == "auth" || key == "scope" || key == "role" {
                                return Err(IpcError::InvalidRequest {
                                    reason: format!(
                                        "forbidden ambient authority field '{key}' in envelope"
                                    ),
                                });
                            }
                        }
                    }
                }
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => {
                in_str = true;
                if container_stack.len() == 1 {
                    key_start = Some(i + 1);
                }
            }
            b'{' => container_stack.push(b'{'),
            b'[' => container_stack.push(b'['),
            b'}' | b']' => {
                container_stack.pop();
            }
            _ => {}
        }
        i += 1;
    }
    Ok(())
}

/// Validate a full request envelope headlessly.
///
/// Checks:
/// - `v == 1`
/// - `id` bounded 64 bytes
/// - `method` RFC grammar
/// - Frame bound already enforced by `MAX_FRAME_BYTES` (caller must ensure
///   `params.len() <= MAX_FRAME_BYTES`, but we re-check)
/// - JSON depth `<= 32`
/// - No ambient `auth`/`scope`/`role` at top level
/// - Params must be valid UTF-8 JSON (quick gate; full schema validation is
///   one layer above)
pub fn validate_request_envelope(
    v: u16,
    id: &str,
    method: &str,
    params_json: &[u8],
) -> Result<(), IpcError> {
    validate_wire_version(v)?;
    validate_id(id)?;
    validate_method(method)?;
    if params_json.len() > MAX_FRAME_BYTES {
        return Err(IpcError::PayloadTooLarge {
            field: "params".into(),
            limit: MAX_FRAME_BYTES,
            actual: params_json.len(),
        });
    }
    // Empty params allowed (no body), but if non-empty must be valid JSON-ish.
    if !params_json.is_empty() {
        validate_json_depth(params_json, MAX_JSON_DEPTH)?;
        validate_no_ambient_auth(params_json)?;
    }
    Ok(())
}

/// Validate a response envelope headlessly (similar bounds, `ok` flag ignored).
pub fn validate_response_envelope(v: u16, id: &str, payload_json: &[u8]) -> Result<(), IpcError> {
    validate_wire_version(v)?;
    validate_id(id)?;
    if payload_json.len() > MAX_FRAME_BYTES {
        return Err(IpcError::PayloadTooLarge {
            field: "response.payload".into(),
            limit: MAX_FRAME_BYTES,
            actual: payload_json.len(),
        });
    }
    if !payload_json.is_empty() {
        validate_json_depth(payload_json, MAX_JSON_DEPTH)?;
    }
    Ok(())
}

// ── chunk framing (RC-10) ───────────────────────────────────────────────────

/// RC-10: maximum decoded bytes per stream chunk (256 KiB).
pub const CHUNK_CEILING: usize = 256 * 1024;

/// Validate a streaming chunk header: `seq`, `total`, `bytes.len() <= CHUNK_CEILING`.
pub fn validate_chunk(seq: u32, total: u32, bytes: &[u8]) -> Result<(), IpcError> {
    if seq >= total && total != 0 {
        return Err(IpcError::InvalidRequest {
            reason: format!("chunk seq {seq} must be < total {total}"),
        });
    }
    if total == 0 {
        return Err(IpcError::InvalidRequest {
            reason: "chunk total must be > 0".into(),
        });
    }
    if bytes.len() > CHUNK_CEILING {
        return Err(IpcError::PayloadTooLarge {
            field: "chunk.bytes".into(),
            limit: CHUNK_CEILING,
            actual: bytes.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ok_and_mismatch() {
        assert!(validate_wire_version(1).is_ok());
        let err = validate_wire_version(2).unwrap_err();
        assert!(matches!(
            err,
            IpcError::VersionMismatch {
                expected: 1,
                actual: 2
            }
        ));
    }

    #[test]
    fn id_validation() {
        assert!(validate_id("01HABC").is_ok());
        assert!(validate_id("").is_err());
        let long = "x".repeat(65);
        assert!(validate_id(&long).is_err());
        assert!(validate_id("bad id").is_err());
        assert!(validate_id("bad\x01id").is_err());
    }

    #[test]
    fn method_validation_via_wire() {
        assert!(validate_method("terminal.text").is_ok());
        assert!(validate_method("terminal..text").is_err());
        assert!(validate_method("Terminal.text").is_err());
    }

    #[test]
    fn json_depth_ok_and_over() {
        assert!(validate_json_depth(b"{}", 32).is_ok());
        assert!(validate_json_depth(b"{\"a\": [1, 2, {\"b\": 3}]}", 32).is_ok());
        // Depth 33: 33 nested arrays: "[[[[...]]]]"
        let nested = "[".repeat(33) + &"]".repeat(33);
        assert!(validate_json_depth(nested.as_bytes(), 32).is_err());
        // Unclosed
        assert!(validate_json_depth(b"{ \"a\": 1", 32).is_err());
        assert!(validate_json_depth(b"{\"a\": \"unclosed}", 32).is_err());
    }

    #[test]
    fn ambient_auth_rejection() {
        // Top-level auth/scope rejected
        let with_scope = br#"{"scope": "admin", "other": 1}"#;
        assert!(validate_no_ambient_auth(with_scope).is_err());
        let with_auth = br#"{"auth": "token123"}"#;
        assert!(validate_no_ambient_auth(with_auth).is_err());
        // Top-level forbidden keys: scope, auth, role
        assert!(validate_no_ambient_auth(br#"{"scope":1}"#).is_err());
        assert!(validate_no_ambient_auth(br#"{"auth":true}"#).is_err());
        assert!(validate_no_ambient_auth(br#"{"role":"admin"}"#).is_err());
        // Whitespace before colon must be rejected
        assert!(validate_no_ambient_auth(br#"{"scope" : 1}"#).is_err());
        assert!(validate_no_ambient_auth(b"{\"scope\" \t\r\n : 1}").is_err());
        // Nested scope is allowed (depth > 1)
        let nested_ok = br#"{"params": {"scope": "value"}}"#;
        assert!(validate_no_ambient_auth(nested_ok).is_ok());
        assert!(validate_no_ambient_auth(br#"{"a":{"scope":1}}"#).is_ok());
        // Normal params without auth key passes
        let normal = br#"{"terminal_id": "t:4"}"#;
        assert!(validate_no_ambient_auth(normal).is_ok());
        // Values matching "scope"/"auth"/"role" must pass (not a key)
        assert!(validate_no_ambient_auth(br#"{"cmd":"scope"}"#).is_ok());
        assert!(validate_no_ambient_auth(br#"{"cmd":"auth"}"#).is_ok());
        assert!(validate_no_ambient_auth(br#"{"cmd":"role"}"#).is_ok());
        // Array enclosing container must pass (not an object)
        assert!(validate_no_ambient_auth(br#"["auth"]"#).is_ok());
        assert!(validate_no_ambient_auth(br#"["scope", "role"]"#).is_ok());
        // Escaped characters inside string must not falsely match
        assert!(validate_no_ambient_auth(br#"{"foo\"scope":1}"#).is_ok());
        assert!(validate_no_ambient_auth(br#"{"cmd":"foo\"scope"}"#).is_ok());
        assert!(validate_no_ambient_auth(br#"{"foo\\\"scope":1}"#).is_ok());
        assert!(validate_no_ambient_auth(br#"["foo\"auth"]"#).is_ok());
    }

    #[test]
    fn request_envelope_ok() {
        let ok =
            validate_request_envelope(1, "id-123", "terminal.text", br#"{"terminal_id":"t:4"}"#);
        assert!(ok.is_ok());
    }

    #[test]
    fn request_envelope_rejects_version() {
        let err = validate_request_envelope(2, "id-123", "terminal.text", b"{}").unwrap_err();
        assert!(matches!(err, IpcError::VersionMismatch { .. }));
    }

    #[test]
    fn request_envelope_rejects_ambient_scope() {
        let err = validate_request_envelope(1, "id-123", "terminal.text", br#"{"scope":"admin"}"#)
            .unwrap_err();
        assert!(matches!(err, IpcError::InvalidRequest { .. }));
    }

    #[test]
    fn request_envelope_rejects_payload_too_large() {
        let big = vec![b'a'; MAX_FRAME_BYTES + 1];
        let err = validate_request_envelope(1, "id", "terminal.text", &big).unwrap_err();
        assert!(matches!(err, IpcError::PayloadTooLarge { .. }));
    }

    #[test]
    fn chunk_validation() {
        assert!(validate_chunk(0, 3, &[0; 100]).is_ok());
        assert!(validate_chunk(3, 3, &[0; 10]).is_err()); // seq >= total
        assert!(validate_chunk(0, 0, &[0; 10]).is_err());
        let big = vec![0; CHUNK_CEILING + 1];
        assert!(validate_chunk(0, 2, &big).is_err());
    }
}
