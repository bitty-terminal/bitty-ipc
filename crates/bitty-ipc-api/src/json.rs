//! Canonical `params`/`result` JSON mapping rules (wiring item 2).
//!
//! S2 domain shapes cross the boundary as JSON bytes inside the wire
//! envelope's `params`/`result` fields (RFC §Wire protocol, "Envelope": the
//! envelope carries bounded JSON values; domain payloads define no `v`/`id`/
//! `method` and no framing of their own). The canonical rules, in validation
//! order, are:
//!
//! 1. Envelope first: `v`, `id`, `method` validate per `wire.rs` before any
//!    `params`/`result` byte is interpreted (RFC §Wire protocol, envelope
//!    rules).
//! 2. Frame bound: `params`/`result` bytes are `<= 256 KiB`
//!    (`MAX_FRAME_BYTES`; RFC §Transport and bounded framing).
//! 3. UTF-8: bytes must be valid UTF-8 JSON; non-UTF-8 is refused whole with
//!    [`IpcError::InvalidFrame`] before any parse (fail-closed framing, RFC
//!    §Failure semantics, FS-IP7).
//! 4. Depth: the object graph nests at most 32 deep (`MAX_JSON_DEPTH`; RFC
//!    §Wire protocol, envelope rules; T-01 stack-exhaustion defense).
//! 5. No ambient authority: top-level `auth`/`scope`/`role` keys are refused;
//!    the server ignores such fields and evaluates the caller's real scope
//!    (RFC §Wire protocol, envelope rules; RFC §Authorization and scopes).
//! 6. Strings are bounded in bytes, not characters: every S2 string field
//!    that crosses must fit its IPC-side byte bound below; multi-byte UTF-8
//!    counts every byte. Grammar checks (name shapes) stay S2-owned; the IPC
//!    side enforces bytes plus UTF-8 only.
//! 7. Schema validation is one layer above: the channel treats `params` as
//!    opaque bytes, and per-op field schemas (which keys, which types) are
//!    transport-wiring work alongside the method registry (batch 2). Unknown
//!    non-authority fields inside `params` pass through opaquely.
//!
//! Method-name strings for AI ops are NOT registered here (batch 2, wiring
//! item 1); scope assignment is NOT done here (batch 2, wiring item 1); no
//! consent-policy choice is made here (batch 2, wiring item 7, open).

use crate::error::IpcError;
use crate::frame::MAX_FRAME_BYTES;
use crate::wire::{MAX_JSON_DEPTH, validate_json_depth, validate_no_ambient_auth};

// ── IPC-side string byte bounds ─────────────────────────────────────────────

/// Maximum bytes for a selection alias string crossing in `params`.
///
/// S2 `SelectEnvelopeRequest.alias` is currently unbounded (no validation at
/// construction). The IPC-side bound mirrors the S2 `MAX_MODEL_NAME_LEN`
/// (`128`, same-shape routing-name precedent) so an alias always fits the
/// byte budget of the name tables it resolves against.
///
/// // CANDIDATE (CTX-0005): confirm with security/architecture reviewer.
/// S2 imposes no bound here; `128` is recommended as the smallest bound
/// consistent with the existing S2 name precedent.
pub const MAX_AGENT_ALIAS_BYTES: usize = 128;

/// Maximum bytes per manifest or descriptor string field crossing in
/// `params`/`result`.
///
/// S2 `Manifest` (`name`, `version`, opaque `host` predicate) and the eight
/// point-descriptor strings are currently unbounded opaque strings ("opaque
/// string only; no validation"). The IPC-side bound mirrors the S2
/// `MAX_TOOL_DESCRIPTION_LEN` (`512`, owner-supplied opaque short-string
/// precedent) so declaration echoes stay short while remaining opaque.
///
/// // CANDIDATE (CTX-0005): confirm with security/architecture reviewer.
/// S2 imposes no bound here; `512` is recommended as the smallest bound
/// consistent with the existing S2 opaque-string precedent.
pub const MAX_MANIFEST_FIELD_BYTES: usize = 512;

// ── validators ──────────────────────────────────────────────────────────────

/// Validate one bounded string field in bytes (UTF-8 is guaranteed by `&str`).
///
/// # Errors
///
/// Returns [`IpcError::LimitExceeded`] with `field`/`limit`/`actual` when
/// `value.len() > limit` (byte count, so multi-byte UTF-8 counts every
/// byte).
pub fn validate_bounded_string(
    field: &'static str,
    value: &str,
    limit: usize,
) -> Result<(), IpcError> {
    if value.len() > limit {
        return Err(IpcError::LimitExceeded {
            field: field.into(),
            limit,
            actual: value.len(),
        });
    }
    Ok(())
}

/// Validate a selection alias string for `params` crossing.
///
/// # Errors
///
/// Returns [`IpcError::LimitExceeded`] when the alias exceeds
/// [`MAX_AGENT_ALIAS_BYTES`] bytes.
pub fn validate_alias(alias: &str) -> Result<(), IpcError> {
    validate_bounded_string("alias", alias, MAX_AGENT_ALIAS_BYTES)
}

/// Validate one manifest/descriptor string field for crossing.
///
/// # Errors
///
/// Returns [`IpcError::LimitExceeded`] when the field exceeds
/// [`MAX_MANIFEST_FIELD_BYTES`] bytes.
pub fn validate_manifest_field(field: &'static str, value: &str) -> Result<(), IpcError> {
    validate_bounded_string(field, value, MAX_MANIFEST_FIELD_BYTES)
}

/// Validate `params` JSON bytes per the canonical rules (order: frame bound,
/// UTF-8, depth, no ambient authority).
///
/// Empty input is allowed (no body). Non-empty input must be valid UTF-8 JSON
/// within the depth cap and free of top-level `auth`/`scope`/`role` keys.
///
/// # Errors
///
/// - [`IpcError::PayloadTooLarge`] when `params.len() > MAX_FRAME_BYTES`.
/// - [`IpcError::InvalidFrame`] when `params` are not valid UTF-8.
/// - [`IpcError::PayloadTooLarge`] (`json.depth`) when nesting exceeds
///   `MAX_JSON_DEPTH`, or [`IpcError::InvalidFrame`] on structurally
///   confusing input.
/// - [`IpcError::InvalidRequest`] on a forbidden top-level authority key.
pub fn validate_params_json(params: &[u8]) -> Result<(), IpcError> {
    validate_json_bytes("params", params)
}

/// Validate `result` JSON bytes per the canonical rules (same order as
/// [`validate_params_json`]).
///
/// # Errors
///
/// Same classes as [`validate_params_json`], with `field` set to `result`.
pub fn validate_result_json(result: &[u8]) -> Result<(), IpcError> {
    validate_json_bytes("result", result)
}

fn validate_json_bytes(field: &'static str, bytes: &[u8]) -> Result<(), IpcError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(IpcError::PayloadTooLarge {
            field: field.into(),
            limit: MAX_FRAME_BYTES,
            actual: bytes.len(),
        });
    }
    if bytes.is_empty() {
        return Ok(());
    }
    core::str::from_utf8(bytes).map_err(|_| IpcError::InvalidFrame {
        reason: format!("{field} must be utf-8 json"),
    })?;
    validate_json_depth(bytes, MAX_JSON_DEPTH)?;
    validate_no_ambient_auth(bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_bound_is_128_bytes() {
        // CANDIDATE (CTX-0005): mirrors S2 MAX_MODEL_NAME_LEN precedent.
        assert_eq!(MAX_AGENT_ALIAS_BYTES, 128);
        assert!(validate_alias(&"a".repeat(128)).is_ok());
        let err = validate_alias(&"a".repeat(129)).unwrap_err();
        assert!(matches!(
            err,
            IpcError::LimitExceeded {
                limit: 128,
                actual: 129,
                ..
            }
        ));
    }

    #[test]
    fn manifest_field_bound_is_512_bytes() {
        // CANDIDATE (CTX-0005): mirrors S2 MAX_TOOL_DESCRIPTION_LEN precedent.
        assert_eq!(MAX_MANIFEST_FIELD_BYTES, 512);
        assert!(validate_manifest_field("manifest.name", &"n".repeat(512)).is_ok());
        let err = validate_manifest_field("manifest.host", &"h".repeat(513)).unwrap_err();
        assert!(matches!(
            err,
            IpcError::LimitExceeded {
                limit: 512,
                actual: 513,
                ..
            }
        ));
    }

    #[test]
    fn string_bounds_count_bytes_not_chars() {
        // Multi-byte UTF-8 counts every byte: 64 x U+00E9 (2 bytes) = 128.
        let s = "\u{e9}".repeat(64);
        assert_eq!(s.len(), 128);
        assert!(validate_alias(&s).is_ok());
        let over = "\u{e9}".repeat(65);
        assert_eq!(over.len(), 130);
        assert!(validate_alias(&over).is_err());
    }

    #[test]
    fn params_json_accepts_valid_utf8() {
        assert!(validate_params_json(b"").is_ok());
        assert!(validate_params_json(br#"{"terminal_id":"t:4"}"#).is_ok());
        // Multi-byte UTF-8 (emoji, CJK-adjacent planes decode the same way)
        // passes: UTF-8 validity is about encoding, never script.
        assert!(validate_params_json("{\"note\":\"caf\u{e9} \\u{1f600}\"}".as_bytes()).is_ok());
    }

    #[test]
    fn params_json_rejects_non_utf8() {
        let bad = [0x7b, 0x22, 0xff, 0x22, 0x7d]; // {"\xff"}
        let err = validate_params_json(&bad).unwrap_err();
        assert!(matches!(err, IpcError::InvalidFrame { .. }));
        assert!(validate_result_json(&bad).is_err());
    }

    #[test]
    fn params_json_enforces_depth_32() {
        // Depth 32 nests pass; depth 33 fails (T-01 stack-exhaustion defense).
        let at_cap = "[".repeat(32) + &"]".repeat(32);
        assert!(validate_params_json(at_cap.as_bytes()).is_ok());
        let over = "[".repeat(33) + &"]".repeat(33);
        let err = validate_params_json(over.as_bytes()).unwrap_err();
        assert!(matches!(err, IpcError::PayloadTooLarge { .. }));
    }

    #[test]
    fn params_json_rejects_ambient_authority() {
        let err = validate_params_json(br#"{"scope":"admin"}"#).unwrap_err();
        assert!(matches!(err, IpcError::InvalidRequest { .. }));
        // Nested occurrence inside params is opaque data, not authority.
        assert!(validate_params_json(br#"{"filter":{"scope":"x"}}"#).is_ok());
    }

    #[test]
    fn result_json_rejects_oversize() {
        let big = vec![b'a'; MAX_FRAME_BYTES + 1];
        let err = validate_result_json(&big).unwrap_err();
        assert!(matches!(err, IpcError::PayloadTooLarge { .. }));
    }
}
