//! Transport-wiring obligations for id correlation and attribution (item 5).
//!
//! The S2 vocabulary defines domain payloads with no `v`/`id`/`method` and no
//! framing of its own; domain shapes ride inside `params`/`result` under the
//! accepted wire envelope (RFC §Wire protocol, "Envelope"). Correlation
//! across the boundary therefore binds three identifier layers, and the
//! transport wiring (not this crate) must uphold the binding plus the
//! attribution-handle rules below. This module provides the enforceable half
//! as pure helpers; the rest is documented as transport obligations. Channel
//! routing behavior is unchanged.
//!
//! Binding (outermost to innermost):
//!
//! 1. Wire `id` (`<= 64` bytes, RFC §Wire protocol) <-> channel [`RequestId`]
//!    (non-zero `u64`, `channel.rs`): the envelope carries the wire id as
//!    text; the channel tracks the numeric request. [`WireBinding`] checks
//!    both ends and matches responses.
//! 2. [`RequestId`] <-> domain attribution handles: S2 `AuthBase` carries
//!    `(agent_instance_id, session_id)` plus the server-side tier, and S2
//!    `ExecutionContext` carries `(execution_id, now_ms)` as a transient
//!    dispatch identity. Handles are attribution-only and transient (S2
//!    `tool_dispatch.rs`: `ExecutionContext` is never stored and never
//!    logged). [`AttributionHandles`] mirrors the three `u64` handles with a
//!    redacted `Debug` so the never-logged rule is enforceable in code.
//! 3. Argument binding: S2 `DispatchRequest` crosses as digest-only
//!    (FNV-1a-64 over the raw argument bytes); the transport binds its own
//!    argument bytes to that digest out-of-band. [`args_digest`] re-states
//!    the digest function (same FNV-1a-64 parameters as the S2
//!    `UsageEvent::args_digest` precedent) so the transport can verify with
//!    [`verify_args_digest`] instead of re-deriving the algorithm.
//!
//! Transport obligations (wiring, not code):
//!
//! - Re-derive tier and grants server-side from the authenticated identity on
//!   every request (RFC §Authorization and scopes: scopes are evaluated
//!   server-side; `AuthBase` and caller-scope echoes are transport-enforced
//!   inputs and observation, never grants).
//! - Treat attribution handles as observation data, never authority:
//!   constructing or presenting a handle grants nothing.
//! - Never store and never log the domain `ExecutionContext`; never log raw
//!   argument bytes (digest only). [`AttributionHandles`] redacts `Debug`
//!   for exactly this reason.
//! - Per-op consent gating (which dispatch needs which grant) is batch-2 work
//!   (wiring item 7) and stays open here.

use std::fmt;

use crate::channel::{IpcResponse, RequestId};
use crate::error::IpcError;
use crate::wire::validate_id;

// ── wire id <-> RequestId ───────────────────────────────────────────────────

/// Checked binding between a wire envelope `id` and a channel [`RequestId`].
///
/// Both ends are validated at construction: the wire id against the envelope
/// rules (non-empty, `<= 64` bytes, no control bytes or whitespace) and the
/// request id against the channel rule (non-zero; zero is reserved for "no
/// id" / notifications). A response correlates to this binding only when its
/// id echoes the bound request id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireBinding {
    /// Wire envelope correlation id.
    wire_id: String,
    /// Channel request identifier.
    request_id: RequestId,
}

impl WireBinding {
    /// Bind `wire_id` to `request_id`, validating both ends.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::InvalidRequest`] when `request_id` is zero, or the
    /// envelope `id` violation (`InvalidRequest` / `LimitExceeded`) when
    /// `wire_id` breaks the `<= 64`-byte wire rules.
    pub fn new(wire_id: String, request_id: RequestId) -> Result<Self, IpcError> {
        if request_id.is_zero() {
            return Err(IpcError::InvalidRequest {
                reason: "correlation requires a non-zero request id".into(),
            });
        }
        validate_id(&wire_id)?;
        Ok(Self {
            wire_id,
            request_id,
        })
    }

    /// Borrow the bound wire id.
    #[must_use]
    pub fn wire_id(&self) -> &str {
        &self.wire_id
    }

    /// The bound request id.
    #[must_use]
    pub fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Whether `response` echoes the bound request id.
    ///
    /// Correlation never reuses an id under pressure: unknown ids return
    /// `false` without insertion, mirroring the pending-table discipline
    /// (`IpcEndpoint::complete`).
    #[must_use]
    pub fn matches_response(&self, response: &IpcResponse) -> bool {
        response.id == self.request_id
    }
}

// ── attribution handles ─────────────────────────────────────────────────────

/// Domain attribution handles for one dispatch (transient, never stored).
///
/// Mirrors the S2 identity triple without depending on any `bitty-ai` crate:
/// `agent_instance_id` + `session_id` (S2 `AuthBase`: who) plus
/// `execution_id` (S2 `ExecutionContext`: which dispatch). All three are
/// opaque `u64` handles: attribution data, never authority.
///
/// `Debug` is redacted by design so `format!("{handles:?}")` cannot emit a
/// handle into logs or traces (the S2 never-logged rule, enforced in code).
/// The dispatch timestamp travels separately as caller-supplied `now_ms`
/// (see `deadline.rs`); no clock is read here.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttributionHandles {
    /// Calling agent instance handle.
    agent_instance_id: u64,
    /// Calling session handle.
    session_id: u64,
    /// Dispatch attribution handle for this call.
    execution_id: u64,
}

impl AttributionHandles {
    /// Carry the three attribution handles for one transient dispatch.
    ///
    /// Pure data carrier: no clock read, no gate, no grant. The transport
    /// must not store this value past the dispatch it attributes.
    #[must_use]
    pub fn transient(agent_instance_id: u64, session_id: u64, execution_id: u64) -> Self {
        Self {
            agent_instance_id,
            session_id,
            execution_id,
        }
    }

    /// Calling agent instance handle.
    #[must_use]
    pub fn agent_instance_id(&self) -> u64 {
        self.agent_instance_id
    }

    /// Calling session handle.
    #[must_use]
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Dispatch attribution handle.
    #[must_use]
    pub fn execution_id(&self) -> u64 {
        self.execution_id
    }
}

impl fmt::Debug for AttributionHandles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never-logged rule: handles are attribution data, and even
        // attribution handles stay out of logs/traces.
        f.write_str("AttributionHandles(redacted)")
    }
}

// ── argument digest binding ─────────────────────────────────────────────────

/// FNV-1a-64 offset basis (same parameters as the S2
/// `UsageEvent::args_digest` precedent: deterministic across processes and
/// platforms).
pub const ARGS_DIGEST_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a-64 prime (same parameters as the S2 `UsageEvent::args_digest`
/// precedent).
pub const ARGS_DIGEST_PRIME: u64 = 0x0100_0000_01b3;

/// Deterministic digest of raw call argument bytes (digest only, never raw args).
///
/// FNV-1a-64 over exactly the argument bytes (inline small hasher, never
/// `DefaultHasher`/`RandomState`): the same bytes give the same digest on
/// every platform and process, and any byte change moves it. The transport
/// binds its own argument bytes to the crossed digest out-of-band with
/// [`verify_args_digest`]; raw argument bytes are never logged or stored for
/// correlation.
#[must_use]
pub fn args_digest(args: &[u8]) -> u64 {
    let mut hash = ARGS_DIGEST_OFFSET_BASIS;
    for byte in args {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(ARGS_DIGEST_PRIME);
    }
    hash
}

/// Whether `args` bind to the crossed `digest`.
///
/// Out-of-band binding check for the digest-only crossing: `true` when
/// [`args_digest`] over the transport's own argument bytes equals the digest
/// the domain envelope carried. A mismatch is a binding failure, reported by
/// the transport as [`IpcError::InvalidRequest`] (shape/binding refusal, no
/// partial state per RFC §Failure semantics, FS-IP1).
#[must_use]
pub fn verify_args_digest(args: &[u8], digest: u64) -> bool {
    args_digest(args) == digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::IpcResponse;

    #[test]
    fn wire_binding_validates_both_ends() {
        assert!(WireBinding::new("id-1".into(), RequestId(7)).is_ok());
        // Zero request id is reserved.
        assert!(WireBinding::new("id-1".into(), RequestId(0)).is_err());
        // Wire id rules apply: empty, too long, whitespace, control bytes.
        assert!(WireBinding::new(String::new(), RequestId(7)).is_err());
        assert!(WireBinding::new("x".repeat(65), RequestId(7)).is_err());
        assert!(WireBinding::new("bad id".into(), RequestId(7)).is_err());
        assert!(WireBinding::new("bad\x01id".into(), RequestId(7)).is_err());
    }

    #[test]
    fn wire_binding_matches_response_by_request_id() {
        let binding = WireBinding::new("wire-abc".into(), RequestId(7)).unwrap();
        assert_eq!(binding.wire_id(), "wire-abc");
        assert_eq!(binding.request_id(), RequestId(7));
        let hit = IpcResponse::success(RequestId(7), b"ok".to_vec()).unwrap();
        let miss = IpcResponse::success(RequestId(8), b"ok".to_vec()).unwrap();
        assert!(binding.matches_response(&hit));
        assert!(!binding.matches_response(&miss));
        // Unknown ids correlate to nothing: no insertion, no reuse.
        debug_assert!(!binding.matches_response(&miss));
    }

    #[test]
    fn wire_binding_drives_pending_completion() {
        // End-to-end through the channel: the bound request id completes the
        // pending entry, an unknown id does not.
        let mut ep = crate::channel::IpcEndpoint::new();
        let binding = WireBinding::new("wire-9".into(), RequestId(41)).unwrap();
        let req = crate::channel::IpcRequest::new(
            binding.request_id(),
            "terminal.text".into(),
            br#"{"terminal_id":"t:4"}"#.to_vec(),
            0,
            1000,
        )
        .unwrap();
        ep.send_request(req).unwrap();
        assert!(ep.peek_pending(binding.request_id()).is_some());
        assert!(!ep.complete(RequestId(999)));
        assert!(ep.complete(binding.request_id()));
        assert!(!ep.has_pending());
    }

    #[test]
    fn attribution_handles_are_transient_and_redacted() {
        let handles = AttributionHandles::transient(11, 22, 33);
        assert_eq!(handles.agent_instance_id(), 11);
        assert_eq!(handles.session_id(), 22);
        assert_eq!(handles.execution_id(), 33);
        // Never-logged rule, enforced: Debug emits no handle digits.
        let shown = format!("{handles:?}");
        assert!(!shown.contains("11"));
        assert!(!shown.contains("22"));
        assert!(!shown.contains("33"));
        assert!(shown.contains("redacted"));
    }

    #[test]
    fn args_digest_matches_fnv1a64_vectors() {
        // Standard FNV-1a 64-bit test vectors pin the algorithm so the
        // transport verifies against the same digest the domain crossed.
        assert_eq!(args_digest(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(args_digest(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(args_digest(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn args_digest_binding_verifies_out_of_band() {
        let args = br#"{"path":"src/main.rs"}"#;
        let digest = args_digest(args);
        assert!(verify_args_digest(args, digest));
        // Any byte change moves the digest: binding fails closed.
        let mut tampered = args.to_vec();
        tampered.push(b' ');
        assert!(!verify_args_digest(&tampered, digest));
        debug_assert!(!verify_args_digest(&tampered, digest));
    }
}
