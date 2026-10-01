//! Generic out-of-process bridge client boundary (CTX-0419, G-1).
//!
//! G-1 from the CTX-0407 pressure test: `bitty-ipc` was `publish = false`,
//! so out-of-process consumers (`bitty-ai`, devtools) pinned it via a git
//! rev plus a `deny.toml` `allow-git` exception (`bitty-ai` PR #7,
//! read-only reference). [`BridgeClient`] is the canonical published
//! boundary those consumers depend on instead: mechanism-only, no AI
//! specifics.
//!
//! # Dispatch order (DIR-018 steps 1-2, client side)
//!
//! Each [`BridgeClient::call`] composes exactly the client-side prefix of
//! the accepted dispatch formula; any refusal leaves no pending state
//! (FS-IP1 transactional denial):
//!
//! 1. **Routing**: [`validate_method_name`](bitty_ipc_api::scope::validate_method_name)
//!    syntax, then [`required_scope_for_method`](bitty_ipc_api::scope::required_scope_for_method);
//!    unknown methods fail closed as `NotFound` before any authorization,
//!    budget, or enqueue.
//! 2. **Authorization**: [`authorize_method`](bitty_ipc_api::scope::authorize_method)
//!    against the server-evaluated [`ScopeSet`](bitty_ipc_api::scope::ScopeSet)
//!    handed to [`BridgeClient::new`]; missing scope fails as `ScopeDenied`.
//!    Clients never assert scopes.
//! 3. **Consent**: per-client [`ConsentLedger`](bitty_ipc_api::scope::ConsentLedger)
//!    check for `(client_id, scope)` at `now_ms`; missing or expired grants
//!    fail as `Denied[ConsentRequired]`. This ledger is the client's local
//!    pre-check mirror; enforcement stays server-side.
//! 4. **Budget**: wire params are bounded by [`MAX_BRIDGE_PARAMS_BYTES`]
//!    (the deferred wire-parsing concern from the CTX-0420 review: any wire
//!    parsing the bridge introduces is bounded here, never unbounded);
//!    over-bound inputs fail as `PayloadTooLarge`, never silently clamped.
//! 5. **Envelope**: [`validate_request_envelope`](bitty_ipc_api::wire::validate_request_envelope)
//!    (`v == 1`, id `<= 64` bytes, method grammar, JSON depth `<= 32`, no
//!    ambient `auth`/`scope`/`role`) before enqueue.
//! 6. **Attribution**: the authenticated `client_id` is bound at
//!    construction (bounded [`MAX_BRIDGE_CLIENT_ID_BYTES`]); every queued
//!    request correlates via a non-zero [`RequestId`](bitty_ipc_api::channel::RequestId).
//! 7. **Outcome**: the queued [`IpcRequest`](bitty_ipc_api::channel::IpcRequest)
//!    hands over via [`BridgeClient::take_request`]; peer answers re-enter
//!    via [`BridgeClient::answer`] and correlate through the pending table.
//!    `Unknown` reconciliation belongs to the ExecutionContext service
//!    (`crate::execution`), not here.
//!
//! # Budgets (accepted contracts, verified first-hand)
//!
//! Every number below reuses an accepted `bitty-ipc` bound; no value is
//! invented here:
//!
//! - Wire params `<= 16 KiB` ([`MAX_BRIDGE_PARAMS_BYTES`],
//!   `tool_dispatch::MAX_TOOL_ARGS_BYTES`, RFC tool-args cap): the largest
//!   params payloads the bridge carries are tool/execution arguments.
//! - Client identity `<= 64` bytes ([`MAX_BRIDGE_CLIENT_ID_BYTES`],
//!   `auth::MAX_SCOPED_ID_BYTES`, scoped-id precedent).
//! - Per-request deadline [`DEFAULT_REQUEST_TIMEOUT_MS`](bitty_ipc_api::channel::DEFAULT_REQUEST_TIMEOUT_MS)
//!   (5 s, channel bound); pending-table and queue caps are the endpoint
//!   defaults (`MAX_PENDING_REQUESTS` 64).
//!
//! The module is pure data, bounded, headless, and `forbid(unsafe)`: it
//! owns no socket, spawns no thread, performs no I/O, and depends on no
//! workspace crate beyond `bitty-ipc` itself. No network, no new external
//! crates, no AI vocabulary.

use bitty_ipc_api::channel::{DEFAULT_REQUEST_TIMEOUT_MS, IpcEndpoint, IpcRequest, IpcResponse, RequestId};
use bitty_ipc_api::error::IpcError;
use bitty_ipc_api::scope::{
    ConsentLedger, Scope, ScopeSet, authorize_method, required_scope_for_method,
    validate_method_name,
};
use bitty_ipc_api::wire::{WIRE_VERSION, validate_request_envelope, validate_response_envelope};

// ── bounds (accepted-contract sources inline) ───────────────────────────────

/// Maximum wire params bytes per [`BridgeClient::call`] (16 KiB, RFC
/// tool-args cap, `tool_dispatch::MAX_TOOL_ARGS_BYTES`).
///
/// This is the bound the CTX-0420 review deferred: wire parsing the bridge
/// introduces is bounded here. Snapshot/tool/execution DTO validation stays
/// in those modules; this caps the raw params bytes before any of them run.
pub const MAX_BRIDGE_PARAMS_BYTES: usize = crate::tool_dispatch::MAX_TOOL_ARGS_BYTES;

/// Maximum client identity bytes (`auth::MAX_SCOPED_ID_BYTES`, scoped-id
/// precedent).
pub const MAX_BRIDGE_CLIENT_ID_BYTES: usize = bitty_ipc_auth::auth::MAX_SCOPED_ID_BYTES;

// ── client ──────────────────────────────────────────────────────────────────

/// Generic out-of-process bridge client: the published boundary for
/// `bitty-ai`, devtools, and any future out-of-process consumer.
///
/// Owns a bounded [`IpcEndpoint`] (queues + pending table), a per-client
/// [`ConsentLedger`], the authenticated `client_id`, and the
/// server-evaluated [`ScopeSet`]. All time comes from caller-supplied
/// `now_ms`, never wall-clock. Mechanism-only: method names, scopes, and
/// params shapes are the generic registry's, never AI-specific.
#[derive(Debug)]
pub struct BridgeClient {
    endpoint: IpcEndpoint,
    consent: ConsentLedger,
    client_id: String,
    granted: ScopeSet,
}

impl BridgeClient {
    /// Construct a bridge for `client_id` with server-evaluated `granted` scopes.
    ///
    /// # Errors
    ///
    /// - [`IpcError::InvalidRequest`] when `client_id` is empty.
    /// - [`IpcError::LimitExceeded`] when `client_id` exceeds
    ///   [`MAX_BRIDGE_CLIENT_ID_BYTES`].
    pub fn new(client_id: impl Into<String>, granted: ScopeSet) -> Result<Self, IpcError> {
        let client_id = client_id.into();
        if client_id.is_empty() {
            return Err(IpcError::InvalidRequest {
                reason: "bridge client_id must be non-empty".into(),
            });
        }
        if client_id.len() > MAX_BRIDGE_CLIENT_ID_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "bridge.client_id".into(),
                limit: MAX_BRIDGE_CLIENT_ID_BYTES,
                actual: client_id.len(),
            });
        }
        Ok(Self {
            endpoint: IpcEndpoint::new(),
            consent: ConsentLedger::new(),
            client_id,
            granted,
        })
    }

    /// Authenticated client identity bound at construction.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Record a per-client consent grant for `scope` lasting `ttl_ms` from `now_ms`.
    ///
    /// This mirrors the grant into the client's local ledger pre-check;
    /// enforcement stays server-side.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::LimitExceeded`] when the ledger is at capacity.
    pub fn grant_consent(
        &mut self,
        scope: Scope,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<(), IpcError> {
        self.consent.grant(
            self.client_id.clone(),
            scope,
            now_ms,
            ttl_ms,
            self.client_id.clone(),
        )
    }

    /// Whether `scope` is currently granted to this client at `now_ms`.
    #[must_use]
    pub fn consent_active(&self, scope: Scope, now_ms: u64) -> bool {
        self.consent.is_granted(&self.client_id, scope, now_ms)
    }

    /// Number of requests still awaiting a correlated response.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.endpoint.pending_count()
    }

    /// Validate, authorize, consent-gate, envelope-check, and enqueue one
    /// bounded request, returning its correlation id.
    ///
    /// Order is routing, authorization, consent, budget, envelope, enqueue
    /// (see module docs). Any refusal leaves no pending state.
    ///
    /// # Errors
    ///
    /// - [`IpcError::InvalidMethod`] when `method` violates the wire grammar.
    /// - [`IpcError::NotFound`] when `method` is not in the generic registry.
    /// - [`IpcError::ScopeDenied`] when `granted` lacks the required scope.
    /// - [`IpcError::Denied`] with code `ConsentRequired` when no live
    ///   `(client_id, scope)` grant exists at `now_ms`.
    /// - [`IpcError::PayloadTooLarge`] when `params` exceeds
    ///   [`MAX_BRIDGE_PARAMS_BYTES`].
    /// - Wire [`IpcError::InvalidRequest`] / `VersionMismatch` when the
    ///   envelope check rejects, or channel errors at capacity.
    pub fn call(
        &mut self,
        method: &str,
        params: Vec<u8>,
        now_ms: u64,
    ) -> Result<RequestId, IpcError> {
        validate_method_name(method)?;
        let required = required_scope_for_method(method).ok_or_else(|| IpcError::NotFound {
            reason: format!("unknown method '{method}'"),
        })?;
        authorize_method(method, &self.granted)?;
        if !self.consent.is_granted(&self.client_id, required, now_ms) {
            return Err(IpcError::Denied {
                code: "ConsentRequired".into(),
                reason: format!(
                    "no live consent for '{}' on '{}'",
                    required.as_str(),
                    self.client_id
                ),
            });
        }
        if params.len() > MAX_BRIDGE_PARAMS_BYTES {
            return Err(IpcError::PayloadTooLarge {
                field: "bridge.params".into(),
                limit: MAX_BRIDGE_PARAMS_BYTES,
                actual: params.len(),
            });
        }
        // Reserve the correlation id first so the envelope check and the
        // enqueue share one id. A refusal after this point advances the id
        // counter only; no request is queued and no pending entry is stored.
        let id = self.endpoint.next_request_id();
        validate_request_envelope(WIRE_VERSION, &id.to_string(), method, &params)?;
        let request = IpcRequest::new(
            id,
            method.to_string(),
            params,
            now_ms,
            DEFAULT_REQUEST_TIMEOUT_MS,
        )?;
        self.endpoint.send_request(request)?;
        Ok(id)
    }

    /// Take the oldest queued request for handover to the transport.
    pub fn take_request(&mut self) -> Option<IpcRequest> {
        self.endpoint.recv_request()
    }

    /// Deliver a peer answer for `id`: envelope-check the payload, buffer it
    /// inbound, and correlate through the pending table.
    ///
    /// Returns `true` when `id` correlated to a known in-flight request.
    /// Unknown ids (never issued, already completed, or already expired)
    /// return `false` **without buffering anything** (fail-closed
    /// pre-enqueue): a hostile peer spraying uncorrelated answers cannot
    /// fill the bounded inbound queue and deny service to legitimate
    /// correlations.
    ///
    /// # Errors
    ///
    /// - [`IpcError::PayloadTooLarge`] when `payload` exceeds the frame bound.
    /// - [`IpcError::InvalidRequest`] when `id` is zero.
    /// - [`IpcError::ChannelFull`] when the inbound response queue is at capacity.
    pub fn answer(
        &mut self,
        id: RequestId,
        payload: Vec<u8>,
        is_error: bool,
    ) -> Result<bool, IpcError> {
        validate_response_envelope(WIRE_VERSION, &id.to_string(), &payload)?;
        let response = if is_error {
            IpcResponse::error(id, payload)?
        } else {
            IpcResponse::success(id, payload)?
        };
        if self.endpoint.peek_pending(id).is_none() {
            return Ok(false);
        }
        self.endpoint.send_response(response)?;
        Ok(self.endpoint.complete(id))
    }

    /// Take the oldest buffered inbound response, if any.
    pub fn take_response(&mut self) -> Option<IpcResponse> {
        self.endpoint.recv_response()
    }

    /// Inspect a pending request without removing it.
    #[must_use]
    pub fn pending_request(&self, id: RequestId) -> Option<&IpcRequest> {
        self.endpoint.peek_pending(id)
    }

    /// Drop pending entries at or past deadline, returning their ids.
    pub fn drain_expired(&mut self, now_ms: u64) -> Vec<RequestId> {
        self.endpoint.drain_expired(now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitty_ipc_api::scope::ScopeSet;

    const CLIENT: &str = "bridge-tests";
    const NOW_MS: u64 = 1_000;
    const TTL_MS: u64 = 60_000;

    fn consented() -> BridgeClient {
        let mut bridge = BridgeClient::new(CLIENT, ScopeSet::cli_default()).expect("valid bridge");
        bridge
            .grant_consent(Scope::TerminalInspect, NOW_MS, TTL_MS)
            .expect("grant fits");
        bridge
    }

    #[test]
    fn bounds_reuse_accepted_contracts() {
        assert_eq!(
            MAX_BRIDGE_PARAMS_BYTES,
            crate::tool_dispatch::MAX_TOOL_ARGS_BYTES
        );
        assert_eq!(MAX_BRIDGE_CLIENT_ID_BYTES, bitty_ipc_auth::auth::MAX_SCOPED_ID_BYTES);
        assert_eq!(MAX_BRIDGE_PARAMS_BYTES, 16 * 1024);
        assert_eq!(MAX_BRIDGE_CLIENT_ID_BYTES, 64);
    }

    #[test]
    fn client_id_is_bounded() {
        assert!(BridgeClient::new("c", ScopeSet::new()).is_ok());
        assert!(BridgeClient::new("", ScopeSet::new()).is_err());
        let long = "c".repeat(MAX_BRIDGE_CLIENT_ID_BYTES + 1);
        let err = BridgeClient::new(long, ScopeSet::new()).unwrap_err();
        assert!(matches!(err, IpcError::LimitExceeded { .. }));
        // Boundary: exactly the cap fits.
        let exact = "c".repeat(MAX_BRIDGE_CLIENT_ID_BYTES);
        assert!(BridgeClient::new(exact, ScopeSet::new()).is_ok());
    }

    #[test]
    fn consent_lifecycle_roundtrips() {
        let mut bridge = BridgeClient::new(CLIENT, ScopeSet::cli_default()).expect("valid bridge");
        assert!(!bridge.consent_active(Scope::TerminalInspect, NOW_MS));
        bridge
            .grant_consent(Scope::TerminalInspect, NOW_MS, TTL_MS)
            .unwrap();
        assert!(bridge.consent_active(Scope::TerminalInspect, NOW_MS));
        assert!(!bridge.consent_active(Scope::TerminalInspect, NOW_MS + TTL_MS));
        assert_eq!(bridge.client_id(), CLIENT);
    }

    #[test]
    fn call_rejects_unknown_method_without_pending() {
        let mut bridge = consented();
        let err = bridge
            .call("panel.context", b"{}".to_vec(), NOW_MS)
            .unwrap_err();
        assert!(matches!(err, IpcError::NotFound { .. }));
        assert_eq!(bridge.pending_count(), 0);
    }

    #[test]
    fn call_rejects_bad_grammar_before_registry() {
        let mut bridge = consented();
        let err = bridge
            .call("Terminal.text", b"{}".to_vec(), NOW_MS)
            .unwrap_err();
        assert!(matches!(err, IpcError::InvalidMethod { .. }));
        assert_eq!(bridge.pending_count(), 0);
    }

    #[test]
    fn call_enqueues_with_default_timeout() {
        let mut bridge = consented();
        let id = bridge
            .call("terminal.snapshot", b"{}".to_vec(), NOW_MS)
            .unwrap();
        let pending = bridge.pending_request(id).expect("pending tracked");
        assert_eq!(pending.timeout_ms, DEFAULT_REQUEST_TIMEOUT_MS);
        assert_eq!(pending.created_at_ms, NOW_MS);
    }

    #[test]
    fn answer_validates_id_and_payload_bounds() {
        let mut bridge = consented();
        assert!(bridge.answer(RequestId(0), b"{}".to_vec(), false).is_err());
        let big = vec![0u8; bitty_ipc_api::frame::MAX_FRAME_BYTES + 1];
        assert!(bridge.answer(RequestId(7), big, false).is_err());
        assert_eq!(bridge.pending_count(), 0);
    }

    #[test]
    fn answer_unknown_id_buffers_nothing_under_flood() {
        // Hostile: 64 unknown answers must not fill the 64-deep inbound
        // queue and deny service to a legitimate correlation.
        let mut bridge = consented();
        for i in 0..64u64 {
            let unknown = RequestId(900_000 + i);
            assert!(
                !bridge
                    .answer(unknown, b"{}".to_vec(), false)
                    .expect("unknown answer fits")
            );
        }
        assert!(
            bridge.take_response().is_none(),
            "unknown ids must buffer nothing"
        );
        let id = bridge
            .call("terminal.snapshot", b"{}".to_vec(), NOW_MS)
            .unwrap();
        assert!(bridge.answer(id, b"ok".to_vec(), false).unwrap());
        assert!(bridge.take_response().is_some());
    }

    #[test]
    fn answer_double_delivery_does_not_buffer_twice() {
        let mut bridge = consented();
        let id = bridge
            .call("terminal.snapshot", b"{}".to_vec(), NOW_MS)
            .unwrap();
        assert!(bridge.answer(id, b"{}".to_vec(), false).unwrap());
        // Already completed: second delivery correlates to nothing and
        // must not consume inbound capacity.
        assert!(!bridge.answer(id, b"{}".to_vec(), false).unwrap());
        assert!(bridge.take_response().is_some());
        assert!(bridge.take_response().is_none());
    }

    #[test]
    fn take_response_drains_inbound_buffer() {
        let mut bridge = consented();
        let id = bridge
            .call("terminal.snapshot", b"{}".to_vec(), NOW_MS)
            .unwrap();
        assert!(bridge.answer(id, b"ok".to_vec(), false).unwrap());
        let response = bridge.take_response().expect("response buffered");
        assert_eq!(response.id, id);
        assert!(!response.is_error);
        assert!(bridge.take_response().is_none());
    }

    #[test]
    fn drain_expired_releases_deadline() {
        let mut bridge = consented();
        let id = bridge
            .call("terminal.snapshot", b"{}".to_vec(), NOW_MS)
            .unwrap();
        let expired = bridge.drain_expired(NOW_MS + DEFAULT_REQUEST_TIMEOUT_MS);
        assert_eq!(expired, vec![id]);
        assert_eq!(bridge.pending_count(), 0);
    }
}
