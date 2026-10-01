//! MCP client primitives — stdio transport stub, bounded framing, timeouts.
//!
//! This module provides headless, bounded MCP client primitives that reuse
//! the IPC framing and channel bounds. There is **no process spawn**, no
//! blocking I/O, no JSON-RPC library, and no plugin-code execution: the MCP
//! client is pure data + a bounded [`StdioTransportStub`] whose queues are
//! driven deterministically by the caller.
//!
//! Trust posture: every byte that arrives on the MCP stdio channel is
//! treated as **untrusted** per ADR-0003 and the threat-model boundary
//! "MCP or Agent client is untrusted automation". Payloads are size-checked
//! before any dispatch, request ids are validated, and deadlines are checked
//! from the caller-supplied `now_ms`, never from wall-clock time. The client
//! is read-only by default — `McpClientStub` exposes no filesystem,
//! clipboard, or process authority; elevation would be a future scoped service
//! call, never ambient.
//!
//! The wire encoding reuses [`crate::frame`] (length-prefixed 256 KiB frames).
//! Higher-level JSON-RPC method dispatch and capability negotiation belong to a
//! follow-up slice and remain draft (no normative spec yet).

use std::collections::BTreeMap;

use bitty_ipc_api::channel::{MAX_METHOD_BYTES, MAX_REQUEST_TIMEOUT_MS, RequestId};
use bitty_ipc_api::error::IpcError;
use bitty_ipc_api::frame::{Frame, MAX_FRAME_BYTES};
use bitty_ipc_core::transport::{DEFAULT_TRANSPORT_CAPACITY, StdioTransportStub};

// ── caps ────────────────────────────────────────────────────────────────────

/// Default MCP request timeout (milliseconds).
pub const DEFAULT_MCP_TIMEOUT_MS: u64 = 10_000;

/// Maximum pending MCP requests per client.
pub const MAX_MCP_PENDING: usize = 32;

/// Maximum bytes for an MCP notification payload.
///
/// Notifications have no response, but they still carry bounded bytes so a
/// malicious server cannot trigger unbounded buffering behind a notification
/// flood (T-01, invariant 7).
pub const MAX_MCP_NOTIFICATION_BYTES: usize = MAX_FRAME_BYTES;

// ── config ──────────────────────────────────────────────────────────────────

/// Owned configuration for an MCP stdio client stub.
///
/// All numeric bounds are checked at construction; values outside the allowed
/// ranges fail closed. The config is cloneable and owned (no `&str`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpClientConfig {
    /// Per-request deadline in milliseconds.
    pub request_timeout_ms: u64,
    /// Max pending requests.
    pub max_pending: usize,
    /// Outgoing/incoming transport capacity in frames (each payload `<= 256 KiB`).
    pub transport_capacity: usize,
}

impl Default for McpClientConfig {
    fn default() -> Self {
        Self {
            request_timeout_ms: DEFAULT_MCP_TIMEOUT_MS,
            max_pending: MAX_MCP_PENDING,
            transport_capacity: DEFAULT_TRANSPORT_CAPACITY,
        }
    }
}

impl McpClientConfig {
    /// Validate a config.
    ///
    /// # Errors
    ///
    /// - [`IpcError::InvalidRequest`] when `request_timeout_ms` is zero or above
    ///   `MAX_REQUEST_TIMEOUT_MS`.
    /// - [`IpcError::LimitExceeded`] when `max_pending` is zero or above
    ///   `MAX_MCP_PENDING`'s ceiling, or when `transport_capacity` is zero or
    ///   above `MAX_TRANSPORT_CAPACITY`.
    pub fn validated(self) -> Result<Self, IpcError> {
        if self.request_timeout_ms == 0 || self.request_timeout_ms > MAX_REQUEST_TIMEOUT_MS {
            return Err(IpcError::InvalidRequest {
                reason: format!(
                    "request_timeout_ms must be 1..={MAX_REQUEST_TIMEOUT_MS}, got {}",
                    self.request_timeout_ms
                ),
            });
        }
        if self.max_pending == 0 || self.max_pending > MAX_MCP_PENDING {
            return Err(IpcError::LimitExceeded {
                field: "max_pending".into(),
                limit: MAX_MCP_PENDING,
                actual: self.max_pending,
            });
        }
        if self.transport_capacity == 0
            || self.transport_capacity > bitty_ipc_core::transport::MAX_TRANSPORT_CAPACITY
        {
            return Err(IpcError::LimitExceeded {
                field: "transport_capacity".into(),
                limit: bitty_ipc_core::transport::MAX_TRANSPORT_CAPACITY,
                actual: self.transport_capacity,
            });
        }
        Ok(self)
    }
}

// ── message types ───────────────────────────────────────────────────────────

/// An outbound MCP request (JSON-RPC request object, stubbed).
///
/// The `params` bytes are opaque and bounded, representing a JSON object
/// without interpreting it. A real client would serialize `method` + `params` +
/// `id` as UTF-8 JSON; this stub validates bounds and correlation only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpRequest {
    /// Request identifier (non-zero).
    pub id: RequestId,
    /// Method name (e.g. `initialize`, `tools/list`).
    pub method: String,
    /// Bounded params payload (opaque, `<= MAX_FRAME_BYTES`).
    pub params: Vec<u8>,
    /// Timestamp when the request was issued.
    pub created_at_ms: u64,
    /// Deadline in milliseconds from `created_at_ms`.
    pub timeout_ms: u64,
}

impl McpRequest {
    /// Validate and create.
    pub fn new(
        id: RequestId,
        method: String,
        params: Vec<u8>,
        created_at_ms: u64,
        timeout_ms: u64,
    ) -> Result<Self, IpcError> {
        if id.is_zero() {
            return Err(IpcError::InvalidRequest {
                reason: "mcp request id must be non-zero".into(),
            });
        }
        validate_mcp_method(&method)?;
        if params.len() > MAX_FRAME_BYTES {
            return Err(IpcError::PayloadTooLarge {
                field: "mcp.params".into(),
                limit: MAX_FRAME_BYTES,
                actual: params.len(),
            });
        }
        if timeout_ms == 0 || timeout_ms > MAX_REQUEST_TIMEOUT_MS {
            return Err(IpcError::InvalidRequest {
                reason: format!(
                    "timeout_ms must be 1..={MAX_REQUEST_TIMEOUT_MS}, got {timeout_ms}"
                ),
            });
        }
        Ok(Self {
            id,
            method,
            params,
            created_at_ms,
            timeout_ms,
        })
    }

    /// Absolute deadline.
    #[must_use]
    pub fn deadline_ms(&self) -> u64 {
        self.created_at_ms.saturating_add(self.timeout_ms)
    }

    /// Whether `now_ms` is at or past the deadline.
    #[must_use]
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.deadline_ms()
    }
}

/// An inbound MCP response (success or error payload, stubbed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpResponse {
    /// Identifier echoing the request.
    pub id: RequestId,
    /// Bounded payload (opaque result/error).
    pub payload: Vec<u8>,
    /// Whether this response is an application-level error (e.g. JSON-RPC error object).
    pub is_error: bool,
}

impl McpResponse {
    /// Create a success response.
    pub fn success(id: RequestId, payload: Vec<u8>) -> Result<Self, IpcError> {
        Self::new(id, payload, false)
    }

    /// Create an error response.
    pub fn error(id: RequestId, payload: Vec<u8>) -> Result<Self, IpcError> {
        Self::new(id, payload, true)
    }

    fn new(id: RequestId, payload: Vec<u8>, is_error: bool) -> Result<Self, IpcError> {
        if id.is_zero() {
            return Err(IpcError::InvalidRequest {
                reason: "mcp response id must be non-zero".into(),
            });
        }
        if payload.len() > MAX_FRAME_BYTES {
            return Err(IpcError::PayloadTooLarge {
                field: "mcp.response".into(),
                limit: MAX_FRAME_BYTES,
                actual: payload.len(),
            });
        }
        Ok(Self {
            id,
            payload,
            is_error,
        })
    }
}

/// An inbound/outbound MCP notification (no id, no response expected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpNotification {
    /// Method name.
    pub method: String,
    /// Bounded payload.
    pub params: Vec<u8>,
}

impl McpNotification {
    /// Validate and create.
    pub fn new(method: String, params: Vec<u8>) -> Result<Self, IpcError> {
        validate_mcp_method(&method)?;
        if params.len() > MAX_MCP_NOTIFICATION_BYTES {
            return Err(IpcError::PayloadTooLarge {
                field: "mcp.notification".into(),
                limit: MAX_MCP_NOTIFICATION_BYTES,
                actual: params.len(),
            });
        }
        Ok(Self { method, params })
    }
}

fn validate_mcp_method(method: &str) -> Result<(), IpcError> {
    if method.is_empty() {
        return Err(IpcError::InvalidMethod {
            method: method.to_string(),
            reason: "mcp method must be non-empty".into(),
        });
    }
    if method.len() > MAX_METHOD_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "mcp.method".into(),
            limit: MAX_METHOD_BYTES,
            actual: method.len(),
        });
    }
    if method.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(IpcError::InvalidMethod {
            method: method.to_string(),
            reason: "mcp method must not contain control bytes".into(),
        });
    }
    if method
        .bytes()
        .any(|b| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r')
    {
        return Err(IpcError::InvalidMethod {
            method: method.to_string(),
            reason: "mcp method must not contain whitespace".into(),
        });
    }
    Ok(())
}

// ── client stub ─────────────────────────────────────────────────────────────

/// Headless MCP stdio client stub.
///
/// The client owns a bounded [`StdioTransportStub`] and a bounded pending-
/// request table. All operations are synchronous and deterministic from
/// caller-supplied `now_ms`; there is no thread, no async runtime, and no
/// OS handle. Tests simulate the server by injecting frames or moving them
/// between two stubs (see [`StdioTransportStub::forward_to`]).
///
/// # Example
///
/// ```rust
/// use bitty_ipc_mcp::mcp::{McpClientConfig, McpClientStub};
/// use bitty_ipc_core::transport::StdioTransportStub;
///
/// let mut client = McpClientStub::new(McpClientConfig::default()).expect("valid config");
/// let now = 0;
/// let id = client.send_request("initialize".into(), br#"{"client":"bitty"}"#.to_vec(), now).expect("send");
/// assert_eq!(client.pending_count(), 1);
/// assert!(!client.is_closed());
///
/// // Simulate a server response arriving as a frame payload.
/// let mut server = StdioTransportStub::new(8);
/// client.transport_mut().forward_to(&mut server);
/// // ... server would handle and reply, then reply frames flow back ...
/// ```
#[derive(Debug)]
pub struct McpClientStub {
    config: McpClientConfig,
    transport: StdioTransportStub,
    pending: BTreeMap<u64, McpRequest>,
    next_id: u64,
    closed: bool,
}

impl McpClientStub {
    /// Create a client with `config`.
    ///
    /// # Errors
    ///
    /// Returns any validation error from [`McpClientConfig::validated`].
    pub fn new(config: McpClientConfig) -> Result<Self, IpcError> {
        let config = config.validated()?;
        let transport = StdioTransportStub::new(config.transport_capacity);
        Ok(Self {
            config,
            transport,
            pending: BTreeMap::new(),
            next_id: 1,
            closed: false,
        })
    }

    /// Configuration (owned clone).
    #[must_use]
    pub fn config(&self) -> &McpClientConfig {
        &self.config
    }

    /// Borrow the transport (read-only, headless harness).
    #[must_use]
    pub fn transport(&self) -> &StdioTransportStub {
        &self.transport
    }

    /// Borrow the transport mutably (harness may move frames between peers).
    #[must_use]
    pub fn transport_mut(&mut self) -> &mut StdioTransportStub {
        &mut self.transport
    }

    /// Whether the client has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed || self.transport.is_closed()
    }

    /// Close the client. Subsequent sends fail with [`IpcError::TransportClosed`].
    pub fn close(&mut self) {
        self.closed = true;
        self.transport.close();
    }

    /// Number of pending requests.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Whether any requests are pending.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Allocate the next non-zero [`RequestId`].
    pub fn next_request_id(&mut self) -> RequestId {
        let id = RequestId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        if self.next_id == 0 {
            self.next_id = 1;
        }
        id
    }

    /// Send a request toward the MCP server.
    ///
    /// The request is validated, framed (256 KiB bound checked), enqueued to
    /// the outgoing transport queue, and tracked in the pending table for
    /// timeout checks. The method does not block.
    ///
    /// # Errors
    ///
    /// - [`IpcError::TransportClosed`] when the client is closed.
    /// - [`IpcError::PendingLimitExceeded`] when already at `max_pending`.
    /// - [`IpcError::TransportFull`] when the outgoing queue is at capacity.
    /// - [`IpcError::FrameTooLarge`] / [`IpcError::PayloadTooLarge`] /
    ///   [`IpcError::InvalidMethod`] for validation failures.
    pub fn send_request(
        &mut self,
        method: String,
        params: Vec<u8>,
        now_ms: u64,
    ) -> Result<RequestId, IpcError> {
        if self.is_closed() {
            return Err(IpcError::TransportClosed {
                reason: "mcp client is closed".into(),
            });
        }
        if self.pending.len() >= self.config.max_pending {
            return Err(IpcError::PendingLimitExceeded {
                limit: self.config.max_pending,
                actual: self.pending.len() + 1,
            });
        }
        let id = self.next_request_id();
        let req = McpRequest::new(id, method, params, now_ms, self.config.request_timeout_ms)?;

        // Encode the request as one frame payload for the harness. The real
        // wire would be `{"jsonrpc":"2.0","id":…, "method":…, "params":…}` as
        // UTF-8 JSON, but for boundedness verification we treat the
        // method+params as the payload and keep framing validation strict.
        // Tests verify the frame roundtrips and that the 256 KiB bound holds.
        let payload = mcp_request_wire_payload(&req);
        if payload.len() > MAX_FRAME_BYTES {
            return Err(IpcError::FrameTooLarge {
                actual: payload.len(),
                limit: MAX_FRAME_BYTES,
            });
        }
        let frame = Frame::new(payload)?;
        self.transport.try_send_frame(frame)?;
        self.pending.insert(id.0, req);
        Ok(id)
    }

    /// Send a notification (no id, no pending tracking).
    ///
    /// Notifications still obey the 256 KiB bound and transport capacity.
    pub fn send_notification(&mut self, notification: McpNotification) -> Result<(), IpcError> {
        if self.is_closed() {
            return Err(IpcError::TransportClosed {
                reason: "mcp client is closed".into(),
            });
        }
        let payload = mcp_notification_wire_payload(&notification);
        if payload.len() > MAX_FRAME_BYTES {
            return Err(IpcError::FrameTooLarge {
                actual: payload.len(),
                limit: MAX_FRAME_BYTES,
            });
        }
        let frame = Frame::new(payload)?;
        self.transport.try_send_frame(frame)
    }

    /// Inject a server response frame as if it arrived on stdin.
    ///
    /// Headless helper: encodes `response` as one frame payload and injects it
    /// into the incoming queue, simulating the server stdio reply.
    pub fn inject_response(&mut self, response: McpResponse) -> Result<(), IpcError> {
        if self.is_closed() {
            return Err(IpcError::TransportClosed {
                reason: "mcp client is closed".into(),
            });
        }
        let payload = mcp_response_wire_payload(&response);
        let frame = Frame::new(payload)?;
        self.transport.inject_incoming(frame)
    }

    /// Inject a server notification / unsolicited message.
    ///
    /// Fail-closed like [`Self::inject_response`]: a closed client accepts
    /// no further inbound bytes, so a compromised peer cannot smuggle an
    /// instruction-bearing notification past shutdown (R-013).
    pub fn inject_notification(&mut self, notification: McpNotification) -> Result<(), IpcError> {
        if self.is_closed() {
            return Err(IpcError::TransportClosed {
                reason: "mcp client is closed".into(),
            });
        }
        let payload = mcp_notification_wire_payload(&notification);
        let frame = Frame::new(payload)?;
        self.transport.inject_incoming(frame)
    }

    /// Poll and decode all incoming frames into stub responses.
    ///
    /// The payload encoding here is intentionally trivial and headless-
    /// testable: the wire helpers preserve `id` and `is_error` in a fixed
    /// header so the stub can correlate. A real JSON-RPC parser would belong
    /// to a follow-up slice; this layer proves boundedness, timeouts, and
    /// correlation without claiming normative wire compatibility.
    pub fn poll_responses(&mut self) -> Vec<McpResponse> {
        let frames = self.transport.drain_incoming();
        let mut out = Vec::new();
        for frame in frames {
            if let Some(resp) = decode_response_frame(frame.payload()) {
                // Correlate: only surface responses whose id matches a pending request,
                // and remove from pending. Unknown ids are dropped (peer is untrusted).
                if self.pending.contains_key(&resp.id.0) {
                    self.pending.remove(&resp.id.0);
                    out.push(resp);
                }
            }
        }
        out
    }

    /// Return ids whose deadlines are at or past `now_ms`, removing them from
    /// the pending table. Deadline check is deterministic via caller-supplied
    /// `now_ms`, never via `Instant`.
    pub fn drain_expired(&mut self, now_ms: u64) -> Vec<RequestId> {
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter_map(|(&id, req)| {
                if req.is_expired(now_ms) {
                    Some(id)
                } else {
                    None
                }
            })
            .collect();
        for id in &expired {
            self.pending.remove(id);
        }
        expired.into_iter().map(RequestId).collect()
    }

    /// Peek at a pending request without removing it.
    #[must_use]
    pub fn peek_pending(&self, id: RequestId) -> Option<&McpRequest> {
        self.pending.get(&id.0)
    }

    /// Drain pending count helper for harness assertions.
    #[must_use]
    pub fn pending_ids(&self) -> Vec<RequestId> {
        self.pending.keys().copied().map(RequestId).collect()
    }
}

// ── trivial wire helpers (headless, not normative) ──────────────────────────

fn mcp_request_wire_payload(req: &McpRequest) -> Vec<u8> {
    // Format: "MCP_REQ:<id>:<method>:<params_len>:<params>"
    // This is not normative JSON-RPC; it preserves correlation and bounds for
    // headless tests without claiming wire compatibility. A future slice that
    // adopts real JSON serialization will replace these helpers and keep the
    // 256 KiB bound check in the same place.
    let header = format!("MCP_REQ:{}:{}:{}:", req.id.0, req.method, req.params.len());
    let mut out = Vec::with_capacity(header.len() + req.params.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(&req.params);
    out
}

fn mcp_response_wire_payload(resp: &McpResponse) -> Vec<u8> {
    // Format: "MCP_RESP:<id>:<is_error as 0/1>:<payload_len>:<payload>"
    let header = format!(
        "MCP_RESP:{}:{}:{}:",
        resp.id.0,
        if resp.is_error { 1 } else { 0 },
        resp.payload.len()
    );
    let mut out = Vec::with_capacity(header.len() + resp.payload.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(&resp.payload);
    out
}

fn mcp_notification_wire_payload(notif: &McpNotification) -> Vec<u8> {
    let header = format!("MCP_NOTIF:{}:{}:", notif.method, notif.params.len());
    let mut out = Vec::with_capacity(header.len() + notif.params.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(&notif.params);
    out
}

fn decode_response_frame(payload: &[u8]) -> Option<McpResponse> {
    // Mirror of mcp_response_wire_payload for headless correlation.
    // Expects "MCP_RESP:<id>:<is_error>:<len>:<payload>"
    let s = std::str::from_utf8(payload).ok()?;
    if !s.starts_with("MCP_RESP:") {
        return None;
    }
    let rest = &s["MCP_RESP:".len()..];
    let (id_str, rest) = rest.split_once(':')?;
    let (err_str, rest) = rest.split_once(':')?;
    let (len_str, rest) = rest.split_once(':')?;
    let id: u64 = id_str.parse().ok()?;
    if id == 0 {
        return None;
    }
    let is_error = match err_str {
        "0" => false,
        "1" => true,
        _ => return None,
    };
    let len: usize = len_str.parse().ok()?;
    if rest.len() < len {
        return None;
    }
    // For our harness the payload length in header must match actual tail length
    // (no extra tail beyond len is allowed for determinism).
    if rest.len() != len {
        // Allow exact match only; extra would be truncated in real framer.
        return None;
    }
    let payload = rest.as_bytes()[..len].to_vec();
    // Reuse validation: payload len already checked by caller framing bound.
    McpResponse::new(RequestId(id), payload, is_error).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> McpClientConfig {
        McpClientConfig::default()
    }

    #[test]
    fn config_validation() {
        assert!(
            McpClientConfig {
                request_timeout_ms: 0,
                ..cfg()
            }
            .validated()
            .is_err()
        );
        assert!(
            McpClientConfig {
                max_pending: 0,
                ..cfg()
            }
            .validated()
            .is_err()
        );
        assert!(
            McpClientConfig {
                transport_capacity: 0,
                ..cfg()
            }
            .validated()
            .is_err()
        );
        assert!(cfg().validated().is_ok());
    }

    #[test]
    fn send_and_correlate_response() {
        let mut client = McpClientStub::new(cfg()).unwrap();
        let id = client
            .send_request("initialize".into(), b"{}".to_vec(), 0)
            .unwrap();
        assert_eq!(client.pending_count(), 1);
        // Simulate server reply.
        client
            .inject_response(McpResponse::success(id, b"ok".to_vec()).unwrap())
            .unwrap();
        let responses = client.poll_responses();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].id, id);
        assert!(!responses[0].is_error);
        assert_eq!(client.pending_count(), 0);
    }

    #[test]
    fn unknown_response_id_is_dropped() {
        let mut client = McpClientStub::new(cfg()).unwrap();
        let _id = client.send_request("tools/list".into(), vec![], 0).unwrap();
        // Inject response with unknown id (untrusted peer).
        client
            .inject_response(McpResponse::success(RequestId(999), b"evil".to_vec()).unwrap())
            .unwrap();
        let responses = client.poll_responses();
        assert!(responses.is_empty(), "unknown id must be dropped");
        assert_eq!(client.pending_count(), 1);
    }

    #[test]
    fn pending_cap_enforced() {
        let mut client = McpClientStub::new(McpClientConfig {
            max_pending: 2,
            ..cfg()
        })
        .unwrap();
        client.send_request("a".into(), vec![], 0).unwrap();
        client.send_request("b".into(), vec![], 0).unwrap();
        let err = client.send_request("c".into(), vec![], 0).unwrap_err();
        assert!(matches!(err, IpcError::PendingLimitExceeded { .. }));
    }

    #[test]
    fn timeout_evicts_pending() {
        let mut client = McpClientStub::new(McpClientConfig {
            request_timeout_ms: 1000,
            ..cfg()
        })
        .unwrap();
        let id = client.send_request("slow".into(), vec![], 0).unwrap();
        // Not yet expired at 999.
        assert!(client.drain_expired(999).is_empty());
        assert_eq!(client.pending_count(), 1);
        // Expires at 1000.
        let expired = client.drain_expired(1000);
        assert_eq!(expired, vec![id]);
        assert_eq!(client.pending_count(), 0);
        // Late response for expired id is dropped.
        client
            .inject_response(McpResponse::success(id, b"late".to_vec()).unwrap())
            .unwrap();
        let responses = client.poll_responses();
        assert!(responses.is_empty());
    }

    #[test]
    fn transport_full_fails_closed() {
        let mut client = McpClientStub::new(McpClientConfig {
            transport_capacity: 1,
            ..cfg()
        })
        .unwrap();
        client.send_request("m1".into(), vec![], 0).unwrap();
        let err = client.send_request("m2".into(), vec![], 0).unwrap_err();
        assert!(matches!(err, IpcError::TransportFull { .. }));
        // Pending was not inserted for failed send.
        assert_eq!(client.pending_count(), 1);
    }

    #[test]
    fn closed_rejects_sends() {
        let mut client = McpClientStub::new(cfg()).unwrap();
        client.close();
        assert!(client.is_closed());
        let err = client.send_request("x".into(), vec![], 0).unwrap_err();
        assert!(matches!(err, IpcError::TransportClosed { .. }));
        // Inbound injection closes too: no notification smuggling past shutdown.
        let notif = McpNotification::new("event".into(), b"data".to_vec()).unwrap();
        assert!(matches!(
            client.send_notification(notif.clone()).unwrap_err(),
            IpcError::TransportClosed { .. }
        ));
        let resp = McpResponse::success(RequestId(1), b"hi".to_vec()).unwrap();
        assert!(matches!(
            client.inject_response(resp).unwrap_err(),
            IpcError::TransportClosed { .. }
        ));
        assert!(matches!(
            client.inject_notification(notif).unwrap_err(),
            IpcError::TransportClosed { .. }
        ));
    }

    #[test]
    fn method_validation() {
        let mut client = McpClientStub::new(cfg()).unwrap();
        assert!(client.send_request("".into(), vec![], 0).is_err());
        let long = "x".repeat(MAX_METHOD_BYTES + 1);
        assert!(client.send_request(long, vec![], 0).is_err());
        assert!(client.send_request("bad method".into(), vec![], 0).is_err());
    }

    #[test]
    fn payload_bound_enforced() {
        let mut client = McpClientStub::new(cfg()).unwrap();
        let large = vec![0u8; MAX_FRAME_BYTES + 1];
        let err = client.send_request("m".into(), large, 0).unwrap_err();
        assert!(matches!(err, IpcError::PayloadTooLarge { .. }));
    }

    #[test]
    fn notification_send_and_inject_headless() {
        let mut client = McpClientStub::new(cfg()).unwrap();
        client
            .send_notification(McpNotification::new("notify".into(), b"hi".to_vec()).unwrap())
            .unwrap();
        assert_eq!(client.transport().outgoing_len(), 1);
        // Inject incoming notification.
        client
            .inject_notification(McpNotification::new("event".into(), b"data".to_vec()).unwrap())
            .unwrap();
        assert_eq!(client.transport().incoming_len(), 1);
    }

    #[test]
    fn pending_ids_and_peek() {
        let mut client = McpClientStub::new(cfg()).unwrap();
        let id = client.send_request("m".into(), b"p".to_vec(), 42).unwrap();
        assert!(client.peek_pending(id).is_some());
        assert!(client.peek_pending(RequestId(999)).is_none());
        assert_eq!(client.pending_ids(), vec![id]);
    }

    #[test]
    fn mcp_request_deadline() {
        let req = McpRequest::new(RequestId(1), "m".into(), vec![], 100, 500).unwrap();
        assert_eq!(req.deadline_ms(), 600);
        assert!(!req.is_expired(599));
        assert!(req.is_expired(600));
    }
}
