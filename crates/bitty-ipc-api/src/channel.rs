//! Bounded IPC channels with request/response caps and deadlines.
//!
//! The channel layer turns framed bytes into owned request/response values.
//! Every queue is bounded so a malicious peer cannot grow memory without
//! limit (T-01, RC-9). Timeouts are checked deterministically from a caller
//! supplied `now_ms` rather than from the wall clock, so all behavior is
//! headless-testable (`std::time::Instant` never appears in the public API).
//!
//! Trust posture: every inbound `IpcRequest` is treated as originating from an
//! **untrusted IPC/MCP client** per ADR-0003 and the threat-model boundary
//! "IPC client is untrusted until authenticated". Method names, payload sizes,
//! queue depths, and pending-request counts are validated before any dispatch.
//! There is no file I/O, no process spawn, and no plugin-code execution on this
//! path — this crate is pure data + bounded queues.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use crate::error::IpcError;
use crate::frame::MAX_FRAME_BYTES;

// ── caps ────────────────────────────────────────────────────────────────────

/// Default depth for the request direction.
pub const DEFAULT_REQUEST_CAPACITY: usize = 64;

/// Default depth for the response direction.
pub const DEFAULT_RESPONSE_CAPACITY: usize = 64;

/// Maximum depth any single IPC queue may be configured with.
///
/// The cap follows the candidate ceiling `RC-9` (16 concurrent connections
/// default) and keeps the headless harness deterministic: capacities above
/// this are rejected at construction.
pub const MAX_CHANNEL_CAPACITY: usize = 256;

/// Maximum number of in-flight requests tracked per endpoint.
pub const MAX_PENDING_REQUESTS: usize = 64;

/// Maximum bytes for an IPC method name (UTF-8, no interior NUL/control).
pub const MAX_METHOD_BYTES: usize = 128;

/// Default request deadline (milliseconds) when none is supplied explicitly.
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 5_000;

/// Hard ceiling for any per-request deadline.
///
/// Prevents a client from pinning resources indefinitely with an enormous
/// timeout. Values above this are clamped or rejected at construction.
pub const MAX_REQUEST_TIMEOUT_MS: u64 = 30_000;

// ── identities ──────────────────────────────────────────────────────────────

/// Monotonic request identifier.
///
/// Identifiers are allocated by the endpoint that sends the request; the peer
/// echoes the identifier in the response. Zero is never allocated (reserved
/// for "no id" / notifications).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(pub u64);

impl RequestId {
    /// Whether this identifier is the reserved zero value.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── request / response ─────────────────────────────────────────────────────

/// An owned IPC request.
///
/// The payload (`params`) is opaque bounded bytes; the channel does not
/// interpret JSON-RPC, CLI grammar, or MCP semantics — it enforces size,
/// method-name, and deadline bounds only. Callers that need structured params
/// validate them one layer above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcRequest {
    /// Request identifier (non-zero).
    pub id: RequestId,
    /// Method name (e.g. `terminal.text`, `mcp.initialize`).
    pub method: String,
    /// Bounded params bytes (opaque, `<= MAX_FRAME_BYTES`).
    pub params: Vec<u8>,
    /// Monotonic timestamp (milliseconds) when the request was created.
    pub created_at_ms: u64,
    /// Deadline in milliseconds from `created_at_ms`.
    pub timeout_ms: u64,
}

impl IpcRequest {
    /// Validate and create a new request.
    ///
    /// # Errors
    ///
    /// - [`IpcError::InvalidMethod`] when `method` is empty, exceeds
    ///   `MAX_METHOD_BYTES`, or contains control bytes (`0x00..0x1F` or `0x7F`),
    ///   or interior whitespace that would confuse the candidate CLI grammar.
    /// - [`IpcError::PayloadTooLarge`] when `params.len() > MAX_FRAME_BYTES`.
    /// - [`IpcError::InvalidRequest`] when `id` is zero or `timeout_ms` is zero
    ///   or exceeds `MAX_REQUEST_TIMEOUT_MS`.
    pub fn new(
        id: RequestId,
        method: String,
        params: Vec<u8>,
        created_at_ms: u64,
        timeout_ms: u64,
    ) -> Result<Self, IpcError> {
        if id.is_zero() {
            return Err(IpcError::InvalidRequest {
                reason: "request id must be non-zero".into(),
            });
        }
        validate_method(&method)?;
        if params.len() > MAX_FRAME_BYTES {
            return Err(IpcError::PayloadTooLarge {
                field: "params".into(),
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

    /// Deadline as absolute `ms`: `created_at_ms + timeout_ms`.
    #[must_use]
    pub fn deadline_ms(&self) -> u64 {
        self.created_at_ms.saturating_add(self.timeout_ms)
    }

    /// Whether `now_ms` is at or past the deadline.
    #[must_use]
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.deadline_ms()
    }

    /// Remaining milliseconds until deadline, saturating to zero when expired.
    #[must_use]
    pub fn remaining_ms(&self, now_ms: u64) -> u64 {
        self.deadline_ms().saturating_sub(now_ms)
    }

    /// Payload length in bytes.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.params.len()
    }
}

/// An owned IPC response (success or typed error payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcResponse {
    /// Identifier that matches the originating request.
    pub id: RequestId,
    /// Bounded response payload (opaque).
    pub payload: Vec<u8>,
    /// Whether this response represents an application-level error.
    ///
    /// Transport failures are represented as `Err(IpcError)` one layer above;
    /// this flag distinguishes "the peer answered with an error payload" from
    /// "the channel/transport failed".
    pub is_error: bool,
}

impl IpcResponse {
    /// Create a success response.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::PayloadTooLarge`] when `payload.len() > MAX_FRAME_BYTES`.
    /// Returns [`IpcError::InvalidRequest`] when `id` is zero.
    pub fn success(id: RequestId, payload: Vec<u8>) -> Result<Self, IpcError> {
        Self::new(id, payload, false)
    }

    /// Create an error response.
    ///
    /// The `payload` should carry a bounded, owned error description (never
    /// a backtrace or secret-bearing dump).
    pub fn error(id: RequestId, payload: Vec<u8>) -> Result<Self, IpcError> {
        Self::new(id, payload, true)
    }

    fn new(id: RequestId, payload: Vec<u8>, is_error: bool) -> Result<Self, IpcError> {
        if id.is_zero() {
            return Err(IpcError::InvalidRequest {
                reason: "response id must be non-zero".into(),
            });
        }
        if payload.len() > MAX_FRAME_BYTES {
            return Err(IpcError::PayloadTooLarge {
                field: "response.payload".into(),
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

    /// Payload length.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }
}

fn validate_method(method: &str) -> Result<(), IpcError> {
    if method.is_empty() {
        return Err(IpcError::InvalidMethod {
            method: method.to_string(),
            reason: "method must be non-empty".into(),
        });
    }
    if method.len() > MAX_METHOD_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "method".into(),
            limit: MAX_METHOD_BYTES,
            actual: method.len(),
        });
    }
    if method.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(IpcError::InvalidMethod {
            method: method.to_string(),
            reason: "method must not contain control bytes".into(),
        });
    }
    if method
        .bytes()
        .any(|b| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r')
    {
        return Err(IpcError::InvalidMethod {
            method: method.to_string(),
            reason: "method must not contain whitespace".into(),
        });
    }
    // RFC wire: segments match ^[a-z][a-z0-9_]*$ separated by '.'.
    // Rejects empty segments, leading/trailing/double dots, and
    // non-lowercase/upper/digit/_ characters. This mirrors the scope crate
    // validation to keep the channel fail-closed on untrusted method strings
    // without depending on the scope module at compile time (avoids cycle).
    if method.starts_with('.') || method.ends_with('.') || method.contains("..") {
        return Err(IpcError::InvalidMethod {
            method: method.to_string(),
            reason: "method must not have empty segment (no leading/trailing/double dot)".into(),
        });
    }
    for seg in method.split('.') {
        if seg.is_empty() {
            return Err(IpcError::InvalidMethod {
                method: method.to_string(),
                reason: "method segment must be non-empty".into(),
            });
        }
        let mut chars = seg.bytes();
        let first = chars.next().unwrap();
        if !first.is_ascii_lowercase() {
            return Err(IpcError::InvalidMethod {
                method: method.to_string(),
                reason: "method segment must start with [a-z]".into(),
            });
        }
        for b in chars {
            let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_';
            if !ok {
                return Err(IpcError::InvalidMethod {
                    method: method.to_string(),
                    reason: "method segment must match ^[a-z][a-z0-9_]*$".into(),
                });
            }
        }
    }
    Ok(())
}

// ── generic bounded channel ─────────────────────────────────────────────────

/// A bounded FIFO queue for any owned IPC value.
///
/// The queue is strictly bounded. [`BoundedChannel::try_send`] fails closed
/// when at capacity; [`BoundedChannel::send_drop_oldest`] evicts the oldest
/// entry and is available only where loss is explicitly acceptable (e.g.
/// untrusted observation streams, not request/response). Callers choose the
/// policy — there is no implicit dropping.
#[derive(Debug)]
pub struct BoundedChannel<T> {
    inner: VecDeque<T>,
    capacity: usize,
    dropped: u64,
}

impl<T> BoundedChannel<T> {
    /// Create a queue with `capacity` entries.
    ///
    /// # Panics
    ///
    /// Panics when `capacity == 0` or `capacity > MAX_CHANNEL_CAPACITY`.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "channel capacity must be > 0");
        assert!(
            capacity <= MAX_CHANNEL_CAPACITY,
            "channel capacity {capacity} exceeds MAX_CHANNEL_CAPACITY {MAX_CHANNEL_CAPACITY}"
        );
        Self {
            inner: VecDeque::with_capacity(capacity),
            capacity,
            dropped: 0,
        }
    }

    /// Capacity of this queue.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of queued entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether no entry is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Number of entries dropped via `send_drop_oldest` since creation or last `clear`.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Try to enqueue `item`; refuse when at capacity.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::ChannelFull`] when the queue already holds `capacity`
    /// entries. No drop occurs — the refusal is total.
    pub fn try_send(&mut self, item: T) -> Result<(), IpcError> {
        if self.inner.len() >= self.capacity {
            return Err(IpcError::ChannelFull {
                capacity: self.capacity,
            });
        }
        self.inner.push_back(item);
        Ok(())
    }

    /// Enqueue `item`, evicting the oldest entry when at capacity.
    ///
    /// The dropped counter increments. Use only where loss is explicitly
    /// acceptable and attributed (e.g. untrusted observation fans, not
    /// request/response acknowledgement).
    pub fn send_drop_oldest(&mut self, item: T) {
        if self.inner.len() >= self.capacity {
            self.inner.pop_front();
            self.dropped = self.dropped.wrapping_add(1);
        }
        self.inner.push_back(item);
    }

    /// Pop the oldest entry, if any.
    pub fn recv(&mut self) -> Option<T> {
        self.inner.pop_front()
    }

    /// Drain all queued entries in FIFO order.
    pub fn drain(&mut self) -> Vec<T> {
        self.inner.drain(..).collect()
    }

    /// Drain up to `limit` entries in FIFO order.
    pub fn drain_bounded(&mut self, limit: usize) -> Vec<T> {
        let take = limit.min(self.inner.len());
        self.inner.drain(..take).collect()
    }

    /// Retain only the entries for which `pred` returns `true`, preserving
    /// order. Used by timeout reaping to drop expired queued requests so
    /// they can never be handed over for execution after their deadline.
    /// The `dropped` counter is untouched: expirations are reported by the
    /// reaper's return value, not conflated with eviction attribution.
    pub fn retain(&mut self, mut pred: impl FnMut(&T) -> bool) {
        self.inner.retain(|item| pred(item));
    }

    /// Peek at the oldest entry without consuming.
    #[must_use]
    pub fn peek(&self) -> Option<&T> {
        self.inner.front()
    }

    /// Iterate queued entries in order without consuming.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.inner.iter()
    }

    /// Clear queued entries and reset the dropped counter.
    pub fn clear(&mut self) {
        self.inner.clear();
        self.dropped = 0;
    }
}

// ── endpoint: pending tracker + request/response pair ───────────────────────

/// Headless IPC endpoint owning a request channel, a response channel, and a
/// bounded pending-request table with deterministic timeout checks.
///
/// The endpoint never spawns a thread or a process; it is pure data + bounded
/// queues so headless tests drive it without IPC endpoints or pipes. A real
/// transport would move bytes between two endpoints' framers; tests simulate
/// that by moving `IpcRequest`/`IpcResponse` values directly or via the
/// transport stub.
#[derive(Debug)]
pub struct IpcEndpoint {
    requests: BoundedChannel<IpcRequest>,
    responses: BoundedChannel<IpcResponse>,
    pending: BTreeMap<u64, IpcRequest>,
    next_id: u64,
}

impl IpcEndpoint {
    /// Create an endpoint with explicit capacities.
    ///
    /// # Panics
    ///
    /// Panics when either capacity is zero or exceeds `MAX_CHANNEL_CAPACITY`.
    pub fn with_capacity(request_capacity: usize, response_capacity: usize) -> Self {
        Self {
            requests: BoundedChannel::new(request_capacity),
            responses: BoundedChannel::new(response_capacity),
            pending: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Create with the default caps (`DEFAULT_REQUEST_CAPACITY` / `DEFAULT_RESPONSE_CAPACITY`).
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_REQUEST_CAPACITY, DEFAULT_RESPONSE_CAPACITY)
    }

    /// Allocate the next non-zero [`RequestId`], wrapping past `u64::MAX` back to 1.
    pub fn next_request_id(&mut self) -> RequestId {
        let id = RequestId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        if self.next_id == 0 {
            self.next_id = 1;
        }
        id
    }

    /// Number of requests currently pending a response.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Whether any requests are pending.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Request queue length.
    #[must_use]
    pub fn request_len(&self) -> usize {
        self.requests.len()
    }

    /// Response queue length.
    #[must_use]
    pub fn response_len(&self) -> usize {
        self.responses.len()
    }

    /// Send a request: validate pending cap, enqueue to the request channel,
    /// and track it in the pending table for timeout checks.
    ///
    /// # Errors
    ///
    /// - [`IpcError::PendingLimitExceeded`] when already tracking `MAX_PENDING_REQUESTS`.
    /// - [`IpcError::ChannelFull`] when the request queue is at capacity.
    /// - Any validation error from [`IpcRequest::new`].
    pub fn send_request(&mut self, request: IpcRequest) -> Result<(), IpcError> {
        if self.pending.len() >= MAX_PENDING_REQUESTS {
            return Err(IpcError::PendingLimitExceeded {
                limit: MAX_PENDING_REQUESTS,
                actual: self.pending.len() + 1,
            });
        }
        if self.pending.contains_key(&request.id.0) {
            return Err(IpcError::InvalidRequest {
                reason: format!("duplicate pending id {}", request.id.0),
            });
        }
        self.requests.try_send(request.clone())?;
        self.pending.insert(request.id.0, request);
        Ok(())
    }

    /// Convenience: allocate an id, validate, and send in one call.
    pub fn create_request(
        &mut self,
        method: String,
        params: Vec<u8>,
        created_at_ms: u64,
        timeout_ms: u64,
    ) -> Result<RequestId, IpcError> {
        let id = self.next_request_id();
        let req = IpcRequest::new(id, method, params, created_at_ms, timeout_ms)?;
        self.send_request(req)?;
        Ok(id)
    }

    /// Receive the oldest enqueued request, if any.
    pub fn recv_request(&mut self) -> Option<IpcRequest> {
        self.requests.recv()
    }

    /// Send a response. Responses are not tracked as pending; they are
    /// correlation-checked by the receiver.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::ChannelFull`] when the response queue is at capacity.
    pub fn send_response(&mut self, response: IpcResponse) -> Result<(), IpcError> {
        self.responses.try_send(response)
    }

    /// Receive the oldest enqueued response, if any.
    pub fn recv_response(&mut self) -> Option<IpcResponse> {
        self.responses.recv()
    }

    /// Consume a response for `id` and remove it from the pending table.
    ///
    /// Returns `true` when a pending entry was found and removed, meaning the
    /// response correlates to a known in-flight request. Unknown ids return
    /// `false` without insertion.
    pub fn complete(&mut self, id: RequestId) -> bool {
        self.pending.remove(&id.0).is_some()
    }

    /// Return ids whose deadlines are at or past `now_ms`, removing them from
    /// the pending table **and** from the not-yet-handed-over request queue.
    ///
    /// Queue removal is load-bearing: without it an expired request stays
    /// queued and a later `recv_request` would hand it over for execution
    /// after its deadline (exec-after-timeout). Deadline order is by
    /// insertion `request.id` order; callers must not rely on
    /// sorted-by-deadline output — they must check each id individually.
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
        if !expired.is_empty() {
            self.requests.retain(|req| !expired.contains(&req.id.0));
        }
        expired.into_iter().map(RequestId).collect()
    }

    /// Inspect a pending request without removing it.
    #[must_use]
    pub fn peek_pending(&self, id: RequestId) -> Option<&IpcRequest> {
        self.pending.get(&id.0)
    }

    /// Clear all queues and pending state (e.g. after transport reset).
    pub fn clear(&mut self) {
        self.requests.clear();
        self.responses.clear();
        self.pending.clear();
    }
}

impl Default for IpcEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_validation() {
        assert!(IpcRequest::new(RequestId(1), "".into(), vec![], 0, 1000).is_err());
        let long = "x".repeat(MAX_METHOD_BYTES + 1);
        assert!(IpcRequest::new(RequestId(1), long, vec![], 0, 1000).is_err());
        assert!(IpcRequest::new(RequestId(1), "bad method".into(), vec![], 0, 1000).is_err());
        assert!(IpcRequest::new(RequestId(1), "bad\x01method".into(), vec![], 0, 1000).is_err());
        assert!(IpcRequest::new(RequestId(1), "ok.method".into(), vec![], 0, 1000).is_ok());
        // RFC segment grammar: ^[a-z][a-z0-9_]*$ per dot segment
        assert!(IpcRequest::new(RequestId(1), "a:b/c".into(), vec![], 0, 1000).is_err());
        assert!(IpcRequest::new(RequestId(1), "terminal..text".into(), vec![], 0, 1000).is_err());
        assert!(IpcRequest::new(RequestId(1), "Terminal.text".into(), vec![], 0, 1000).is_err());
        assert!(IpcRequest::new(RequestId(1), ".leading".into(), vec![], 0, 1000).is_err());
        assert!(IpcRequest::new(RequestId(1), "trailing.".into(), vec![], 0, 1000).is_err());
    }

    #[test]
    fn payload_bound_enforced() {
        let large = vec![0u8; MAX_FRAME_BYTES + 1];
        let err = IpcRequest::new(RequestId(1), "m".into(), large, 0, 1000).unwrap_err();
        assert!(matches!(err, IpcError::PayloadTooLarge { .. }));
    }

    #[test]
    fn request_id_zero_rejected() {
        let err = IpcRequest::new(RequestId(0), "m".into(), vec![], 0, 1000).unwrap_err();
        assert!(matches!(err, IpcError::InvalidRequest { .. }));
    }

    #[test]
    fn timeout_zero_and_over_max_rejected() {
        assert!(IpcRequest::new(RequestId(1), "m".into(), vec![], 0, 0).is_err());
        assert!(
            IpcRequest::new(
                RequestId(1),
                "m".into(),
                vec![],
                0,
                MAX_REQUEST_TIMEOUT_MS + 1
            )
            .is_err()
        );
    }

    #[test]
    fn deadline_computation() {
        let r = IpcRequest::new(RequestId(1), "m".into(), vec![], 100, 1000).unwrap();
        assert_eq!(r.deadline_ms(), 1100);
        assert!(!r.is_expired(1099));
        assert!(r.is_expired(1100));
        assert_eq!(r.remaining_ms(1099), 1);
        assert_eq!(r.remaining_ms(2000), 0);
    }

    #[test]
    fn bounded_channel_try_send_fails_when_full() {
        let mut ch: BoundedChannel<u32> = BoundedChannel::new(2);
        ch.try_send(1).unwrap();
        ch.try_send(2).unwrap();
        let err = ch.try_send(3).unwrap_err();
        assert!(matches!(err, IpcError::ChannelFull { capacity: 2 }));
        assert_eq!(ch.len(), 2);
    }

    #[test]
    fn bounded_channel_drop_oldest_evicts() {
        let mut ch: BoundedChannel<u32> = BoundedChannel::new(2);
        ch.try_send(1).unwrap();
        ch.try_send(2).unwrap();
        ch.send_drop_oldest(3);
        assert_eq!(ch.dropped(), 1);
        let drained = ch.drain();
        assert_eq!(drained, vec![2, 3]);
    }

    #[test]
    fn bounded_channel_drain_bounded() {
        let mut ch: BoundedChannel<u32> = BoundedChannel::new(8);
        for i in 0..5 {
            ch.try_send(i).unwrap();
        }
        let first = ch.drain_bounded(2);
        assert_eq!(first, vec![0, 1]);
        assert_eq!(ch.len(), 3);
    }

    #[test]
    fn endpoint_pending_and_timeout() {
        let mut ep = IpcEndpoint::with_capacity(8, 8);
        let now = 0;
        let id = ep.create_request("m".into(), vec![], now, 1000).unwrap();
        assert_eq!(ep.pending_count(), 1);
        assert_eq!(ep.request_len(), 1);

        // Not yet expired.
        assert!(ep.drain_expired(999).is_empty());
        assert_eq!(ep.pending_count(), 1);

        // Expires at 1000.
        let expired = ep.drain_expired(1000);
        assert_eq!(expired, vec![id]);
        assert_eq!(ep.pending_count(), 0);
    }

    #[test]
    fn drain_expired_removes_queued_requests_no_exec_after_timeout() {
        // Hostile: a request still queued (never handed over) must not be
        // executable after its deadline passes.
        let mut ep = IpcEndpoint::with_capacity(8, 8);
        let id = ep.create_request("m".into(), vec![], 0, 1000).unwrap();
        assert_eq!(ep.request_len(), 1);
        let expired = ep.drain_expired(1000);
        assert_eq!(expired, vec![id]);
        assert_eq!(ep.pending_count(), 0);
        assert_eq!(
            ep.request_len(),
            0,
            "expired request must not remain queued for execution"
        );
        assert!(
            ep.recv_request().is_none(),
            "no exec-after-timeout from the queue"
        );
    }

    #[test]
    fn drain_expired_keeps_live_queued_requests() {
        let mut ep = IpcEndpoint::with_capacity(8, 8);
        let _short = ep.create_request("a".into(), vec![], 0, 500).unwrap();
        let live = ep.create_request("b".into(), vec![], 0, 5000).unwrap();
        let expired = ep.drain_expired(1000);
        assert_eq!(expired.len(), 1);
        assert_eq!(ep.pending_count(), 1);
        assert_eq!(ep.request_len(), 1);
        let remaining = ep.recv_request().expect("live request survives");
        assert_eq!(remaining.id, live);
    }

    #[test]
    fn endpoint_complete_removes_pending() {
        let mut ep = IpcEndpoint::new();
        let id = ep.create_request("method".into(), vec![], 0, 5000).unwrap();
        assert!(ep.peek_pending(id).is_some());
        assert!(ep.complete(id));
        assert!(!ep.has_pending());
        // Unknown id returns false.
        assert!(!ep.complete(RequestId(999)));
    }

    #[test]
    fn endpoint_pending_cap_enforced() {
        let mut ep = IpcEndpoint::with_capacity(MAX_PENDING_REQUESTS + 8, 8);
        for i in 0..MAX_PENDING_REQUESTS {
            ep.create_request(format!("m{i}"), vec![], 0, 1000).unwrap();
        }
        let err = ep
            .create_request("overflow".into(), vec![], 0, 1000)
            .unwrap_err();
        assert!(matches!(err, IpcError::PendingLimitExceeded { .. }));
    }

    #[test]
    fn endpoint_request_channel_full_fails_closed() {
        let mut ep = IpcEndpoint::with_capacity(1, 8);
        ep.create_request("a".into(), vec![], 0, 1000).unwrap();
        let err = ep.create_request("b".into(), vec![], 0, 1000).unwrap_err();
        assert!(matches!(err, IpcError::ChannelFull { .. }));
        // Pending was not inserted for the failed send.
        assert_eq!(ep.pending_count(), 1);
    }

    #[test]
    fn endpoint_response_channel_bounded() {
        let mut ep = IpcEndpoint::with_capacity(8, 1);
        ep.send_response(IpcResponse::success(RequestId(1), b"ok".to_vec()).unwrap())
            .unwrap();
        let err = ep
            .send_response(IpcResponse::success(RequestId(2), b"ok".to_vec()).unwrap())
            .unwrap_err();
        assert!(matches!(err, IpcError::ChannelFull { .. }));
    }

    #[test]
    fn response_payload_bound() {
        let large = vec![0u8; MAX_FRAME_BYTES + 1];
        let err = IpcResponse::success(RequestId(1), large).unwrap_err();
        assert!(matches!(err, IpcError::PayloadTooLarge { .. }));
    }

    #[test]
    fn request_id_wraps_non_zero() {
        let mut ep = IpcEndpoint::new();
        ep.next_id = u64::MAX;
        let id = ep.next_request_id();
        assert_eq!(id.0, u64::MAX);
        let next = ep.next_request_id();
        assert_eq!(next.0, 1);
        assert!(!next.is_zero());
    }

    #[test]
    fn endpoint_clear_resets_all() {
        let mut ep = IpcEndpoint::new();
        ep.create_request("m".into(), vec![], 0, 1000).unwrap();
        ep.send_response(IpcResponse::success(RequestId(42), vec![]).unwrap())
            .unwrap();
        ep.clear();
        assert_eq!(ep.request_len(), 0);
        assert_eq!(ep.response_len(), 0);
        assert_eq!(ep.pending_count(), 0);
    }
}
