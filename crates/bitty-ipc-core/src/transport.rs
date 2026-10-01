//! Stdio transport stub for IPC and MCP.
//!
//! A real stdio transport would spawn a child process and bridge its `stdin`
//! / `stdout` pipes as length-prefixed frames. Process spawning, pipe
//! ownership, and peer-credential checks live outside this crate (the
//! isolation RFC and threat-model sections "IPC, CLI, and child processes").
//!
//! This module provides a **headless stub** that mimics the bounded,
//! asynchronous boundary without any OS handle: all data stays in owned
//! `VecDeque<Frame>` queues that are strictly bounded and deterministically
//! drained. Tests simulate both ends by moving frames between stubs or by
//! injecting bytes through the [`Framer`](bitty_ipc_api::frame::Framer).
//!
//! The stub satisfies the CTX-0031 contract clause "MCP client primitives
//! (stdio transport stub)" without performing process spawn or blocking I/O,
//! and it keeps the crate headless-testable on both Linux CI and the
//! `windows-latest` job.

use std::collections::VecDeque;

use bitty_ipc_api::error::IpcError;
use bitty_ipc_api::frame::{Frame, MAX_FRAME_BYTES};

/// Default per-direction frame capacity for the stub.
pub const DEFAULT_TRANSPORT_CAPACITY: usize = 64;

/// Maximum per-direction frame capacity allowed at construction.
pub const MAX_TRANSPORT_CAPACITY: usize = 256;

/// Bounded in-memory transport that mimics a stdio pipe pair.
///
/// Two queues represent the two directions:
///
/// - `outgoing`: frames the local side has sent toward the peer (to be read
///   by the peer's incoming queue in a headless harness).
/// - `incoming`: frames the local side has received from the peer.
///
/// No bytes are ever copied to an OS handle. The stub is headless-testable,
/// bounded, and fail-closed when capacity is reached.
#[derive(Debug)]
pub struct StdioTransportStub {
    outgoing: VecDeque<Frame>,
    incoming: VecDeque<Frame>,
    capacity: usize,
    closed: bool,
    dropped_outgoing: u64,
}

impl StdioTransportStub {
    /// Create a stub with `capacity` frames per direction.
    ///
    /// # Panics
    ///
    /// Panics when `capacity == 0` or `capacity > MAX_TRANSPORT_CAPACITY`.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "transport capacity must be > 0");
        assert!(
            capacity <= MAX_TRANSPORT_CAPACITY,
            "transport capacity {capacity} exceeds MAX_TRANSPORT_CAPACITY {MAX_TRANSPORT_CAPACITY}"
        );
        Self {
            outgoing: VecDeque::with_capacity(capacity),
            incoming: VecDeque::with_capacity(capacity),
            capacity,
            closed: false,
            dropped_outgoing: 0,
        }
    }

    /// Create with the default capacity.
    #[must_use]
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_TRANSPORT_CAPACITY)
    }

    /// Capacity per direction.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of outgoing frames buffered (not yet drained by peer).
    #[must_use]
    pub fn outgoing_len(&self) -> usize {
        self.outgoing.len()
    }

    /// Number of incoming frames buffered.
    #[must_use]
    pub fn incoming_len(&self) -> usize {
        self.incoming.len()
    }

    /// Whether outgoing queue is empty.
    #[must_use]
    pub fn is_outgoing_empty(&self) -> bool {
        self.outgoing.is_empty()
    }

    /// Whether incoming queue is empty.
    #[must_use]
    pub fn is_incoming_empty(&self) -> bool {
        self.incoming.is_empty()
    }

    /// Whether the transport has been closed (peer died, pipe broken).
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Number of outgoing frames dropped via `send_drop_oldest` since
    /// creation or last `clear`.
    #[must_use]
    pub const fn dropped_outgoing(&self) -> u64 {
        self.dropped_outgoing
    }

    /// Close the transport. All subsequent `try_send_*` calls fail with
    /// [`IpcError::TransportClosed`]; queued frames may still be drained.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Clear all buffered frames and reset counters (does not reopen a closed transport).
    pub fn clear(&mut self) {
        self.outgoing.clear();
        self.incoming.clear();
        self.dropped_outgoing = 0;
    }

    /// Try to send a `frame` toward the peer (outgoing direction).
    ///
    /// # Errors
    ///
    /// - [`IpcError::TransportClosed`] when the transport is closed.
    /// - [`IpcError::TransportFull`] when the outgoing queue is at capacity.
    pub fn try_send_frame(&mut self, frame: Frame) -> Result<(), IpcError> {
        if self.closed {
            return Err(IpcError::TransportClosed {
                reason: "stdio transport is closed".into(),
            });
        }
        if self.outgoing.len() >= self.capacity {
            return Err(IpcError::TransportFull {
                capacity: self.capacity,
            });
        }
        self.outgoing.push_back(frame);
        Ok(())
    }

    /// Convenience: encode `payload` and enqueue as one outgoing frame.
    ///
    /// Checks the 256 KiB bound via [`encode_frame`] before enqueuing.
    pub fn try_send_payload(&mut self, payload: &[u8]) -> Result<(), IpcError> {
        if payload.len() > MAX_FRAME_BYTES {
            return Err(IpcError::FrameTooLarge {
                actual: payload.len(),
                limit: MAX_FRAME_BYTES,
            });
        }
        let frame = Frame::new(payload.to_vec())?;
        self.try_send_frame(frame)
    }

    /// Send a frame, evicting the oldest outgoing frame when at capacity.
    ///
    /// The dropped counter increments. This is the policy for untrusted
    /// observation streams where staleness is preferable to blocking; it must
    /// not be used for request/response acknowledgement where loss is silent
    /// failure.
    pub fn send_drop_oldest(&mut self, frame: Frame) {
        if self.closed {
            return;
        }
        if self.outgoing.len() >= self.capacity {
            self.outgoing.pop_front();
            self.dropped_outgoing = self.dropped_outgoing.wrapping_add(1);
        }
        self.outgoing.push_back(frame);
    }

    /// Pop the oldest outgoing frame (simulating the peer reading it).
    pub fn recv_outgoing(&mut self) -> Option<Frame> {
        self.outgoing.pop_front()
    }

    /// Drain all outgoing frames in FIFO order (harness helper to move bytes
    /// to the peer's incoming queue).
    pub fn drain_outgoing(&mut self) -> Vec<Frame> {
        self.outgoing.drain(..).collect()
    }

    /// Try to send raw wire bytes toward the peer, decoding length-prefixed
    /// frames and enqueueing them into the outgoing queue (TERM-IPC-013 / CTX-0554).
    ///
    /// This helper allows a harness to push raw wire bytes (one or more length-prefixed
    /// frames) into the transport. Frames are extracted via [`Framer`](bitty_ipc_api::frame::Framer)
    /// and validated against [`MAX_FRAME_BYTES`] and transport capacity.
    ///
    /// # Errors
    ///
    /// - [`IpcError::TransportClosed`] when the transport is closed.
    /// - [`IpcError::TransportFull`] when the resulting frames would exceed capacity.
    /// - [`IpcError::FrameTooLarge`] when a frame exceeds [`MAX_FRAME_BYTES`].
    /// - [`IpcError::FrameTruncated`] when wire ends with an incomplete frame.
    pub fn try_send_wire_bytes(&mut self, wire: &[u8]) -> Result<usize, IpcError> {
        if self.closed {
            return Err(IpcError::TransportClosed {
                reason: "stdio transport is closed".into(),
            });
        }
        let mut framer = bitty_ipc_api::frame::Framer::new();
        let frames = framer.push_bytes(wire)?;
        if !framer.is_empty() {
            return Err(IpcError::FrameTruncated {
                expected: 4,
                actual: framer.buffered_len(),
            });
        }
        if self.outgoing.len() + frames.len() > self.capacity {
            return Err(IpcError::TransportFull {
                capacity: self.capacity,
            });
        }
        let count = frames.len();
        for frame in frames {
            self.outgoing.push_back(frame);
        }
        Ok(count)
    }

    /// Inject a frame that has arrived from the peer (incoming direction).
    ///
    /// This is the headless entry point for the receiving side: tests move
    /// frames from the sender's `drain_outgoing` into the receiver's
    /// `inject_incoming`, simulating pipe delivery without blocking.
    ///
    /// # Errors
    ///
    /// - [`IpcError::TransportClosed`] when the transport is closed.
    /// - [`IpcError::TransportFull`] when the incoming queue is at capacity.
    pub fn inject_incoming(&mut self, frame: Frame) -> Result<(), IpcError> {
        if self.closed {
            return Err(IpcError::TransportClosed {
                reason: "stdio transport is closed".into(),
            });
        }
        if self.incoming.len() >= self.capacity {
            return Err(IpcError::TransportFull {
                capacity: self.capacity,
            });
        }
        self.incoming.push_back(frame);
        Ok(())
    }

    /// Inject a raw payload as one incoming frame (headless helper).
    pub fn inject_incoming_payload(&mut self, payload: &[u8]) -> Result<(), IpcError> {
        let frame = Frame::new(payload.to_vec())?;
        self.inject_incoming(frame)
    }

    /// Receive the oldest incoming frame, if any.
    pub fn recv_incoming(&mut self) -> Option<Frame> {
        self.incoming.pop_front()
    }

    /// Drain all incoming frames in FIFO order.
    pub fn drain_incoming(&mut self) -> Vec<Frame> {
        self.incoming.drain(..).collect()
    }

    /// Drain incoming frames up to `limit` (bounded batch, mirroring the
    /// isolation RFC's per-wakeup ceiling).
    pub fn drain_incoming_bounded(&mut self, limit: usize) -> Vec<Frame> {
        let take = limit.min(self.incoming.len());
        self.incoming.drain(..take).collect()
    }

    /// Move all outgoing frames from `self` into `peer`'s incoming queue
    /// headlessly (single-call pipe simulation).
    ///
    /// Returns the number of frames moved. Stops early when `peer`'s incoming
    /// queue is full or closed; remaining frames stay in `self`'s outgoing
    /// queue for retry.
    pub fn forward_to(&mut self, peer: &mut Self) -> usize {
        let mut moved = 0;
        while let Some(_frame) = self.outgoing.front() {
            if peer.is_closed() || peer.incoming_len() >= peer.capacity {
                break;
            }
            let frame = self.outgoing.pop_front().unwrap();
            // `Frame` is bounded, so this cannot fail due to size.
            let _ = peer.inject_incoming(frame);
            moved += 1;
        }
        moved
    }

    /// Encode `payload` via [`encode_frame`], enqueue as outgoing, and atomically
    /// inject into `peer`'s incoming queue when `peer` has capacity.
    ///
    /// This combines `try_send_payload` + `forward_to` in one headless step for
    /// concise tests. Returns `Ok(())` when both steps succeed.
    pub fn send_to_peer(&mut self, payload: &[u8], peer: &mut Self) -> Result<(), IpcError> {
        self.try_send_payload(payload)?;
        self.forward_to(peer);
        Ok(())
    }
}

impl Default for StdioTransportStub {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_and_default_capacity() {
        let t = StdioTransportStub::with_default_capacity();
        assert_eq!(t.capacity(), DEFAULT_TRANSPORT_CAPACITY);
        assert!(!t.is_closed());
    }

    #[test]
    fn try_send_and_recv_outgoing() {
        let mut t = StdioTransportStub::new(4);
        t.try_send_payload(b"hello").unwrap();
        t.try_send_payload(b"world").unwrap();
        assert_eq!(t.outgoing_len(), 2);
        let f = t.recv_outgoing().unwrap();
        assert_eq!(f.payload(), b"hello");
        assert_eq!(t.outgoing_len(), 1);
    }

    #[test]
    fn outgoing_full_is_fail_closed() {
        let mut t = StdioTransportStub::new(2);
        t.try_send_payload(b"a").unwrap();
        t.try_send_payload(b"b").unwrap();
        let err = t.try_send_payload(b"c").unwrap_err();
        assert!(matches!(err, IpcError::TransportFull { capacity: 2 }));
    }

    #[test]
    fn closed_rejects_sends() {
        let mut t = StdioTransportStub::new(4);
        t.close();
        assert!(t.is_closed());
        let err = t.try_send_payload(b"hi").unwrap_err();
        assert!(matches!(err, IpcError::TransportClosed { .. }));
    }

    #[test]
    fn send_drop_oldest_evicts_and_counts() {
        let mut t = StdioTransportStub::new(2);
        t.try_send_payload(b"a").unwrap();
        t.try_send_payload(b"b").unwrap();
        t.send_drop_oldest(Frame::new(b"c".to_vec()).unwrap());
        assert_eq!(t.dropped_outgoing(), 1);
        let out = t.drain_outgoing();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].payload(), b"b");
        assert_eq!(out[1].payload(), b"c");
    }

    #[test]
    fn inject_and_recv_incoming() {
        let mut t = StdioTransportStub::new(4);
        t.inject_incoming_payload(b"from-peer").unwrap();
        assert_eq!(t.incoming_len(), 1);
        let f = t.recv_incoming().unwrap();
        assert_eq!(f.payload(), b"from-peer");
    }

    #[test]
    fn incoming_full_rejects() {
        let mut t = StdioTransportStub::new(1);
        t.inject_incoming_payload(b"a").unwrap();
        let err = t.inject_incoming_payload(b"b").unwrap_err();
        assert!(matches!(err, IpcError::TransportFull { .. }));
    }

    #[test]
    fn forward_to_moves_frames_headlessly() {
        let mut a = StdioTransportStub::new(8);
        let mut b = StdioTransportStub::new(8);
        a.try_send_payload(b"msg1").unwrap();
        a.try_send_payload(b"msg2").unwrap();
        let moved = a.forward_to(&mut b);
        assert_eq!(moved, 2);
        assert_eq!(a.outgoing_len(), 0);
        assert_eq!(b.incoming_len(), 2);
        assert_eq!(b.recv_incoming().unwrap().payload(), b"msg1");
    }

    #[test]
    fn forward_to_stops_when_peer_full() {
        let mut a = StdioTransportStub::new(8);
        let mut b = StdioTransportStub::new(1);
        a.try_send_payload(b"m1").unwrap();
        a.try_send_payload(b"m2").unwrap();
        a.try_send_payload(b"m3").unwrap();
        let moved = a.forward_to(&mut b);
        assert_eq!(moved, 1);
        assert_eq!(a.outgoing_len(), 2);
        assert_eq!(b.incoming_len(), 1);
    }

    #[test]
    fn payload_bound_enforced_on_send() {
        let mut t = StdioTransportStub::new(8);
        let large = vec![0u8; MAX_FRAME_BYTES + 1];
        let err = t.try_send_payload(&large).unwrap_err();
        assert!(matches!(err, IpcError::FrameTooLarge { .. }));
    }

    #[test]
    fn clear_resets_queues_and_dropped() {
        let mut t = StdioTransportStub::new(2);
        t.try_send_payload(b"a").unwrap();
        t.try_send_payload(b"b").unwrap();
        t.send_drop_oldest(Frame::new(b"c".to_vec()).unwrap());
        assert_eq!(t.dropped_outgoing(), 1);
        t.clear();
        assert_eq!(t.outgoing_len(), 0);
        assert_eq!(t.dropped_outgoing(), 0);
        // closed stays closed even after clear
        t.close();
        t.clear();
        assert!(t.is_closed());
    }

    #[test]
    fn headless_roundtrip_via_encode_and_frame() {
        let mut a = StdioTransportStub::new(8);
        let mut b = StdioTransportStub::new(8);
        let payload = b"headless roundtrip payload with bounded framing";
        a.try_send_payload(payload).unwrap();
        a.forward_to(&mut b);
        let got = b.recv_incoming().unwrap();
        assert_eq!(got.payload(), payload);

        // Verify encoding path: payload -> encode -> framer -> decode payload
        let wire = bitty_ipc_api::frame::encode_frame(payload).unwrap();
        let (decoded, consumed) = bitty_ipc_api::frame::decode_frame(&wire).unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.payload(), payload);
    }

    /// TERM-IPC-013 / CTX-0554: pure single and concatenated frame wire fixtures
    /// must decode into proper frames and agree with the framing contract.
    #[test]
    fn try_send_wire_bytes_single_and_concatenated_frames() {
        let mut t = StdioTransportStub::new(8);

        // Single frame
        let wire1 = bitty_ipc_api::frame::encode_frame(b"frame1").unwrap();
        let sent = t.try_send_wire_bytes(&wire1).unwrap();
        assert_eq!(sent, 1);
        assert_eq!(t.outgoing_len(), 1);

        // Concatenated multi-frame
        let wire2 = bitty_ipc_api::frame::encode_frame(b"frame2").unwrap();
        let wire3 = bitty_ipc_api::frame::encode_frame(b"frame3").unwrap();
        let mut concat = wire2;
        concat.extend_from_slice(&wire3);
        let sent = t.try_send_wire_bytes(&concat).unwrap();
        assert_eq!(sent, 2);
        assert_eq!(t.outgoing_len(), 3);

        let frames = t.drain_outgoing();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].payload(), b"frame1");
        assert_eq!(frames[1].payload(), b"frame2");
        assert_eq!(frames[2].payload(), b"frame3");
    }

    /// TERM-IPC-013 / CTX-0554: exact cap and truncated framing bounds.
    #[test]
    fn try_send_wire_bytes_exact_cap_and_truncated_validation() {
        let mut t = StdioTransportStub::new(8);

        // Exact MAX_FRAME_BYTES payload
        let max_payload = vec![42u8; MAX_FRAME_BYTES];
        let wire_max = bitty_ipc_api::frame::encode_frame(&max_payload).unwrap();
        let sent = t.try_send_wire_bytes(&wire_max).unwrap();
        assert_eq!(sent, 1);
        assert_eq!(t.outgoing_len(), 1);

        // Truncated wire bytes
        let truncated = vec![0, 0, 0, 10, 1, 2, 3]; // declares 10 bytes, has 3
        let err = t.try_send_wire_bytes(&truncated).unwrap_err();
        assert!(matches!(err, IpcError::FrameTruncated { .. }));

        // Incomplete header
        let incomplete_header = vec![0, 0];
        let err = t.try_send_wire_bytes(&incomplete_header).unwrap_err();
        assert!(matches!(err, IpcError::FrameTruncated { .. }));
    }
}
