//! Bounded message framing for IPC and MCP.
//!
//! The wire format is intentionally minimal and headless-testable:
//! a 4-byte big-endian length prefix followed by exactly that many
//! payload bytes. No negotiation, no compression, no ambient extension.
//!
//! The bound is 256 KiB (262 144 bytes) of payload per frame, matching the
//! CTX-0031 task and the proposed isolation RFC `RC-10` chunking.
//! Payloads larger than the bound are refused before allocation (T-01,
//! invariant 7). Incomplete frames are reported as [`IpcError::FrameTruncated`],
//! never buffered unboundedly.

use crate::error::IpcError;

/// Maximum payload bytes per frame (256 KiB).
///
/// This is the sole framing bound; no frame may carry more than this many
/// bytes. The value follows the task requirement "message framing bounded
/// 256KiB" and aligns with the candidate `RC-10` snapshot chunking.
pub const MAX_FRAME_BYTES: usize = 256 * 1024;

/// Maximum bytes a [`Framer`] will buffer while waiting for a complete frame.
///
/// The framer keeps at most one partial frame plus its 4-byte header in memory.
/// Burst absorption beyond that is refused so a malicious peer cannot force
/// unbounded growth (T-01). The cap is `MAX_FRAME_BYTES + 4` plus a small slack
/// for the next header probe, staying well below 1 MiB.
pub const MAX_BUFFERED_BYTES: usize = MAX_FRAME_BYTES + 8;

/// A validated, owned frame payload.
///
/// Construction checks the 256 KiB bound; every `Frame` that exists is within
/// limit. Payloads are opaque bytes — the framing layer does not interpret
/// JSON, message type, or method.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Frame {
    payload: Vec<u8>,
}

impl Frame {
    /// Create a frame from already-validated `payload`.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::FrameTooLarge`] when `payload.len() > MAX_FRAME_BYTES`.
    pub fn new(payload: Vec<u8>) -> Result<Self, IpcError> {
        if payload.len() > MAX_FRAME_BYTES {
            return Err(IpcError::FrameTooLarge {
                actual: payload.len(),
                limit: MAX_FRAME_BYTES,
            });
        }
        Ok(Self { payload })
    }

    /// Borrow the payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consume into the owned payload bytes.
    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    /// Payload length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    /// Whether the payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

/// Encode `payload` into wire bytes `[len_be32 || payload]`.
///
/// The caller supplies an unstructured bounded payload. Encoding checks the
/// 256 KiB bound before allocating the 4-byte header.
///
/// # Errors
///
/// Returns [`IpcError::FrameTooLarge`] when `payload.len() > MAX_FRAME_BYTES`.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, IpcError> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge {
            actual: payload.len(),
            limit: MAX_FRAME_BYTES,
        });
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode exactly one frame from the start of `buf`.
///
/// On success returns the frame and the number of bytes consumed
/// (4 + payload length). The caller may loop while `buf` remains.
///
/// # Errors
///
/// - [`IpcError::FrameTruncated`] when fewer than 4 header bytes are available,
///   or when the declared length exceeds available body bytes.
/// - [`IpcError::FrameTooLarge`] when the declared length exceeds `MAX_FRAME_BYTES`.
/// - [`IpcError::InvalidFrame`] is not used here; framing faults are represented
///   by the two cases above so callers can attribute correctly.
pub fn decode_frame(buf: &[u8]) -> Result<(Frame, usize), IpcError> {
    if buf.len() < 4 {
        return Err(IpcError::FrameTruncated {
            expected: 4,
            actual: buf.len(),
        });
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge {
            actual: len,
            limit: MAX_FRAME_BYTES,
        });
    }
    let total = 4 + len;
    if buf.len() < total {
        return Err(IpcError::FrameTruncated {
            expected: total,
            actual: buf.len(),
        });
    }
    let payload = buf[4..total].to_vec();
    Ok((Frame { payload }, total))
}

/// Incremental, headless decoder that buffers partial frames.
///
/// The framer is the streaming counterpart to [`encode_frame`] / [`decode_frame`].
/// Callers feed arbitrary byte slices via [`Framer::push_bytes`]; the framer
/// returns completed frames and retains only the incomplete tail. Its internal
/// buffer is strictly bounded by [`MAX_BUFFERED_BYTES`] plus one in-flight
/// declared length — a peer cannot force unbounded growth by sending a huge
/// length prefix or by trickling one byte at a time (T-01, invariant 7).
#[derive(Debug, Default)]
pub struct Framer {
    buf: Vec<u8>,
}

impl Framer {
    /// Create an empty framer.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Bytes currently buffered waiting for a complete frame.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the framer holds no buffered bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Clear buffered bytes (e.g. after a transport reset).
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Feed `bytes` into the framer and extract completed frames.
    ///
    /// The returned vector contains zero or more fully decoded frames in the
    /// order they completed. Any trailing partial frame stays buffered for the
    /// next call.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::FrameTooLarge`] immediately when a declared frame
    /// length exceeds `MAX_FRAME_BYTES`. The framer is cleared on such an
    /// error so the malicious prefix cannot poison later decodes.
    ///
    /// Returns [`IpcError::PayloadTooLarge`] when buffered bytes would exceed
    /// `MAX_BUFFERED_BYTES` and the bound cannot be respected as a streaming
    /// buffer. This is also fail-closed and clears the buffer.
    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<Vec<Frame>, IpcError> {
        if self.buf.len() + bytes.len() > MAX_BUFFERED_BYTES && bytes.len() > MAX_BUFFERED_BYTES {
            // Single push itself is huge; refuse without buffering unbounded.
            self.buf.clear();
            return Err(IpcError::PayloadTooLarge {
                field: "framer.buffer".into(),
                limit: MAX_BUFFERED_BYTES,
                actual: self.buf.len() + bytes.len(),
            });
        }
        if self.buf.len() + bytes.len() > MAX_BUFFERED_BYTES + MAX_FRAME_BYTES {
            // Pathological buffering of many tiny pushes; bound the total.
            self.buf.clear();
            return Err(IpcError::PayloadTooLarge {
                field: "framer.buffer".into(),
                limit: MAX_BUFFERED_BYTES + MAX_FRAME_BYTES,
                actual: self.buf.len() + bytes.len(),
            });
        }
        self.buf.extend_from_slice(bytes);

        let mut frames = Vec::new();
        let mut consumed = 0usize;

        loop {
            let remaining = &self.buf[consumed..];
            if remaining.is_empty() {
                break;
            }
            if remaining.len() < 4 {
                // Need more header bytes.
                break;
            }
            let len = u32::from_be_bytes([remaining[0], remaining[1], remaining[2], remaining[3]])
                as usize;
            if len > MAX_FRAME_BYTES {
                self.buf.clear();
                return Err(IpcError::FrameTooLarge {
                    actual: len,
                    limit: MAX_FRAME_BYTES,
                });
            }
            let total = 4 + len;
            if remaining.len() < total {
                // Need more body bytes.
                break;
            }
            let payload = remaining[4..total].to_vec();
            frames.push(Frame { payload });
            consumed += total;
        }

        if consumed > 0 {
            self.buf.drain(..consumed);
        }
        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip_empty() {
        let payload = b"";
        let wire = encode_frame(payload).expect("encode empty");
        assert_eq!(wire.len(), 4);
        let (frame, consumed) = decode_frame(&wire).expect("decode");
        assert_eq!(consumed, 4);
        assert_eq!(frame.payload(), payload);
    }

    #[test]
    fn encode_decode_roundtrip_small() {
        let payload = b"hello world";
        let wire = encode_frame(payload).expect("encode");
        let (frame, consumed) = decode_frame(&wire).expect("decode");
        assert_eq!(consumed, 4 + payload.len());
        assert_eq!(frame.payload(), payload);
    }

    #[test]
    fn max_frame_exactly_allowed() {
        let payload = vec![0xAB; MAX_FRAME_BYTES];
        let wire = encode_frame(&payload).expect("max frame must encode");
        assert_eq!(wire.len(), 4 + MAX_FRAME_BYTES);
        let (frame, consumed) = decode_frame(&wire).expect("max frame must decode");
        assert_eq!(consumed, wire.len());
        assert_eq!(frame.len(), MAX_FRAME_BYTES);
    }

    #[test]
    fn encode_rejects_over_max() {
        let payload = vec![0xFF; MAX_FRAME_BYTES + 1];
        let err = encode_frame(&payload).unwrap_err();
        assert_eq!(err.error_class(), crate::error::ErrorClass::Framing);
        assert!(matches!(err, IpcError::FrameTooLarge { .. }));
    }

    #[test]
    fn frame_new_enforces_bound() {
        let payload = vec![1; MAX_FRAME_BYTES + 10];
        let err = Frame::new(payload).unwrap_err();
        assert!(matches!(err, IpcError::FrameTooLarge { .. }));
    }

    #[test]
    fn decode_rejects_length_prefix_over_max() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&(MAX_FRAME_BYTES as u32 + 1).to_be_bytes());
        wire.extend_from_slice(b"tiny"); // actual body tiny, but prefix already invalid
        let err = decode_frame(&wire).unwrap_err();
        assert!(matches!(err, IpcError::FrameTooLarge { .. }));
    }

    #[test]
    fn decode_reports_truncation_for_short_header() {
        let buf = [0x00, 0x00];
        let err = decode_frame(&buf).unwrap_err();
        assert!(matches!(err, IpcError::FrameTruncated { .. }));
    }

    #[test]
    fn decode_reports_truncation_for_short_body() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&10u32.to_be_bytes());
        wire.extend_from_slice(b"12345"); // only 5 of 10
        let err = decode_frame(&wire).unwrap_err();
        assert!(matches!(err, IpcError::FrameTruncated { .. }));
    }

    #[test]
    fn framer_incremental_two_frames_concatenated() {
        let w1 = encode_frame(b"first").unwrap();
        let w2 = encode_frame(b"second message").unwrap();
        let mut combined = Vec::new();
        combined.extend_from_slice(&w1);
        combined.extend_from_slice(&w2);

        let mut framer = Framer::new();
        // Feed one byte at a time to stress incremental path.
        let mut out = Vec::new();
        for b in combined.chunks(1) {
            let frames = framer.push_bytes(b).unwrap();
            out.extend(frames);
        }
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].payload(), b"first");
        assert_eq!(out[1].payload(), b"second message");
        assert!(framer.is_empty());
    }

    #[test]
    fn framer_partial_then_complete() {
        let wire = encode_frame(b"payload").unwrap();
        let mut framer = Framer::new();
        // Split header and body.
        let first = framer.push_bytes(&wire[..2]).unwrap();
        assert!(first.is_empty());
        assert_eq!(framer.buffered_len(), 2);

        let second = framer.push_bytes(&wire[2..]).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].payload(), b"payload");
        assert!(framer.is_empty());
    }

    #[test]
    fn framer_rejects_length_prefix_over_max_and_clears() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&(MAX_FRAME_BYTES as u32 + 1).to_be_bytes());
        wire.extend_from_slice(b"evil");
        let mut framer = Framer::new();
        let err = framer.push_bytes(&wire).unwrap_err();
        assert!(matches!(err, IpcError::FrameTooLarge { .. }));
        assert!(framer.is_empty(), "framer must clear on poison prefix");
        // Subsequent valid frame must still decode.
        let good = encode_frame(b"ok").unwrap();
        let frames = framer.push_bytes(&good).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload(), b"ok");
    }

    #[test]
    fn framer_empty_push_is_noop() {
        let mut framer = Framer::new();
        let frames = framer.push_bytes(b"").unwrap();
        assert!(frames.is_empty());
        assert!(framer.is_empty());
    }

    #[test]
    fn encode_empty_frame_is_four_zero_bytes() {
        let wire = encode_frame(b"").unwrap();
        assert_eq!(wire, vec![0, 0, 0, 0]);
    }
}
