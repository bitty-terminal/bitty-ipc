//! Inbound request continuation (devtools-rfc Amendment A4, #1482).
//!
//! One physical frame carries at most [`MAX_FRAME_BYTES`] payload bytes, while
//! the accepted inbound limit for one logical request is 1 MiB
//! ([`MAX_LOGICAL_REQUEST_BYTES`]). A larger logical request therefore arrives
//! as continuation fragments, one per physical frame. Every fragment payload
//! starts with a 16-byte header (all integers big-endian):
//!
//! | Offset | Size | Field             | Rule                                       |
//! | ------ | ---- | ----------------- | ------------------------------------------ |
//! | 0      | 4    | `magic`           | [`CONTINUATION_MAGIC`] (`\0BC1`)           |
//! | 4      | 4    | `continuation_id` | Nonzero; same in every fragment            |
//! | 8      | 2    | `sequence`        | `0` first, then exactly one more each      |
//! | 10     | 1    | `flags`           | Bit 0 is [`CONTINUATION_FLAG_FINAL`]       |
//! | 11     | 1    | `reserved`        | Zero                                       |
//! | 12     | 4    | `total_length`    | Logical request length; same in every one  |
//!
//! A JSON envelope never starts with `0x00`, so a fragment can never be
//! mistaken for a plain request frame.
//!
//! Fragmentation is canonical: only a request above one frame uses it, every
//! non-final fragment is a full frame, and the final one carries the
//! remainder. A 1 MiB request is therefore at most five fragments, which
//! removes slow-drip fragment amplification.
//!
//! [`Reassembler`] owns at most one open reassembly per connection. It
//! validates each header before buffering, checks the declared total against
//! the inbound limit before allocating, and bounds the whole exchange by
//! [`CONTINUATION_DEADLINE_MS`]. Any violation discards the buffer and is
//! returned as a [`ContinuationError`]; nothing is parsed or dispatched until
//! the logical request is complete, so a partial, late, or malformed request
//! has no side effect.

use crate::error::IpcError;
use crate::frame::{MAX_FRAME_BYTES, encode_frame};
use crate::limits::RC9_PAYLOAD_CAP_BYTES;

/// Magic prefix of every continuation fragment payload (`\0BC1`).
pub const CONTINUATION_MAGIC: [u8; 4] = [0x00, b'B', b'C', b'1'];

/// Bytes of the fragment header that precede each chunk.
pub const CONTINUATION_HEADER_BYTES: usize = 16;

/// Chunk bytes carried by every non-final fragment (one full frame).
pub const CONTINUATION_CHUNK_BYTES: usize = MAX_FRAME_BYTES - CONTINUATION_HEADER_BYTES;

/// `flags` bit marking the fragment that completes the logical request.
pub const CONTINUATION_FLAG_FINAL: u8 = 0b0000_0001;

/// Largest logical request a client may send (the accepted 1 MiB inbound
/// limit, RC-9 payload cap).
pub const MAX_LOGICAL_REQUEST_BYTES: usize = RC9_PAYLOAD_CAP_BYTES;

/// Deadline for the final fragment, measured from the first one.
pub const CONTINUATION_DEADLINE_MS: u64 = 5_000;

/// Why a continuation sequence failed closed.
///
/// Each variant maps to one `transport` wire code ([`Self::code`]); the
/// connection replies with `id` `0` and closes, because the logical request id
/// is still unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContinuationError {
    /// The declared `total_length` exceeds [`MAX_LOGICAL_REQUEST_BYTES`].
    TooLarge {
        /// Declared logical request length.
        declared: usize,
    },
    /// The final fragment did not arrive within [`CONTINUATION_DEADLINE_MS`].
    Timeout {
        /// Milliseconds since the first fragment.
        elapsed_ms: u64,
    },
    /// Any other header, ordering, or length violation.
    Invalid {
        /// Bounded, static description of the violated rule.
        reason: &'static str,
    },
}

impl ContinuationError {
    /// Stable `transport` wire code for this failure.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "FrameTooLarge",
            Self::Timeout { .. } => "ContinuationTimeout",
            Self::Invalid { .. } => "ContinuationInvalid",
        }
    }

    /// Bounded message for the error reply (never echoes peer bytes).
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::TooLarge { declared } => {
                format!("continuation total {declared} exceeds limit {MAX_LOGICAL_REQUEST_BYTES}")
            }
            Self::Timeout { elapsed_ms } => format!(
                "continuation incomplete after {elapsed_ms} ms (deadline {CONTINUATION_DEADLINE_MS} ms)"
            ),
            Self::Invalid { reason } => format!("invalid continuation: {reason}"),
        }
    }
}

/// Outcome of feeding one physical frame payload to a [`Reassembler`].
#[derive(Debug, PartialEq, Eq)]
pub enum Accepted {
    /// A complete logical request: a plain frame, or a finished reassembly.
    Request(Vec<u8>),
    /// A fragment was buffered; the logical request needs more fragments.
    Pending,
}

/// Returns `true` when `payload` is a continuation fragment.
#[must_use]
pub fn is_fragment(payload: &[u8]) -> bool {
    payload.starts_with(&CONTINUATION_MAGIC)
}

/// A validated fragment header.
#[derive(Debug, Clone, Copy)]
struct Header {
    id: u32,
    sequence: u16,
    final_fragment: bool,
    total: usize,
}

const fn invalid(reason: &'static str) -> ContinuationError {
    ContinuationError::Invalid { reason }
}

/// Parse and validate the header of a fragment payload (magic already seen).
fn parse_header(payload: &[u8]) -> Result<(Header, &[u8]), ContinuationError> {
    let Some((head, chunk)) = payload.split_at_checked(CONTINUATION_HEADER_BYTES) else {
        return Err(invalid("fragment shorter than its header"));
    };
    let id = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
    let sequence = u16::from_be_bytes([head[8], head[9]]);
    let flags = head[10];
    let reserved = head[11];
    let total = u32::from_be_bytes([head[12], head[13], head[14], head[15]]);
    if id == 0 {
        return Err(invalid("continuation id must be nonzero"));
    }
    if flags & !CONTINUATION_FLAG_FINAL != 0 {
        return Err(invalid("undefined flag bits are set"));
    }
    if reserved != 0 {
        return Err(invalid("reserved byte is not zero"));
    }
    // A u32 always fits in usize on every supported (32/64-bit) target; a
    // narrower target saturates, which the limit check below still rejects.
    let total = usize::try_from(total).unwrap_or(usize::MAX);
    Ok((
        Header {
            id,
            sequence,
            final_fragment: flags & CONTINUATION_FLAG_FINAL != 0,
            total,
        },
        chunk,
    ))
}

/// The one open reassembly of a connection.
#[derive(Debug)]
struct Open {
    id: u32,
    total: usize,
    next_sequence: u16,
    started_ms: u64,
    buf: Vec<u8>,
}

impl Open {
    /// Append one chunk; returns `true` when the logical request is complete.
    fn append(&mut self, header: Header, chunk: &[u8]) -> Result<bool, ContinuationError> {
        let remaining = self.total - self.buf.len();
        if header.final_fragment {
            if chunk.len() != remaining {
                return Err(invalid(
                    "final fragment does not complete the declared length",
                ));
            }
        } else {
            if chunk.len() != CONTINUATION_CHUNK_BYTES {
                return Err(invalid("non-final fragment is not a full frame"));
            }
            if chunk.len() >= remaining {
                return Err(invalid("non-final fragment reaches the declared length"));
            }
        }
        self.buf.extend_from_slice(chunk);
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| invalid("sequence overflow"))?;
        Ok(header.final_fragment)
    }
}

/// Per-connection inbound continuation state machine.
///
/// Feed every physical frame payload through [`Self::accept`]. Plain frames
/// pass through unchanged while no reassembly is open; fragments are buffered
/// until the final one completes the logical request. Every error clears the
/// state, so the caller replies once and closes the connection.
#[derive(Debug, Default)]
pub struct Reassembler {
    open: Option<Open>,
}

impl Reassembler {
    /// A reassembler with no open reassembly.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a reassembly is open (fragments buffered, final one pending).
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.open.is_some()
    }

    /// Absolute deadline (same clock as [`Self::accept`]) for the open
    /// reassembly's final fragment, or `None` when nothing is open.
    ///
    /// The serve loop bounds every socket read by this deadline, so a peer
    /// that drips a fragment byte by byte cannot hold the connection past it.
    #[must_use]
    pub fn deadline_ms(&self) -> Option<u64> {
        self.open
            .as_ref()
            .map(|open| open.started_ms.saturating_add(CONTINUATION_DEADLINE_MS))
    }

    /// Feed one physical frame payload read at `now_ms`.
    ///
    /// # Errors
    ///
    /// Returns a [`ContinuationError`] for every violated rule; the open
    /// reassembly, if any, is discarded without being returned.
    pub fn accept(&mut self, payload: Vec<u8>, now_ms: u64) -> Result<Accepted, ContinuationError> {
        let outcome = self.accept_inner(payload, now_ms);
        if outcome.is_err() {
            self.open = None;
        }
        outcome
    }

    /// Discard an open reassembly because the stream stalled.
    ///
    /// Returns the [`ContinuationError::Timeout`] to report when a reassembly
    /// was open, or `None` when there was nothing to discard.
    pub fn stalled(&mut self, now_ms: u64) -> Option<ContinuationError> {
        self.open.take().map(|open| ContinuationError::Timeout {
            elapsed_ms: now_ms.saturating_sub(open.started_ms),
        })
    }

    fn accept_inner(
        &mut self,
        payload: Vec<u8>,
        now_ms: u64,
    ) -> Result<Accepted, ContinuationError> {
        if !is_fragment(&payload) {
            if self.open.is_some() {
                return Err(invalid("plain frame while a reassembly is open"));
            }
            return Ok(Accepted::Request(payload));
        }
        let (header, chunk) = parse_header(&payload)?;
        let complete = match self.open.as_mut() {
            None => {
                if header.sequence != 0 {
                    return Err(invalid("first fragment must have sequence 0"));
                }
                if header.total > MAX_LOGICAL_REQUEST_BYTES {
                    return Err(ContinuationError::TooLarge {
                        declared: header.total,
                    });
                }
                if header.total <= MAX_FRAME_BYTES {
                    return Err(invalid(
                        "a request that fits one frame must not be fragmented",
                    ));
                }
                // Bounded allocation: the declared total is at most 1 MiB.
                let open = self.open.insert(Open {
                    id: header.id,
                    total: header.total,
                    next_sequence: 0,
                    started_ms: now_ms,
                    buf: Vec::with_capacity(header.total),
                });
                open.append(header, chunk)?
            }
            Some(open) => {
                let elapsed_ms = now_ms.saturating_sub(open.started_ms);
                if elapsed_ms > CONTINUATION_DEADLINE_MS {
                    return Err(ContinuationError::Timeout { elapsed_ms });
                }
                if header.sequence == 0 {
                    return Err(invalid("new first fragment while a reassembly is open"));
                }
                if header.id != open.id {
                    return Err(invalid("continuation id changed mid-request"));
                }
                if header.total != open.total {
                    return Err(invalid("total length changed mid-request"));
                }
                if header.sequence != open.next_sequence {
                    return Err(invalid("fragment sequence out of order"));
                }
                open.append(header, chunk)?
            }
        };
        if !complete {
            return Ok(Accepted::Pending);
        }
        let request = self.open.take().map(|open| open.buf).unwrap_or_default();
        if is_fragment(&request) {
            return Err(invalid("reassembled request is itself a fragment"));
        }
        Ok(Accepted::Request(request))
    }
}

/// Encode one logical request as wire frames (length prefix included).
///
/// A request of at most [`MAX_FRAME_BYTES`] becomes one plain frame; a larger
/// one becomes canonical continuation fragments tagged `continuation_id`.
/// This is the reference sender for fixtures and in-tree clients.
///
/// # Errors
///
/// Returns [`IpcError::FrameTooLarge`] when `request` exceeds
/// [`MAX_LOGICAL_REQUEST_BYTES`], and [`IpcError::InvalidRequest`] for a zero
/// `continuation_id` when fragmentation is needed. No frame is produced on
/// error.
pub fn encode_request_frames(
    request: &[u8],
    continuation_id: u32,
) -> Result<Vec<Vec<u8>>, IpcError> {
    if request.len() > MAX_LOGICAL_REQUEST_BYTES {
        return Err(IpcError::FrameTooLarge {
            actual: request.len(),
            limit: MAX_LOGICAL_REQUEST_BYTES,
        });
    }
    if request.len() <= MAX_FRAME_BYTES {
        return Ok(vec![encode_frame(request)?]);
    }
    if continuation_id == 0 {
        return Err(IpcError::InvalidRequest {
            reason: "continuation id must be nonzero".into(),
        });
    }
    // The limit check above keeps the total within u32 (1 MiB).
    let total = u32::try_from(request.len()).map_err(|_| IpcError::FrameTooLarge {
        actual: request.len(),
        limit: MAX_LOGICAL_REQUEST_BYTES,
    })?;
    let chunks: Vec<&[u8]> = request.chunks(CONTINUATION_CHUNK_BYTES).collect();
    let last = chunks.len() - 1;
    let mut frames = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.into_iter().enumerate() {
        let sequence = u16::try_from(index).map_err(|_| IpcError::InvalidRequest {
            reason: "continuation sequence overflow".into(),
        })?;
        let mut payload = Vec::with_capacity(CONTINUATION_HEADER_BYTES + chunk.len());
        payload.extend_from_slice(&CONTINUATION_MAGIC);
        payload.extend_from_slice(&continuation_id.to_be_bytes());
        payload.extend_from_slice(&sequence.to_be_bytes());
        payload.push(if index == last {
            CONTINUATION_FLAG_FINAL
        } else {
            0
        });
        payload.push(0);
        payload.extend_from_slice(&total.to_be_bytes());
        payload.extend_from_slice(chunk);
        frames.push(encode_frame(&payload)?);
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: u32 = 7;

    /// Physical frame payloads (length prefix stripped) for `request`.
    fn fragments(request: &[u8], id: u32) -> Vec<Vec<u8>> {
        encode_request_frames(request, id)
            .unwrap()
            .into_iter()
            .map(|frame| frame[4..].to_vec())
            .collect()
    }

    /// A fragment payload with an explicit header.
    fn fragment(id: u32, sequence: u16, flags: u8, total: u32, chunk: &[u8]) -> Vec<u8> {
        let mut payload = CONTINUATION_MAGIC.to_vec();
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&sequence.to_be_bytes());
        payload.push(flags);
        payload.push(0);
        payload.extend_from_slice(&total.to_be_bytes());
        payload.extend_from_slice(chunk);
        payload
    }

    fn request_of(len: usize) -> Vec<u8> {
        (0..len).map(|i| b'a' + (i % 26) as u8).collect()
    }

    /// Feed every payload at `now_ms`; returns the final outcome.
    fn feed_all(
        reassembler: &mut Reassembler,
        payloads: Vec<Vec<u8>>,
    ) -> Result<Accepted, ContinuationError> {
        let mut last = Ok(Accepted::Pending);
        for payload in payloads {
            last = reassembler.accept(payload, 0);
            if last.is_err() {
                break;
            }
        }
        last
    }

    fn assert_invalid(outcome: Result<Accepted, ContinuationError>, reassembler: &Reassembler) {
        let err = outcome.unwrap_err();
        assert_eq!(err.code(), "ContinuationInvalid", "{err:?}");
        assert!(
            !reassembler.is_open(),
            "a violation must discard the buffer"
        );
    }

    #[test]
    fn header_layout_is_sixteen_bytes_and_chunk_fills_a_frame() {
        assert_eq!(CONTINUATION_HEADER_BYTES, 16);
        assert_eq!(
            CONTINUATION_CHUNK_BYTES + CONTINUATION_HEADER_BYTES,
            MAX_FRAME_BYTES
        );
        assert_eq!(MAX_LOGICAL_REQUEST_BYTES, 1024 * 1024);
        assert_eq!(CONTINUATION_DEADLINE_MS, 5_000);
        // A JSON envelope never starts with the magic's first byte.
        assert_eq!(CONTINUATION_MAGIC[0], 0x00);
    }

    #[test]
    fn plain_frames_pass_through_unchanged() {
        let mut reassembler = Reassembler::new();
        let plain = br#"{"id":1,"method":"bitty.debug/ping","version":"1.0"}"#.to_vec();
        assert_eq!(
            reassembler.accept(plain.clone(), 0).unwrap(),
            Accepted::Request(plain)
        );
        assert!(!reassembler.is_open());
    }

    #[test]
    fn encoder_keeps_a_one_frame_request_plain() {
        let request = request_of(MAX_FRAME_BYTES);
        let frames = encode_request_frames(&request, ID).unwrap();
        assert_eq!(frames.len(), 1);
        assert!(!is_fragment(&frames[0][4..]));
    }

    #[test]
    fn just_above_one_frame_reassembles_from_two_fragments() {
        let request = request_of(MAX_FRAME_BYTES + 1);
        let payloads = fragments(&request, ID);
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0].len(), MAX_FRAME_BYTES);
        let mut reassembler = Reassembler::new();
        assert_eq!(
            reassembler.accept(payloads[0].clone(), 0).unwrap(),
            Accepted::Pending
        );
        assert!(reassembler.is_open());
        assert_eq!(
            reassembler.accept(payloads[1].clone(), 1).unwrap(),
            Accepted::Request(request)
        );
        assert!(!reassembler.is_open());
    }

    #[test]
    fn the_inbound_limit_reassembles_from_five_fragments() {
        let request = request_of(MAX_LOGICAL_REQUEST_BYTES);
        let payloads = fragments(&request, ID);
        assert_eq!(payloads.len(), 5);
        let mut reassembler = Reassembler::new();
        assert_eq!(
            feed_all(&mut reassembler, payloads).unwrap(),
            Accepted::Request(request)
        );
    }

    #[test]
    fn an_exact_multiple_of_the_chunk_ends_with_a_full_final_fragment() {
        let request = request_of(CONTINUATION_CHUNK_BYTES * 2);
        let payloads = fragments(&request, ID);
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[1][10], CONTINUATION_FLAG_FINAL);
        let mut reassembler = Reassembler::new();
        assert_eq!(
            feed_all(&mut reassembler, payloads).unwrap(),
            Accepted::Request(request)
        );
    }

    #[test]
    fn a_reassembler_serves_consecutive_requests() {
        let mut reassembler = Reassembler::new();
        for id in [1, 2] {
            let request = request_of(MAX_FRAME_BYTES + 10);
            let got = feed_all(&mut reassembler, fragments(&request, id)).unwrap();
            assert_eq!(got, Accepted::Request(request));
        }
    }

    #[test]
    fn over_limit_total_is_frame_too_large_before_any_buffering() {
        let mut reassembler = Reassembler::new();
        let total = u32::try_from(MAX_LOGICAL_REQUEST_BYTES + 1).unwrap();
        let chunk = vec![b'x'; CONTINUATION_CHUNK_BYTES];
        let err = reassembler
            .accept(fragment(ID, 0, 0, total, &chunk), 0)
            .unwrap_err();
        assert_eq!(err.code(), "FrameTooLarge");
        assert!(!reassembler.is_open());
        let err = reassembler
            .accept(fragment(ID, 0, 0, u32::MAX, &chunk), 0)
            .unwrap_err();
        assert_eq!(err.code(), "FrameTooLarge");
    }

    #[test]
    fn encoder_refuses_over_limit_and_zero_id_without_frames() {
        let over = request_of(MAX_LOGICAL_REQUEST_BYTES + 1);
        assert!(matches!(
            encode_request_frames(&over, ID),
            Err(IpcError::FrameTooLarge { .. })
        ));
        let big = request_of(MAX_FRAME_BYTES + 1);
        assert!(matches!(
            encode_request_frames(&big, 0),
            Err(IpcError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn malformed_first_fragments_fail_closed() {
        let total = u32::try_from(MAX_FRAME_BYTES + 1).unwrap();
        let full = vec![b'x'; CONTINUATION_CHUNK_BYTES];
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("short header", CONTINUATION_MAGIC.to_vec()),
            ("zero id", fragment(0, 0, 0, total, &full)),
            ("undefined flag", fragment(ID, 0, 0b10, total, &full)),
            ("nonzero sequence first", fragment(ID, 1, 0, total, &full)),
            ("fits one frame", fragment(ID, 0, 0, 1024, &full)),
            ("short non-final", fragment(ID, 0, 0, total, &full[..100])),
            (
                "final too short",
                fragment(ID, 0, CONTINUATION_FLAG_FINAL, total, &full),
            ),
            ("empty chunk", fragment(ID, 0, 0, total, &[])),
        ];
        for (name, payload) in cases {
            let mut reassembler = Reassembler::new();
            let outcome = reassembler.accept(payload, 0);
            assert!(outcome.is_err(), "{name} must fail closed");
            assert_invalid(outcome, &reassembler);
        }
        let mut reserved = fragment(ID, 0, 0, total, &full);
        reserved[11] = 1;
        let mut reassembler = Reassembler::new();
        let outcome = reassembler.accept(reserved, 0);
        assert_invalid(outcome, &reassembler);
    }

    #[test]
    fn ordering_and_identity_violations_fail_closed() {
        let request = request_of(CONTINUATION_CHUNK_BYTES * 2 + 5);
        let good = fragments(&request, ID);
        assert_eq!(good.len(), 3);
        let total = u32::try_from(request.len()).unwrap();
        let chunk = &good[1][CONTINUATION_HEADER_BYTES..];
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("wrong id", fragment(ID + 1, 1, 0, total, chunk)),
            ("wrong total", fragment(ID, 1, 0, total + 1, chunk)),
            ("skipped sequence", fragment(ID, 2, 0, total, chunk)),
            ("repeated sequence", fragment(ID, 0, 0, total, chunk)),
            ("plain frame interleaved", br#"{"id":1}"#.to_vec()),
            (
                "overrun as final",
                fragment(ID, 1, CONTINUATION_FLAG_FINAL, total, chunk),
            ),
        ];
        for (name, payload) in cases {
            let mut reassembler = Reassembler::new();
            assert_eq!(
                reassembler.accept(good[0].clone(), 0).unwrap(),
                Accepted::Pending
            );
            let outcome = reassembler.accept(payload, 0);
            assert!(outcome.is_err(), "{name} must fail closed");
            assert_invalid(outcome, &reassembler);
        }
    }

    #[test]
    fn non_final_fragment_that_reaches_the_total_fails_closed() {
        let request = request_of(CONTINUATION_CHUNK_BYTES * 2);
        let good = fragments(&request, ID);
        let total = u32::try_from(request.len()).unwrap();
        let mut reassembler = Reassembler::new();
        assert_eq!(
            reassembler.accept(good[0].clone(), 0).unwrap(),
            Accepted::Pending
        );
        let unfinished = fragment(ID, 1, 0, total, &good[1][CONTINUATION_HEADER_BYTES..]);
        let outcome = reassembler.accept(unfinished, 0);
        assert_invalid(outcome, &reassembler);
    }

    #[test]
    fn a_fragment_after_the_deadline_discards_the_request() {
        let request = request_of(MAX_FRAME_BYTES + 1);
        let payloads = fragments(&request, ID);
        let mut reassembler = Reassembler::new();
        assert_eq!(
            reassembler.accept(payloads[0].clone(), 1_000).unwrap(),
            Accepted::Pending
        );
        let err = reassembler
            .accept(payloads[1].clone(), 1_000 + CONTINUATION_DEADLINE_MS + 1)
            .unwrap_err();
        assert_eq!(err.code(), "ContinuationTimeout");
        assert!(!reassembler.is_open());
    }

    #[test]
    fn a_fragment_on_the_deadline_is_still_accepted() {
        let request = request_of(MAX_FRAME_BYTES + 1);
        let payloads = fragments(&request, ID);
        let mut reassembler = Reassembler::new();
        assert_eq!(
            reassembler.accept(payloads[0].clone(), 0).unwrap(),
            Accepted::Pending
        );
        assert_eq!(
            reassembler
                .accept(payloads[1].clone(), CONTINUATION_DEADLINE_MS)
                .unwrap(),
            Accepted::Request(request)
        );
    }

    #[test]
    fn stalled_reports_a_timeout_only_while_open() {
        let mut reassembler = Reassembler::new();
        assert_eq!(reassembler.stalled(10), None);
        let request = request_of(MAX_FRAME_BYTES + 1);
        let payloads = fragments(&request, ID);
        assert_eq!(
            reassembler.accept(payloads[0].clone(), 10).unwrap(),
            Accepted::Pending
        );
        assert_eq!(
            reassembler.stalled(70),
            Some(ContinuationError::Timeout { elapsed_ms: 60 })
        );
        assert!(!reassembler.is_open());
    }

    #[test]
    fn a_reassembled_fragment_never_nests() {
        let inner = fragment(ID, 0, 0, 0, &[]);
        let mut request = inner;
        request.resize(MAX_FRAME_BYTES + 1, b' ');
        let mut reassembler = Reassembler::new();
        let outcome = feed_all(&mut reassembler, fragments(&request, ID + 1));
        assert_invalid(outcome, &reassembler);
    }

    #[test]
    fn error_messages_are_bounded_and_never_echo_peer_bytes() {
        let messages = [
            ContinuationError::TooLarge {
                declared: usize::MAX,
            }
            .message(),
            ContinuationError::Timeout {
                elapsed_ms: u64::MAX,
            }
            .message(),
            invalid("fragment sequence out of order").message(),
        ];
        for message in messages {
            assert!(message.len() < 128, "{message}");
        }
    }
}
