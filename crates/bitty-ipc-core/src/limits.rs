//! Rate limits and budgets (RFC RC-9 / RC-10, IR-D3).
//!
//! Status: **accepted initial values** on 2026-08-29 following the
//! Performance Budget RFC convention that numbers are target contracts. Tests
//! must parameterize on the declared values; changing a value requires an RFC
//! revision, never silent drift.
//!
//! This module is headless, bounded, `forbid(unsafe)`.

use bitty_ipc_api::error::IpcError;

// ── RC-9: IPC request rate and payload ──────────────────────────────────────

/// RC-9: sustained request rate per connection (100 req/s).
pub const RC9_REQ_PER_SEC: u32 = 100;

/// RC-9: burst factor (2x for 1 s => 200 req burst).
pub const RC9_BURST_PER_SEC: u32 = RC9_REQ_PER_SEC * 2;

/// RC-9: payload cap per request (1 MiB decoded). Note: framing already caps
/// at 256 KiB per frame, so a logical request that would exceed 1 MiB must be
/// chunked client-side.
pub const RC9_PAYLOAD_CAP_BYTES: usize = 1024 * 1024;

/// RC-9: maximum concurrent connections per endpoint (16 default).
pub const RC9_MAX_CONNECTIONS: usize = 16;

/// RC-9 window length for burst accounting (1 second in ms).
pub const RC9_WINDOW_MS: u64 = 1_000;

// ── RC-10: MCP/Agent response size ──────────────────────────────────────────

/// RC-10: stream chunk ceiling (256 KiB decoded bytes per chunk).
pub const RC10_CHUNK_CEILING: usize = 256 * 1024;

/// RC-10: maximum snapshot size before chunking is required (same as frame bound).
pub const RC10_MAX_SNAPSHOT_BYTES: usize = bitty_ipc_api::frame::MAX_FRAME_BYTES;

// ── channel/transport ceilings already in place ─────────────────────────────

/// Maximum channel capacity per RFC (256, `MAX_CHANNEL_CAPACITY`).
pub const MAX_CHANNEL_CAPACITY: usize = bitty_ipc_api::channel::MAX_CHANNEL_CAPACITY;

/// Maximum pending requests per client (64).
pub const MAX_PENDING_REQUESTS: usize = bitty_ipc_api::channel::MAX_PENDING_REQUESTS;

/// Default transport capacity per direction (64).
pub const DEFAULT_TRANSPORT_CAPACITY: usize = crate::transport::DEFAULT_TRANSPORT_CAPACITY;

// ── headless rate limiter ───────────────────────────────────────────────────

/// Headless token-bucket rate limiter for RC-9 (100 req/s, 2x burst).
///
/// The limiter is deterministic via caller-supplied `now_ms`, never wall-clock.
/// Tokens refill at `limit_per_sec` per second up to `burst` capacity; each
/// admitted request consumes one token. A fresh limiter starts full, so a
/// short spike of up to `burst` passes, while sustained load is capped at
/// `limit_per_sec` per second no matter how long the window is observed.
///
/// The timestamp deque is observational only (powers `count_in_window`); it
/// holds at most the admissions inside the trailing 1 s window and never
/// gates admission by itself. Fail-closed: `check()` returns `RateLimited`
/// when no token is available, without partial state.
///
/// A malicious peer therefore cannot grow host memory by flooding: the frame
/// bound caps each allocation, the channel caps bound queue depth, and overflow
/// is fail-closed and countable (FS-IP4 attribution).
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Timestamps (ms) of recent admissions within the window, observational.
    timestamps: std::collections::VecDeque<u64>,
    /// Sustained refill rate (tokens per second).
    limit_per_sec: u32,
    /// Bucket capacity (maximum instantaneous burst).
    burst: u32,
    /// Available tokens in thousandths (fixed-point, avoids float drift).
    tokens_milli: u64,
    /// Last `now_ms` the bucket was refilled at (`None` before first check).
    last_ms: Option<u64>,
}

impl RateLimiter {
    /// Create a limiter with RC-9 defaults (100/s sustained, 200 burst).
    #[must_use]
    pub fn rc9_default() -> Self {
        Self::new(RC9_REQ_PER_SEC, RC9_BURST_PER_SEC)
    }

    /// Create with explicit limits (for tests).
    #[must_use]
    pub fn new(limit_per_sec: u32, burst: u32) -> Self {
        Self {
            timestamps: std::collections::VecDeque::with_capacity(burst as usize),
            limit_per_sec,
            burst,
            tokens_milli: u64::from(burst).saturating_mul(1_000),
            last_ms: None,
        }
    }

    /// Number of requests in the current 1-second window ending at `now_ms`.
    pub fn count_in_window(&mut self, now_ms: u64) -> usize {
        self.evict_old(now_ms);
        self.timestamps.len()
    }

    /// Check whether a request at `now_ms` is allowed; if so, record it.
    ///
    /// # Errors
    ///
    /// Returns `IpcError::Denied(RateLimited)` when no token is available:
    /// either the instantaneous `burst` is exhausted or the sustained
    /// `limit_per_sec` refill has not yet accrued. No timestamp is recorded
    /// and no token is consumed on denial.
    pub fn check(&mut self, now_ms: u64) -> Result<(), IpcError> {
        self.evict_old(now_ms);
        self.refill(now_ms);
        if self.tokens_milli < 1_000 {
            return Err(IpcError::Denied {
                code: "RateLimited".into(),
                reason: format!(
                    "rate limited: sustained {} req/s with burst {} exhausted at {} ms",
                    self.limit_per_sec, self.burst, now_ms
                ),
            });
        }
        self.tokens_milli -= 1_000;
        self.timestamps.push_back(now_ms);
        Ok(())
    }

    /// Refill tokens accrued since the last check, capped at `burst`.
    ///
    /// Backwards clock steps accrue nothing and never move the watermark
    /// backwards, so skew cannot mint tokens.
    fn refill(&mut self, now_ms: u64) {
        let Some(last) = self.last_ms else {
            self.last_ms = Some(now_ms);
            return;
        };
        let elapsed = now_ms.saturating_sub(last);
        if elapsed == 0 {
            return;
        }
        self.last_ms = Some(now_ms);
        let cap_milli = u64::from(self.burst).saturating_mul(1_000);
        let accrued = (elapsed as u128).saturating_mul(u128::from(self.limit_per_sec));
        let topped = u128::from(self.tokens_milli)
            .saturating_add(accrued)
            .min(u128::from(cap_milli));
        self.tokens_milli = topped.min(u128::from(u64::MAX)) as u64;
    }

    /// Evict timestamps older than `RC9_WINDOW_MS` from `now_ms`.
    fn evict_old(&mut self, now_ms: u64) {
        while let Some(&front) = self.timestamps.front() {
            if now_ms.saturating_sub(front) >= RC9_WINDOW_MS {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }
    }

    /// Whether the limiter has no pending window entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.timestamps.is_empty()
    }
}

/// Validate logical payload size against RC-9 cap (1 MiB).
///
/// A logical request that would exceed 1 MiB must be chunked client-side
/// (RC-10). This check validates the assembled logical size before framing;
/// per-frame 256 KiB enforcement lives in `frame::encode_frame` / `Frame::new`
/// and rejects an oversize single frame with `FrameTooLarge` without chunking.
/// Oversize logical payloads are rejected whole with `Denied/PayloadCap` and
/// no partial parse (FS-IP1).
pub fn check_payload_cap(payload_len: usize) -> Result<(), IpcError> {
    if payload_len > RC9_PAYLOAD_CAP_BYTES {
        return Err(IpcError::Denied {
            code: "PayloadCap".into(),
            reason: format!(
                "payload {} exceeds RC-9 cap {}",
                payload_len, RC9_PAYLOAD_CAP_BYTES
            ),
        });
    }
    Ok(())
}

/// Validate a single frame payload against the 256 KiB framing bound.
///
/// This is the per-frame complement to `check_payload_cap`: a single frame
/// `payload_len > MAX_FRAME_BYTES` is rejected with `FrameTooLarge` before any
/// allocation of the claimed size (T-01, P0-AC-001 parity).
pub fn check_frame_payload(payload_len: usize) -> Result<(), IpcError> {
    if payload_len > bitty_ipc_api::frame::MAX_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge {
            actual: payload_len,
            limit: bitty_ipc_api::frame::MAX_FRAME_BYTES,
        });
    }
    Ok(())
}

/// Validate concurrent connection count against RC-9 max (16).
///
/// Exceeding sheds **newest** connection first (FS-IP2), preserving service
/// for existing clients. This function just checks the cap; the shedding
/// policy belongs to the endpoint that calls it.
pub fn check_connection_cap(active: usize) -> Result<(), IpcError> {
    if active >= RC9_MAX_CONNECTIONS {
        return Err(IpcError::Denied {
            code: "ConnectionLimit".into(),
            reason: format!(
                "concurrent connections {} >= limit {} (shed newest)",
                active, RC9_MAX_CONNECTIONS
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_burst_and_window() {
        let mut lim = RateLimiter::new(10, 5);
        // Burst of 5 in same ms should pass
        for _ in 0..5 {
            assert!(lim.check(0).is_ok());
        }
        // 6th in same window fails
        assert!(lim.check(0).is_err());
        // After window passes, bucket evicts
        assert!(lim.check(1000).is_ok());
        assert_eq!(lim.count_in_window(1000), 1);
    }

    #[test]
    fn rate_limiter_enforces_sustained_per_sec_after_burst() {
        // Hostile: burst 20 at t=0 must not grant a fresh 20 at t=1000;
        // sustained 10/s refills only 10 per second.
        let mut lim = RateLimiter::new(10, 20);
        for _ in 0..20 {
            assert!(lim.check(0).is_ok());
        }
        assert!(lim.check(0).is_err());
        for _ in 0..10 {
            assert!(lim.check(1000).is_ok());
        }
        assert!(
            lim.check(1000).is_err(),
            "sustained per_sec must cap refill, not re-arm full burst"
        );
    }

    #[test]
    fn rate_limiter_partial_refill_and_no_backwards_refill() {
        let mut lim = RateLimiter::new(10, 10);
        for _ in 0..10 {
            assert!(lim.check(0).is_ok());
        }
        assert!(lim.check(0).is_err());
        // 500 ms refills exactly 5.
        for _ in 0..5 {
            assert!(lim.check(500).is_ok());
        }
        assert!(lim.check(500).is_err());
        // Clock skew backwards grants nothing.
        assert!(lim.check(0).is_err());
    }

    #[test]
    fn rc9_default_sustains_100_per_sec_after_burst() {
        let mut lim = RateLimiter::rc9_default();
        for _ in 0..RC9_BURST_PER_SEC {
            assert!(lim.check(0).is_ok());
        }
        assert!(lim.check(0).is_err());
        for _ in 0..RC9_REQ_PER_SEC {
            assert!(lim.check(1000).is_ok());
        }
        assert!(lim.check(1000).is_err());
    }

    #[test]
    fn payload_cap() {
        assert!(check_payload_cap(0).is_ok());
        assert!(check_payload_cap(RC9_PAYLOAD_CAP_BYTES).is_ok());
        assert!(check_payload_cap(RC9_PAYLOAD_CAP_BYTES + 1).is_err());
        // Per-frame bound is separate: single frame oversize is FrameTooLarge,
        // logical payload within RC-9 but over frame size is okay when chunked.
        let over_framing = bitty_ipc_api::frame::MAX_FRAME_BYTES + 1;
        assert!(check_payload_cap(over_framing).is_ok());
        assert!(check_frame_payload(over_framing).is_err());
        let err = check_frame_payload(over_framing).unwrap_err();
        assert!(matches!(err, IpcError::FrameTooLarge { .. }));
    }

    #[test]
    fn connection_cap() {
        assert!(check_connection_cap(0).is_ok());
        assert!(check_connection_cap(15).is_ok());
        assert!(check_connection_cap(16).is_err());
    }

    #[test]
    fn rc9_defaults_match_rfc() {
        assert_eq!(RC9_REQ_PER_SEC, 100);
        assert_eq!(RC9_BURST_PER_SEC, 200);
        assert_eq!(RC9_MAX_CONNECTIONS, 16);
        assert_eq!(RC9_PAYLOAD_CAP_BYTES, 1024 * 1024);
        assert_eq!(RC10_CHUNK_CEILING, 256 * 1024);
    }
}
