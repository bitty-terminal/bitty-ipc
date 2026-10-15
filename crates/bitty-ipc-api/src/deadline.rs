//! Domain-to-channel timeout mapping (wiring item 6).
//!
//! The S2 `CompleteRequest` envelope carries a caller deadline
//! (`timeout_ms`, at most `MAX_REQUEST_TIMEOUT_MS`, with caller-supplied
//! `now_ms`; no wall clock is read on that path) while the channel enforces
//! `DEFAULT_REQUEST_TIMEOUT_MS` / `MAX_REQUEST_TIMEOUT_MS` with deterministic
//! `drain_expired` reaping from caller-supplied `now_ms` (RFC §Agent auth,
//! consent, and streaming: timeouts are "checked from caller-supplied
//! `now_ms`, never wall-clock time"). Both ceilings are `30 s`; this module
//! states who enforces what and provides the caller-`now_ms` mapping rule as
//! pure helpers. The enforceable half (validation + deadline arithmetic +
//! no-exec-after-timeout) is covered by tests; execution-side re-checks stay
//! host-owned.
//!
//! Who enforces what:
//!
//! | Layer | Rule | Effect |
//! | ----- | ---- | ------ |
//! | S2 envelope (`CompleteRequest::check`) | refuse `timeout_ms` past the
//! ceiling early | `TimeoutTooLarge` before any work |
//! | S2 execution | re-check the ceiling authoritatively at execution time |
//! pre-I/O refusal, no partial state |
//! | IPC channel construction (`IpcRequest::new`) | refuse `timeout_ms` of
//! `0` or past `MAX_REQUEST_TIMEOUT_MS` | [`IpcError::InvalidRequest`],
//! never queued |
//! | IPC channel reaping (`IpcEndpoint::drain_expired`) | drop expired ids
//! from the pending table **and** the not-yet-handed-over queue |
//! no-exec-after-timeout |
//! | Transport default | `DEFAULT_REQUEST_TIMEOUT_MS` (`5 s`) applies when the
//! caller supplies no explicit deadline | deterministic default, still
//! caller-`now_ms`-relative |
//!
//! Caller-`now_ms` mapping rule: the domain `now_ms` maps verbatim to channel
//! `created_at_ms`; the absolute deadline is
//! `now_ms.saturating_add(timeout_ms)`; expiry holds when `now >= deadline`.
//! No wall-clock time is read at any step.

use crate::channel::MAX_REQUEST_TIMEOUT_MS;
use crate::error::IpcError;

/// Shared hard ceiling for any per-request deadline (`30 s`).
///
/// Re-exported for the mapping rule below. This equals the S2
/// `MAX_REQUEST_TIMEOUT_MS` (`30_000`): the envelope early-refusal ceiling
/// and the channel construction ceiling are the same bound, so a domain
/// timeout that passes the envelope gate also passes channel construction.
/// Changing either side requires a joint revision, never silent drift.
pub use crate::channel::MAX_REQUEST_TIMEOUT_MS as DOMAIN_TIMEOUT_CEILING_MS;

/// Default deadline applied when the caller supplies none (`5 s`).
///
/// Re-exported for wiring completeness: the transport default, still
/// `caller-now_ms`-relative (RFC §Agent auth, consent, and streaming).
pub use crate::channel::DEFAULT_REQUEST_TIMEOUT_MS as DOMAIN_DEFAULT_TIMEOUT_MS;

/// Validate a domain `timeout_ms` for channel crossing.
///
/// Accepts exactly the channel construction range `1..=MAX_REQUEST_TIMEOUT_MS`,
/// so a domain timeout that passes here also passes `IpcRequest::new`.
///
/// # Errors
///
/// Returns [`IpcError::InvalidRequest`] when `timeout_ms` is `0` or exceeds
/// `MAX_REQUEST_TIMEOUT_MS` (same shape as `IpcRequest::new`, and the
/// IPC-side expression of S2 `TimeoutTooLarge` per `refusal.rs`).
pub fn validate_domain_timeout(timeout_ms: u64) -> Result<(), IpcError> {
    if timeout_ms == 0 || timeout_ms > MAX_REQUEST_TIMEOUT_MS {
        return Err(IpcError::InvalidRequest {
            reason: format!("timeout_ms must be 1..={MAX_REQUEST_TIMEOUT_MS}, got {timeout_ms}"),
        });
    }
    Ok(())
}

/// Map caller `now_ms` plus a validated `timeout_ms` to an absolute deadline.
///
/// Saturating addition: far-future `now_ms` values pin at `u64::MAX` instead
/// of wrapping. Expiry holds when `now_ms >= deadline`, matching
/// `IpcRequest::is_expired`.
#[must_use]
pub fn domain_deadline_ms(now_ms: u64, timeout_ms: u64) -> u64 {
    now_ms.saturating_add(timeout_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{IpcEndpoint, IpcRequest, RequestId};

    #[test]
    fn ceiling_matches_s2_envelope_bound() {
        // The S2 CompleteRequest early-refusal ceiling and the channel
        // construction ceiling are the same bound (30 s). A literal pin
        // (no bitty-ai dependency; citation in the module docs above).
        assert_eq!(MAX_REQUEST_TIMEOUT_MS, 30_000);
        assert_eq!(DOMAIN_TIMEOUT_CEILING_MS, 30_000);
        assert_eq!(DOMAIN_DEFAULT_TIMEOUT_MS, 5_000);
    }

    #[test]
    fn domain_timeout_validation_mirrors_construction() {
        assert!(validate_domain_timeout(1).is_ok());
        assert!(validate_domain_timeout(5_000).is_ok());
        assert!(validate_domain_timeout(30_000).is_ok());
        assert!(validate_domain_timeout(0).is_err());
        assert!(validate_domain_timeout(30_001).is_err());
        // Same shape the channel enforces: InvalidRequest both sides.
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
    fn now_ms_maps_verbatim_to_created_at() {
        // Caller-now_ms rule: domain now_ms becomes created_at_ms verbatim;
        // the deadline is the saturating sum; no wall clock anywhere.
        let now_ms = 1_700_000_000_000_u64;
        let timeout_ms = 5_000_u64;
        validate_domain_timeout(timeout_ms).unwrap();
        let req = IpcRequest::new(RequestId(9), "m".into(), vec![], now_ms, timeout_ms).unwrap();
        assert_eq!(req.created_at_ms, now_ms);
        assert_eq!(req.deadline_ms(), domain_deadline_ms(now_ms, timeout_ms));
        assert!(!req.is_expired(now_ms + timeout_ms - 1));
        assert!(req.is_expired(now_ms + timeout_ms));
    }

    #[test]
    fn deadline_saturates_instead_of_wrapping() {
        assert_eq!(domain_deadline_ms(u64::MAX, 30_000), u64::MAX);
        assert_eq!(domain_deadline_ms(u64::MAX - 1, 5), u64::MAX);
    }

    #[test]
    fn mapped_request_never_executes_after_timeout() {
        // The enforceable half end-to-end: a domain-mapped request reaped at
        // its deadline leaves no queued work behind (no-exec-after-timeout).
        let mut ep = IpcEndpoint::with_capacity(8, 8);
        let now_ms = 10_000_u64;
        let timeout_ms = 1_000_u64;
        validate_domain_timeout(timeout_ms).unwrap();
        let id = {
            let req =
                IpcRequest::new(RequestId(3), "m".into(), vec![], now_ms, timeout_ms).unwrap();
            let id = req.id;
            ep.send_request(req).unwrap();
            id
        };
        assert_eq!(ep.request_len(), 1);
        let deadline = domain_deadline_ms(now_ms, timeout_ms);
        assert!(ep.drain_expired(deadline - 1).is_empty());
        assert_eq!(ep.drain_expired(deadline), vec![id]);
        assert_eq!(ep.request_len(), 0);
        assert!(ep.recv_request().is_none());
    }
}
