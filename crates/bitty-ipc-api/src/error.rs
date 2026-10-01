//! Owned error vocabulary for `bitty-ipc`.

use std::fmt;

/// Stable error class mirroring the security and isolation corpus.
///
/// Maps to the RFC error taxonomy: `InvalidFrame`/`PayloadTooLarge` -> `Framing`,
/// `MethodInvalid`/`VersionMismatch` -> `Validation`, `Unauthenticated` -> `Unauthenticated`,
/// `Denied`/`ScopeViolation`/`RateLimited`/`PayloadCap` -> `Scope`, plus transport/channel/timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorClass {
    /// Frame or payload size / truncation failure.
    Framing,
    /// Bounded channel capacity exceeded.
    Channel,
    /// Transport (stdio pipe / IPC endpoint) failure.
    Transport,
    /// Request timeout / deadline exceeded.
    Timeout,
    /// Validation of method, params, or protocol fields.
    Validation,
    /// Scope / peer-credential denial.
    Scope,
    /// Peer credential unauthenticated (SO_PEERCRED mismatch, wrong UID).
    Unauthenticated,
    /// Generic denied (rate limited, payload cap whole, chunk violation).
    Denied,
    /// Requested entity not found.
    NotFound,
    /// Unavailable / shed.
    Unavailable,
    /// Internal invariant.
    Internal,
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Framing => "framing",
            Self::Channel => "channel",
            Self::Transport => "transport",
            Self::Timeout => "timeout",
            Self::Validation => "validation",
            Self::Scope => "scope",
            Self::Unauthenticated => "unauthenticated",
            Self::Denied => "denied",
            Self::NotFound => "not_found",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        };
        f.write_str(label)
    }
}

/// Owned, headless-testable error for every `bitty-ipc` failure mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcError {
    /// Frame payload exceeds the 256 KiB bound.
    FrameTooLarge {
        /// Actual payload length in bytes.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// Payload exceeds per-message or per-field limit.
    PayloadTooLarge {
        /// Field or context.
        field: String,
        /// Configured limit.
        limit: usize,
        /// Actual length.
        actual: usize,
    },
    /// Frame header or body truncated.
    FrameTruncated {
        /// Expected bytes (header + length).
        expected: usize,
        /// Actual bytes available.
        actual: usize,
    },
    /// Frame contents malformed.
    InvalidFrame {
        /// Human-readable reason.
        reason: String,
    },
    /// Bounded channel at capacity.
    ChannelFull {
        /// Channel capacity.
        capacity: usize,
    },
    /// Channel closed or endpoint gone.
    ChannelClosed {
        /// Reason.
        reason: String,
    },
    /// Transport closed.
    TransportClosed {
        /// Reason.
        reason: String,
    },
    /// Transport buffer at capacity.
    TransportFull {
        /// Capacity (frames).
        capacity: usize,
    },
    /// Transport failure (peer died, broken pipe).
    Transport {
        /// Reason.
        reason: String,
    },
    /// Request deadline exceeded.
    Timeout {
        /// Request id that timed out.
        request_id: u64,
        /// Configured timeout in ms.
        timeout_ms: u64,
    },
    /// Too many pending requests.
    PendingLimitExceeded {
        /// Configured limit.
        limit: usize,
        /// Actual pending count.
        actual: usize,
    },
    /// Method name invalid.
    InvalidMethod {
        /// Attempted method.
        method: String,
        /// Reason.
        reason: String,
    },
    /// Generic validation failure.
    InvalidRequest {
        /// Reason.
        reason: String,
    },
    /// Scope denied for action.
    ScopeDenied {
        /// Scope that was checked.
        scope: String,
        /// Action attempted.
        action: String,
    },
    /// Limit exceeded for a named field.
    LimitExceeded {
        /// Field.
        field: String,
        /// Limit.
        limit: usize,
        /// Actual.
        actual: usize,
    },
    /// Wire version mismatch (expected v1, got other).
    VersionMismatch {
        /// Expected version.
        expected: u16,
        /// Actual version.
        actual: u16,
    },
    /// Peer credential check failed — UID mismatch or tampered endpoint.
    Unauthenticated {
        /// Reason (no stack trace, no OS handle).
        reason: String,
    },
    /// Generic denied with stable code (RateLimited, PayloadCap, ChunkViolation, ScopeViolation).
    Denied {
        /// Stable code e.g. `ScopeViolation`, `RateLimited`, `PayloadCap`, `ChunkViolation`.
        code: String,
        /// Human message.
        reason: String,
    },
    /// Entity not found (instance, method, terminal).
    NotFound {
        /// Reason.
        reason: String,
    },
    /// Service unavailable or connection shed.
    Unavailable {
        /// Reason.
        reason: String,
    },
    /// Internal invariant failure (fail-closed).
    Internal {
        /// Reason.
        reason: String,
    },
}

impl IpcError {
    /// Convenience for frame-too-large.
    #[must_use]
    pub fn frame_too_large(actual: usize, limit: usize) -> Self {
        Self::FrameTooLarge { actual, limit }
    }

    /// Convenience for invalid frame.
    #[must_use]
    pub fn invalid_frame(reason: impl Into<String>) -> Self {
        Self::InvalidFrame {
            reason: reason.into(),
        }
    }

    /// Convenience for channel full.
    #[must_use]
    pub fn channel_full(capacity: usize) -> Self {
        Self::ChannelFull { capacity }
    }

    /// Convenience for transport closed.
    #[must_use]
    pub fn transport_closed(reason: impl Into<String>) -> Self {
        Self::TransportClosed {
            reason: reason.into(),
        }
    }

    /// Convenience for invalid method.
    #[must_use]
    pub fn invalid_method(method: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidMethod {
            method: method.into(),
            reason: reason.into(),
        }
    }

    /// Convenience for invalid request.
    #[must_use]
    pub fn invalid_request(reason: impl Into<String>) -> Self {
        Self::InvalidRequest {
            reason: reason.into(),
        }
    }

    /// Convenience for scope denial.
    #[must_use]
    pub fn scope_denied(scope: impl Into<String>, action: impl Into<String>) -> Self {
        Self::ScopeDenied {
            scope: scope.into(),
            action: action.into(),
        }
    }

    /// Convenience for unauthenticated peer.
    #[must_use]
    pub fn unauthenticated(reason: impl Into<String>) -> Self {
        Self::Unauthenticated {
            reason: reason.into(),
        }
    }

    /// Convenience for version mismatch.
    #[must_use]
    pub fn version_mismatch(expected: u16, actual: u16) -> Self {
        Self::VersionMismatch { expected, actual }
    }

    /// Convenience for generic denied.
    #[must_use]
    pub fn denied(code: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Denied {
            code: code.into(),
            reason: reason.into(),
        }
    }

    /// Convenience for not found.
    #[must_use]
    pub fn not_found(reason: impl Into<String>) -> Self {
        Self::NotFound {
            reason: reason.into(),
        }
    }

    /// Stable class for diagnostics and doctor aggregation.
    #[must_use]
    pub fn error_class(&self) -> ErrorClass {
        match self {
            Self::FrameTooLarge { .. }
            | Self::PayloadTooLarge { .. }
            | Self::FrameTruncated { .. }
            | Self::InvalidFrame { .. }
            | Self::LimitExceeded { .. } => ErrorClass::Framing,
            Self::ChannelFull { .. } | Self::ChannelClosed { .. } => ErrorClass::Channel,
            Self::TransportClosed { .. } | Self::TransportFull { .. } | Self::Transport { .. } => {
                ErrorClass::Transport
            }
            Self::Timeout { .. } => ErrorClass::Timeout,
            Self::InvalidMethod { .. }
            | Self::InvalidRequest { .. }
            | Self::VersionMismatch { .. } => ErrorClass::Validation,
            Self::PendingLimitExceeded { .. } => ErrorClass::Channel,
            Self::ScopeDenied { .. } => ErrorClass::Scope,
            Self::Unauthenticated { .. } => ErrorClass::Unauthenticated,
            Self::Denied { .. } => ErrorClass::Denied,
            Self::NotFound { .. } => ErrorClass::NotFound,
            Self::Unavailable { .. } => ErrorClass::Unavailable,
            Self::Internal { .. } => ErrorClass::Internal,
        }
    }
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { actual, limit } => {
                write!(f, "frame too large: {actual} bytes exceeds limit {limit}")
            }
            Self::PayloadTooLarge {
                field,
                limit,
                actual,
            } => write!(f, "{field}: payload {actual} exceeds limit {limit}"),
            Self::FrameTruncated { expected, actual } => {
                write!(
                    f,
                    "frame truncated: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidFrame { reason } => write!(f, "invalid frame: {reason}"),
            Self::ChannelFull { capacity } => write!(f, "channel full (capacity {capacity})"),
            Self::ChannelClosed { reason } => write!(f, "channel closed: {reason}"),
            Self::TransportClosed { reason } => write!(f, "transport closed: {reason}"),
            Self::TransportFull { capacity } => {
                write!(f, "transport full (capacity {capacity} frames)")
            }
            Self::Transport { reason } => write!(f, "transport error: {reason}"),
            Self::Timeout {
                request_id,
                timeout_ms,
            } => write!(f, "request {request_id} timed out after {timeout_ms} ms"),
            Self::PendingLimitExceeded { limit, actual } => {
                write!(f, "pending limit {limit} exceeded (actual {actual})")
            }
            Self::InvalidMethod { method, reason } => {
                write!(f, "invalid method '{method}': {reason}")
            }
            Self::InvalidRequest { reason } => write!(f, "invalid request: {reason}"),
            Self::ScopeDenied { scope, action } => {
                write!(f, "scope '{scope}' denied for action '{action}'")
            }
            Self::LimitExceeded {
                field,
                limit,
                actual,
            } => write!(f, "{field}: limit {limit} exceeded (actual {actual})"),
            Self::VersionMismatch { expected, actual } => {
                write!(f, "version mismatch: expected {expected}, got {actual}")
            }
            Self::Unauthenticated { reason } => write!(f, "unauthenticated: {reason}"),
            Self::Denied { code, reason } => write!(f, "denied [{code}]: {reason}"),
            Self::NotFound { reason } => write!(f, "not found: {reason}"),
            Self::Unavailable { reason } => write!(f, "unavailable: {reason}"),
            Self::Internal { reason } => write!(f, "internal: {reason}"),
        }
    }
}

impl std::error::Error for IpcError {}
