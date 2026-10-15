//! IPC-side mapping for S2 domain refusal classes (wiring item 4).
//!
//! The S2 envelope vocabulary reports refusals with counts and bounds only,
//! never caller bytes (bitty-ai `provider_registry.rs` `IpcEnvelopeError`,
//! `ProviderIpcError`; `context_providers.rs` `ContextReadError`;
//! `cache_disclosure.rs` `CacheHintError`/`FallbackError`). This module states
//! the IPC-side expression of each refusal class named in the verdict as an
//! executable table: [`AgentRefusal::to_ipc_error`]. No new [`IpcError`]
//! variant is introduced; every class below maps onto the accepted RFC error
//! taxonomy (RFC §Wire protocol, "Error taxonomy": `InvalidFrame`,
//! `PayloadTooLarge`, `MethodInvalid`, `VersionMismatch`, `Unauthenticated`,
//! `Denied` with `ScopeViolation`/`RateLimited`/`PayloadCap`/`ChunkViolation`
//! sub-codes, `Timeout`, `NotFound`, `Conflict`, `Unavailable`, `Internal`).
//!
//! Where the mapping is interpretive rather than mechanical, the variant is
//! marked `CANDIDATE (CTX-0005)` and needs security/architecture reviewer
//! confirmation before transport scoping. Scope assignment (which required
//! scope an AI op carries) and per-op consent gating are batch-2 work
//! (wiring items 1 and 7) and are not decided here: the table uses the
//! scope-free `Denied` code form everywhere a scope denial is expressed, and
//! batch 2 may refine rows to `ScopeDenied` once the registry entries exist.

use crate::error::IpcError;

// ── refusal classes ─────────────────────────────────────────────────────────

/// S2 refusal class mirror for IPC-side error mapping.
///
/// Counts and bounds only, never caller bytes: variants carry `limit`/`actual`
/// pairs or nothing, so logging or transporting the mapped [`IpcError`]
/// cannot leak caller input. This mirrors the S2 convention without depending
/// on any `bitty-ai` crate (dependency direction is one-way: `bitty-ai`
/// consumes `bitty-ipc-api`, never the reverse).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRefusal {
    /// Effect uncertainty with lost acknowledgement (S2 `Unknown` / ack-loss).
    ///
    /// The operation may have happened; retrying blindly or failing over to
    /// another provider is unsafe. Maps to [`IpcError::Unavailable`]:
    /// fail-closed, reconcile-before-retry, never blind fallback.
    ///
    /// // CANDIDATE (CTX-0005): confirm with security/architecture reviewer.
    /// The verdict flagged this semantic choice (`Unknown` -> `Unavailable`
    /// vs a new code). `Unavailable` is recommended because the accepted RFC
    /// taxonomy already carries "service unavailable or connection shed" with
    /// fail-closed reconcile semantics (RFC §Wire protocol, "Error
    /// taxonomy"), and no new error variant is warranted (a new variant
    /// would need an RFC revision per the accepted versioning rules).
    UnknownAckLoss,
    /// Reserved caller-scope declaration on a `list_models`-class request
    /// (S2 `ReservedScopeDenied`, MP-4 filtering deferred).
    ///
    /// Maps to `Denied` with code `ScopeViolation`: the denial is about
    /// scope posture, but the required-scope registry entries for AI ops are
    /// batch-2 work (wiring item 1), so no `ScopeDenied` scope string is
    /// assigned here. Batch 2 may refine this row to `ScopeDenied` once the
    /// entries exist.
    ReservedScopeDenied,
    /// Declared payload exceeds its budget (S2 `BudgetExceeded`).
    ///
    /// Maps to `Denied` with code `PayloadCap`, the accepted RC-9 expression
    /// for "payload beyond cap is rejected whole" (RFC §Rate limits and
    /// budgets, RC-9 row). Fail-closed with no partial state (RFC §Failure
    /// semantics, FS-IP1).
    BudgetExceeded {
        /// Budget in bytes.
        limit: usize,
        /// Observed bytes.
        actual: usize,
    },
    /// Requested timeout exceeds the hard ceiling (S2 `TimeoutTooLarge`).
    ///
    /// Maps to [`IpcError::InvalidRequest`], the same shape the channel
    /// already enforces at construction (`IpcRequest::new` rejects
    /// `timeout_ms` of `0` or above `MAX_REQUEST_TIMEOUT_MS` with
    /// `InvalidRequest`).
    TimeoutTooLarge {
        /// Hard ceiling in milliseconds.
        max: u64,
        /// Requested timeout in milliseconds.
        actual: u64,
    },
    /// Domain codec bytes do not follow the envelope wire form (S2
    /// `FallbackError::Malformed`: bad magic, short or overrunning framing,
    /// non-UTF-8 field, or trailing bytes).
    ///
    /// Maps to [`IpcError::InvalidFrame`]: the nested domain codec failed
    /// inside `params`/`result`, and the wire envelope reports the framing
    /// failure without parsing further (RFC §Wire protocol, envelope rules).
    MalformedEnvelope,
    /// Cache-hint scope mismatch (S2 `CacheHintError::ScopeMismatch`): the
    /// carried scope differs from the echoed key's scope.
    ///
    /// Maps to [`IpcError::InvalidRequest`]: the S2 shape check
    /// (`CacheHintRequest::validate`) is a pure equality gate, and matching
    /// stays with the caller, so the IPC expression is a shape refusal, not
    /// an authorization verdict.
    ///
    /// // CANDIDATE (CTX-0005): confirm with security/architecture reviewer.
    /// A reviewer could read the mismatch as an authorization signal
    /// (`Denied`/`ScopeViolation`) instead. The shape reading is recommended
    /// because no grant decision runs at this gate.
    CacheScopeMismatch,
    /// Cache-hint key mismatch (S2 `CacheHintError::KeyMismatch`): a
    /// response key does not echo its request key.
    ///
    /// Maps to [`IpcError::InvalidRequest`] for the same shape-gate reason
    /// as [`AgentRefusal::CacheScopeMismatch`].
    ///
    /// // CANDIDATE (CTX-0005): confirm with security/architecture reviewer.
    CacheKeyMismatch,
    /// Context read with no scopes (S2 `ContextReadError::EmptyScopes`).
    ///
    /// Maps to [`IpcError::InvalidRequest`]: a required field is missing
    /// (RFC §Failure semantics, FS-IP1 transactional denial).
    ContextReadEmpty,
    /// Context read over a count bound (S2 `ContextReadError::TooManyScopes`
    /// / `TooManyRecords` / `TooManyAbsences`).
    ///
    /// Maps to [`IpcError::LimitExceeded`] with the S2 `{limit, actual}`
    /// pair carried over: this matches the established codebase pattern for
    /// count/length overruns (`method`/`id` length checks map to
    /// `LimitExceeded`, while byte payloads map to `PayloadTooLarge`).
    ///
    /// // CANDIDATE (CTX-0005): confirm with security/architecture reviewer.
    /// The alternative is `Denied` with code `PayloadCap` (RC-9 language).
    /// `LimitExceeded` is recommended because the S2 refusal shape is a
    /// `{limit, actual}` count pair, which `LimitExceeded` preserves exactly.
    ContextReadTooMany {
        /// Which count bound was exceeded.
        field: ContextReadCount,
        /// Bound.
        limit: usize,
        /// Observed count.
        actual: usize,
    },
}

/// Which context-read count bound an [`AgentRefusal::ContextReadTooMany`]
/// refusal exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextReadCount {
    /// Requested scopes over `MAX_CONTEXT_RECORDS`.
    Scopes,
    /// Carried records over `MAX_CONTEXT_RECORDS`.
    Records,
    /// Absence entries over `MAX_ARTIFACTS`.
    Absences,
}

impl ContextReadCount {
    /// Stable field label carried in the mapped [`IpcError::LimitExceeded`].
    #[must_use]
    pub fn field(self) -> &'static str {
        match self {
            Self::Scopes => "context.scopes",
            Self::Records => "context.records",
            Self::Absences => "context.absences",
        }
    }
}

// ── mapping ─────────────────────────────────────────────────────────────────

impl AgentRefusal {
    /// Map this refusal class to its IPC-side [`IpcError`] expression.
    ///
    /// Total: every variant maps, with no wildcard arm, so adding a variant
    /// forces an explicit classification here (fail-closed on new failure
    /// modes, mirroring the S2 total-mapping discipline).
    #[must_use]
    pub fn to_ipc_error(&self) -> IpcError {
        match *self {
            // CANDIDATE (CTX-0005): confirm with security/architecture reviewer.
            Self::UnknownAckLoss => IpcError::Unavailable {
                reason: "domain reports uncertain effect (ack lost); reconcile before retry".into(),
            },
            Self::ReservedScopeDenied => IpcError::Denied {
                code: "ScopeViolation".into(),
                reason: "caller scope on list-style request is reserved and denied".into(),
            },
            Self::BudgetExceeded { limit, actual } => IpcError::Denied {
                code: "PayloadCap".into(),
                reason: format!("payload {actual} exceeds budget {limit}"),
            },
            Self::TimeoutTooLarge { max, actual } => IpcError::InvalidRequest {
                reason: format!("timeout {actual}ms exceeds ceiling {max}ms"),
            },
            Self::MalformedEnvelope => IpcError::InvalidFrame {
                reason: "domain envelope bytes do not follow the codec wire form".into(),
            },
            // CANDIDATE (CTX-0005): confirm with security/architecture reviewer.
            Self::CacheScopeMismatch => IpcError::InvalidRequest {
                reason: "cache hint scope does not match key scope".into(),
            },
            // CANDIDATE (CTX-0005): confirm with security/architecture reviewer.
            Self::CacheKeyMismatch => IpcError::InvalidRequest {
                reason: "cache hint response key does not echo the request key".into(),
            },
            Self::ContextReadEmpty => IpcError::InvalidRequest {
                reason: "context read requires at least one scope".into(),
            },
            // CANDIDATE (CTX-0005): confirm with security/architecture reviewer.
            Self::ContextReadTooMany {
                field,
                limit,
                actual,
            } => IpcError::LimitExceeded {
                field: field.field().into(),
                limit,
                actual,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorClass;

    #[test]
    fn unknown_ack_loss_maps_to_unavailable_candidate() {
        // CANDIDATE (CTX-0005): Unknown -> Unavailable (no new error variant).
        let err = AgentRefusal::UnknownAckLoss.to_ipc_error();
        assert_eq!(err.error_class(), ErrorClass::Unavailable);
        assert!(matches!(err, IpcError::Unavailable { .. }));
    }

    #[test]
    fn reserved_scope_denied_maps_to_denied_scope_violation() {
        let err = AgentRefusal::ReservedScopeDenied.to_ipc_error();
        assert_eq!(err.error_class(), ErrorClass::Denied);
        assert!(matches!(
            err,
            IpcError::Denied { ref code, .. } if code == "ScopeViolation"
        ));
    }

    #[test]
    fn budget_exceeded_maps_to_denied_payload_cap() {
        let err = AgentRefusal::BudgetExceeded {
            limit: 1024,
            actual: 2048,
        }
        .to_ipc_error();
        assert_eq!(err.error_class(), ErrorClass::Denied);
        assert!(matches!(
            err,
            IpcError::Denied { ref code, .. } if code == "PayloadCap"
        ));
    }

    #[test]
    fn timeout_too_large_maps_to_invalid_request() {
        let err = AgentRefusal::TimeoutTooLarge {
            max: 30_000,
            actual: 60_000,
        }
        .to_ipc_error();
        assert!(matches!(err, IpcError::InvalidRequest { .. }));
        assert_eq!(err.error_class(), ErrorClass::Validation);
    }

    #[test]
    fn malformed_envelope_maps_to_invalid_frame() {
        let err = AgentRefusal::MalformedEnvelope.to_ipc_error();
        assert!(matches!(err, IpcError::InvalidFrame { .. }));
        assert_eq!(err.error_class(), ErrorClass::Framing);
    }

    #[test]
    fn cache_hint_mismatches_map_to_invalid_request() {
        for refusal in [
            AgentRefusal::CacheScopeMismatch,
            AgentRefusal::CacheKeyMismatch,
        ] {
            let err = refusal.to_ipc_error();
            assert!(
                matches!(err, IpcError::InvalidRequest { .. }),
                "{refusal:?}"
            );
        }
    }

    #[test]
    fn context_read_empty_maps_to_invalid_request() {
        let err = AgentRefusal::ContextReadEmpty.to_ipc_error();
        assert!(matches!(err, IpcError::InvalidRequest { .. }));
    }

    #[test]
    fn context_read_counts_map_to_limit_exceeded_with_fields() {
        for (field, label) in [
            (ContextReadCount::Scopes, "context.scopes"),
            (ContextReadCount::Records, "context.records"),
            (ContextReadCount::Absences, "context.absences"),
        ] {
            let err = AgentRefusal::ContextReadTooMany {
                field,
                limit: 128,
                actual: 129,
            }
            .to_ipc_error();
            assert!(
                matches!(
                    err,
                    IpcError::LimitExceeded { ref field, limit: 128, actual: 129 } if field == label
                ),
                "{field:?}"
            );
        }
    }

    #[test]
    fn mapping_carries_counts_never_caller_bytes() {
        // Refusal variants are counts-only by construction; the mapped errors
        // echo limits/actuals plus static reasons, never caller payload.
        let err = AgentRefusal::BudgetExceeded {
            limit: 100,
            actual: 200,
        }
        .to_ipc_error();
        let shown = format!("{err}");
        assert!(shown.contains("100") && shown.contains("200"));
    }
}
