//! Generic execution IPC verbs (RUN-19, #1050).
//!
//! Reconciles the `execution.*` verbs with the accepted agent surface: one
//! countable verb list, one scope rule, RFC wire grammar on every name. The
//! verbs mirror the supervisor's capability-scoped operations one-to-one
//! (`spawn_as`/`get_as`/`list_as`/`read_output_as`/`output_index_as`/
//! `write_input_as`/`signal_as`/`cancel_as`/`attach_as`/`events_since_as`/
//! `acknowledge_as`); the capability-plane operations (`grant_as`/
//! `revoke_as`/`transfer_as`) are intentionally excluded — grant management
//! crosses the authorization boundary, not the execution data plane, and its
//! transport binding is a separate review.
//!
//! Every verb requires [`Scope::ProcessSpawn`]: execution verbs are never
//! split into observe/control bundles (the CTX-0514 invariant), and
//! [`EXECUTION_SCOPE`] already documents that supervised execution is always
//! separate and requires elevation.
//!
//! Transport note: the generic scope registry
//! (`scope::required_scope_for_method` / `scope::all_known_methods`) is
//! deliberately unchanged here, so the R-011 sync tests stay green. The host
//! boundary authenticates the principal, checks
//! [`required_scope_for_verb`], then dispatches to the matching `*_as`
//! supervisor method; registering these verbs in the generic transport
//! registry is the follow-up that flips them from reconciled to routable.

use bitty_ipc_api::error::IpcError;
use bitty_ipc_api::scope::{Scope, validate_method_name};

/// Spawn a supervised job (`spawn_as`).
pub const EXECUTION_SPAWN_VERB: &str = "execution.spawn";
/// Fetch one job snapshot (`get_as`).
pub const EXECUTION_GET_VERB: &str = "execution.get";
/// List tracked jobs (`list_as`).
pub const EXECUTION_LIST_VERB: &str = "execution.list";
/// Read retained output bytes (`read_output_as`).
pub const EXECUTION_READ_OUTPUT_VERB: &str = "execution.read_output";
/// Read the metadata-only output index (`output_index_as`).
pub const EXECUTION_OUTPUT_INDEX_VERB: &str = "execution.output_index";
/// Write bytes to job stdin (`write_input_as`).
pub const EXECUTION_WRITE_INPUT_VERB: &str = "execution.write_input";
/// Deliver a signal intent (`signal_as`).
pub const EXECUTION_SIGNAL_VERB: &str = "execution.signal";
/// Request cancellation (`cancel_as`).
pub const EXECUTION_CANCEL_VERB: &str = "execution.cancel";
/// Attach to a running job (`attach_as`).
pub const EXECUTION_ATTACH_VERB: &str = "execution.attach";
/// Drain or replay delivery events (`events_since_as`).
pub const EXECUTION_EVENTS_VERB: &str = "execution.events";
/// Acknowledge critical events (`acknowledge_as`).
pub const EXECUTION_ACKNOWLEDGE_VERB: &str = "execution.acknowledge";

/// All generic execution verbs (11, wire-stable).
///
/// The single countable list backing [`required_scope_for_verb`]: every entry
/// maps to `Some`, and every `Some` mapping has its verb here.
pub const EXECUTION_VERBS: &[&str] = &[
    EXECUTION_SPAWN_VERB,
    EXECUTION_GET_VERB,
    EXECUTION_LIST_VERB,
    EXECUTION_READ_OUTPUT_VERB,
    EXECUTION_OUTPUT_INDEX_VERB,
    EXECUTION_WRITE_INPUT_VERB,
    EXECUTION_SIGNAL_VERB,
    EXECUTION_CANCEL_VERB,
    EXECUTION_ATTACH_VERB,
    EXECUTION_EVENTS_VERB,
    EXECUTION_ACKNOWLEDGE_VERB,
];

/// Whether `method` is a generic execution verb.
#[must_use]
pub fn is_execution_verb(method: &str) -> bool {
    EXECUTION_VERBS.contains(&method)
}

/// Required scope for an execution verb.
///
/// Returns `Some(Scope::ProcessSpawn)` for every known verb and `None` for
/// anything else (unknown verb -> `NotFound` at the boundary, never ambient
/// authority).
#[must_use]
pub fn required_scope_for_verb(method: &str) -> Option<Scope> {
    if is_execution_verb(method) {
        Some(Scope::ProcessSpawn)
    } else {
        None
    }
}

/// Validates an execution verb name: RFC wire grammar first, then membership.
///
/// Returns the matched verb on success.
///
/// # Errors
///
/// - `InvalidMethod` when the name violates the RFC wire grammar.
/// - `NotFound` when the name is well-formed but not an execution verb.
pub fn validate_execution_verb(method: &str) -> Result<&'static str, IpcError> {
    validate_method_name(method)?;
    EXECUTION_VERBS
        .iter()
        .copied()
        .find(|verb| *verb == method)
        .ok_or_else(|| IpcError::NotFound {
            reason: format!("unknown execution verb '{method}'"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_verb_validates_and_requires_process_spawn() {
        assert_eq!(EXECUTION_VERBS.len(), 11);
        for verb in EXECUTION_VERBS {
            assert_eq!(validate_execution_verb(verb), Ok(*verb));
            assert_eq!(required_scope_for_verb(verb), Some(Scope::ProcessSpawn));
            assert!(is_execution_verb(verb));
        }
    }

    #[test]
    fn registry_and_mapping_stay_in_sync() {
        // Every list entry maps; every mapped verb is listed.
        for verb in EXECUTION_VERBS {
            assert!(
                required_scope_for_verb(verb).is_some(),
                "{verb} must map to a scope"
            );
        }
        for candidate in [
            EXECUTION_SPAWN_VERB,
            EXECUTION_GET_VERB,
            EXECUTION_LIST_VERB,
            EXECUTION_READ_OUTPUT_VERB,
            EXECUTION_OUTPUT_INDEX_VERB,
            EXECUTION_WRITE_INPUT_VERB,
            EXECUTION_SIGNAL_VERB,
            EXECUTION_CANCEL_VERB,
            EXECUTION_ATTACH_VERB,
            EXECUTION_EVENTS_VERB,
            EXECUTION_ACKNOWLEDGE_VERB,
        ] {
            assert!(
                EXECUTION_VERBS.contains(&candidate),
                "{candidate} must be listed"
            );
        }
    }

    #[test]
    fn unknown_verbs_fail_closed() {
        assert!(!is_execution_verb("execution.grant"));
        assert_eq!(required_scope_for_verb("execution.grant"), None);
        assert_eq!(required_scope_for_verb("terminal.text"), None);
        assert!(matches!(
            validate_execution_verb("execution.grant"),
            Err(IpcError::NotFound { .. })
        ));
    }

    #[test]
    fn malformed_names_fail_as_invalid_method() {
        assert!(matches!(
            validate_execution_verb(""),
            Err(IpcError::InvalidMethod { .. })
        ));
        assert!(matches!(
            validate_execution_verb("Execution.spawn"),
            Err(IpcError::InvalidMethod { .. })
        ));
        assert!(matches!(
            validate_execution_verb("execution..spawn"),
            Err(IpcError::InvalidMethod { .. })
        ));
    }
}
