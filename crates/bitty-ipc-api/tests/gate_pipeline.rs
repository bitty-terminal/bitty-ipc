//! Gate-pipeline ordering test for incoming `ai.*` requests (CTX-0008, S-A).
//!
//! S-E handler contract (bitty-ai side): every future `ai.*` handler must run
//! these gates in this order over the existing pure pieces, refusing at the
//! first failure without running later gates or contacting the handler:
//!
//! 1. Method resolution (`authorize_method` over `required_scope_for_method`,
//!    `scope.rs`): an unknown method refuses `NotFound` before any
//!    scope or consent state is consulted (fail-closed, FS-IP1; there is no
//!    `ai.`-namespace wildcard, so even every scope granted cannot reach an
//!    unregistered name).
//! 2. Scope authorization (`authorize_method` against the server-derived
//!    `ScopeSet`, `scope.rs`): a known method without a grant refuses
//!    `ScopeDenied` before the consent ledger is consulted.
//! 3. Per-op consent (`ConsentLedger::is_granted` for the exact
//!    `(client_id, scope)` at `now_ms`, `scope.rs`): a missing, revoked, or
//!    expired grant refuses `ScopeDenied` before deadline or JSON work.
//! 4. Deadline (`validate_domain_timeout` at construction plus
//!    `IpcEndpoint::drain_expired` at dispatch, `deadline.rs` + `channel.rs`):
//!    an expired request refuses `Timeout` and is reaped from both the
//!    pending table and the queue (no-exec-after-timeout) before JSON
//!    validation. The construction-time expression of an oversized domain
//!    timeout is `InvalidRequest` via `AgentRefusal::TimeoutTooLarge`
//!    (`refusal.rs`); the dispatch-time expression is `Timeout` here.
//! 5. Params JSON (`validate_params_json`: frame bound, UTF-8, depth 32, no
//!    top-level `auth`/`scope`/`role`, `json.rs`): malformed params refuse
//!    with a validation error (`InvalidRequest`, `InvalidFrame`, or
//!    `PayloadTooLarge`, see `error.rs`) with no handler contact.
//! 6. Dispatch: only a request that passes every gate reaches the handler.
//!
//! Each refusal test below poisons every later gate (inputs that would fail
//! there too) and asserts the early gate's error, its error class from the
//! taxonomy (`error.rs`), and probe flags proving the later gates never ran.
//! The positive test proves lawful traffic is admitted.
//!
//! Test-only: public API only, no new public items, no transport code. The
//! documented registry and consent defaults live in `docs/s2-wiring-batch2.md`.

use std::cell::Cell;

use bitty_ipc_api::{
    AgentRefusal, ConsentLedger, ErrorClass, IpcEndpoint, IpcError, IpcRequest, Scope, ScopeSet,
    authorize_method, domain_deadline_ms, required_scope_for_method, validate_domain_timeout,
    validate_method_name, validate_params_json,
};

const CLIENT: &str = "agent-7";
const INSPECT_METHOD: &str = "ai.model_select";
const INVOKE_METHOD: &str = "ai.tool_dispatch";
const UNKNOWN_METHOD: &str = "ai.evil";
const MALFORMED_PARAMS: &[u8] = br#"{"scope":"ai.invoke"}"#;
const VALID_PARAMS: &[u8] = br#"{"terminal_id":"t:4"}"#;

/// Probe flags recording which pipeline gates actually ran.
#[derive(Default)]
struct GateProbe {
    consent_consulted: Cell<bool>,
    deadline_checked: Cell<bool>,
    json_validated: Cell<bool>,
    handler_contacted: Cell<bool>,
}

/// Test-only composition of the gate pipeline in contract order.
///
/// Gates 1-2 run as one `authorize_method` call (resolution refuses `NotFound`
/// before the grant check can run); then consent, deadline, JSON, and finally
/// handler contact. Each gate after the first sets its probe flag when it
/// runs and returns its refusal early, so a test can prove short-circuiting.
#[allow(clippy::too_many_arguments)]
fn run_ai_pipeline(
    method: &str,
    granted: &ScopeSet,
    ledger: &ConsentLedger,
    client_id: &str,
    now_ms: u64,
    created_at_ms: u64,
    timeout_ms: u64,
    params: &[u8],
    endpoint: &mut IpcEndpoint,
    probe: &GateProbe,
) -> Result<Scope, IpcError> {
    // Gates 1-2: method resolution + scope authorization.
    let required = authorize_method(method, granted)?;
    // Gate 3: per-op consent on the exact (client, scope) at now_ms.
    probe.consent_consulted.set(true);
    if !ledger.is_granted(client_id, required, now_ms) {
        return Err(IpcError::ScopeDenied {
            scope: required.as_str().into(),
            action: method.into(),
        });
    }
    // Gate 4: deadline (construction range, then dispatch-time reaping).
    probe.deadline_checked.set(true);
    validate_domain_timeout(timeout_ms)?;
    let id = endpoint.next_request_id();
    let request = IpcRequest::new(
        id,
        method.to_string(),
        params.to_vec(),
        created_at_ms,
        timeout_ms,
    )?;
    endpoint.send_request(request)?;
    if endpoint.drain_expired(now_ms).contains(&id) {
        return Err(IpcError::Timeout {
            request_id: id.0,
            timeout_ms,
        });
    }
    // Gate 5: params JSON validation.
    probe.json_validated.set(true);
    validate_params_json(params)?;
    // Gate 6: handler contact (S-E dispatch owns the real call).
    probe.handler_contacted.set(true);
    Ok(required)
}

/// Ledger with one live grant for `(CLIENT, scope)` covering `now_ms`.
fn ledger_with_live_grant(scope: Scope, now_ms: u64) -> ConsentLedger {
    let mut ledger = ConsentLedger::new();
    ledger
        .grant(CLIENT.to_owned(), scope, 0, 10_000, "user".to_owned())
        .expect("grant fits in an empty ledger");
    assert!(ledger.is_granted(CLIENT, scope, now_ms));
    ledger
}

#[test]
fn unknown_method_refuses_not_found_first() {
    // Grammar-valid but unregistered: resolution fails before any grant check.
    assert!(validate_method_name(UNKNOWN_METHOD).is_ok());
    assert_eq!(required_scope_for_method(UNKNOWN_METHOD), None);
    let granted = ScopeSet::all();
    let ledger = ledger_with_live_grant(Scope::AiInspect, 500);
    let mut endpoint = IpcEndpoint::new();
    let probe = GateProbe::default();
    // Later gates poisoned: expired deadline, malformed params.
    let err = run_ai_pipeline(
        UNKNOWN_METHOD,
        &granted,
        &ledger,
        CLIENT,
        1_000,
        0,
        1_000,
        MALFORMED_PARAMS,
        &mut endpoint,
        &probe,
    )
    .unwrap_err();
    assert!(
        matches!(&err, IpcError::NotFound { .. }),
        "unexpected: {err:?}"
    );
    assert_eq!(err.error_class(), ErrorClass::NotFound);
    assert!(!probe.consent_consulted.get());
    assert!(!probe.deadline_checked.get());
    assert!(!probe.json_validated.get());
    assert!(!probe.handler_contacted.get());
    assert_eq!(endpoint.request_len(), 0);
    assert_eq!(endpoint.pending_count(), 0);
}

#[test]
fn missing_grant_refuses_scope_denied_before_consent() {
    // The CLI default carries no ai scope; the ledger WOULD allow, but the
    // scope gate denies first without consulting it.
    let granted = ScopeSet::cli_default();
    assert!(!granted.contains(Scope::AiInspect));
    let ledger = ledger_with_live_grant(Scope::AiInspect, 500);
    let mut endpoint = IpcEndpoint::new();
    let probe = GateProbe::default();
    // Later gates poisoned: expired deadline, malformed params.
    let err = run_ai_pipeline(
        INSPECT_METHOD,
        &granted,
        &ledger,
        CLIENT,
        1_000,
        0,
        1_000,
        MALFORMED_PARAMS,
        &mut endpoint,
        &probe,
    )
    .unwrap_err();
    assert!(
        matches!(
            &err,
            IpcError::ScopeDenied { scope, action }
            if scope == "ai.inspect" && action == INSPECT_METHOD
        ),
        "unexpected: {err:?}"
    );
    assert_eq!(err.error_class(), ErrorClass::Scope);
    assert!(!probe.consent_consulted.get());
    assert!(!probe.deadline_checked.get());
    assert!(!probe.json_validated.get());
    assert!(!probe.handler_contacted.get());
    assert_eq!(endpoint.request_len(), 0);
    assert_eq!(endpoint.pending_count(), 0);
}

#[test]
fn consent_denial_refuses_before_deadline_and_json() {
    let granted = ScopeSet::single(Scope::AiInspect);
    let never = ConsentLedger::new();
    let mut expired = ConsentLedger::new();
    expired
        .grant(
            CLIENT.to_owned(),
            Scope::AiInspect,
            0,
            100,
            "user".to_owned(),
        )
        .unwrap();
    let mut revoked = ConsentLedger::new();
    revoked
        .grant(
            CLIENT.to_owned(),
            Scope::AiInspect,
            0,
            10_000,
            "user".to_owned(),
        )
        .unwrap();
    assert!(revoked.revoke(CLIENT, Scope::AiInspect));
    // now_ms 1000: every ledger below denies, while the poisoned deadline
    // (created 0 + timeout 1000, at expiry) and malformed params would also
    // fail if those gates ran.
    let cases: [(&str, ConsentLedger, u64); 3] = [
        ("never-granted", never, 1_000),
        ("expired", expired, 1_000),
        ("revoked", revoked, 1_000),
    ];
    for (label, ledger, now_ms) in cases {
        let mut endpoint = IpcEndpoint::new();
        let probe = GateProbe::default();
        let err = run_ai_pipeline(
            INSPECT_METHOD,
            &granted,
            &ledger,
            CLIENT,
            now_ms,
            0,
            1_000,
            MALFORMED_PARAMS,
            &mut endpoint,
            &probe,
        )
        .unwrap_err();
        assert!(
            matches!(
                &err,
                IpcError::ScopeDenied { scope, .. } if scope == "ai.inspect"
            ),
            "{label}: unexpected {err:?}"
        );
        assert_eq!(err.error_class(), ErrorClass::Scope, "{label}");
        assert!(probe.consent_consulted.get(), "{label}");
        assert!(!probe.deadline_checked.get(), "{label}");
        assert!(!probe.json_validated.get(), "{label}");
        assert!(!probe.handler_contacted.get(), "{label}");
        assert_eq!(endpoint.request_len(), 0, "{label}");
        assert_eq!(endpoint.pending_count(), 0, "{label}");
    }
}

#[test]
fn expired_deadline_refuses_timeout_before_json() {
    let granted = ScopeSet::single(Scope::AiInspect);
    let ledger = ledger_with_live_grant(Scope::AiInspect, 500);
    let mut endpoint = IpcEndpoint::new();
    let probe = GateProbe::default();
    // Caller-now_ms mapping: the absolute deadline is the saturating sum.
    let created_at_ms = 0;
    let timeout_ms = 1_000;
    let deadline = domain_deadline_ms(created_at_ms, timeout_ms);
    assert!(validate_domain_timeout(timeout_ms).is_ok());
    // Params would ALSO fail JSON validation: the timeout refusal must win.
    let err = run_ai_pipeline(
        INSPECT_METHOD,
        &granted,
        &ledger,
        CLIENT,
        deadline,
        created_at_ms,
        timeout_ms,
        MALFORMED_PARAMS,
        &mut endpoint,
        &probe,
    )
    .unwrap_err();
    assert!(
        matches!(
            &err,
            IpcError::Timeout {
                request_id: 1,
                timeout_ms: 1_000
            }
        ),
        "unexpected: {err:?}"
    );
    assert_eq!(err.error_class(), ErrorClass::Timeout);
    assert!(probe.consent_consulted.get());
    assert!(probe.deadline_checked.get());
    assert!(!probe.json_validated.get());
    assert!(!probe.handler_contacted.get());
    // Reaped from both the pending table and the queue: no exec-after-timeout.
    assert_eq!(endpoint.pending_count(), 0);
    assert_eq!(endpoint.request_len(), 0);
    assert!(endpoint.recv_request().is_none());
    // Companion: the construction-time expression of an oversized domain
    // timeout is InvalidRequest via the refusal table, distinct from this
    // dispatch-time Timeout.
    let construction = AgentRefusal::TimeoutTooLarge {
        max: 30_000,
        actual: 60_000,
    }
    .to_ipc_error();
    assert!(matches!(construction, IpcError::InvalidRequest { .. }));
}

#[test]
fn malformed_params_refuse_without_handler_contact() {
    let granted = ScopeSet::single(Scope::AiInspect);
    let ledger = ledger_with_live_grant(Scope::AiInspect, 1_000);
    let non_utf8 = [0x7b, 0x22, 0xff, 0x22, 0x7d];
    // Live deadline throughout (created 0 + timeout 5000, now 1000).
    let cases: [(&str, &[u8], ErrorClass); 2] = [
        (
            "ambient-authority",
            MALFORMED_PARAMS,
            ErrorClass::Validation,
        ),
        ("non-utf8", &non_utf8, ErrorClass::Framing),
    ];
    for (label, params, class) in cases {
        let mut endpoint = IpcEndpoint::new();
        let probe = GateProbe::default();
        let err = run_ai_pipeline(
            INSPECT_METHOD,
            &granted,
            &ledger,
            CLIENT,
            1_000,
            0,
            5_000,
            params,
            &mut endpoint,
            &probe,
        )
        .unwrap_err();
        assert!(
            matches!(
                &err,
                IpcError::InvalidRequest { .. } | IpcError::InvalidFrame { .. }
            ),
            "{label}: unexpected {err:?}"
        );
        assert_eq!(err.error_class(), class, "{label}");
        assert!(probe.consent_consulted.get(), "{label}");
        assert!(probe.deadline_checked.get(), "{label}");
        assert!(probe.json_validated.get(), "{label}");
        assert!(!probe.handler_contacted.get(), "{label}");
    }
}

#[test]
fn fully_authorized_request_passes_all_gates() {
    // Both ai families admit lawful traffic: an inspect method and an invoke
    // method, each with its exact grant, live consent, live deadline, and
    // valid params.
    for (method, scope) in [
        (INSPECT_METHOD, Scope::AiInspect),
        (INVOKE_METHOD, Scope::AiInvoke),
    ] {
        let granted = ScopeSet::single(scope);
        let ledger = ledger_with_live_grant(scope, 1_000);
        let mut endpoint = IpcEndpoint::new();
        let probe = GateProbe::default();
        let out = run_ai_pipeline(
            method,
            &granted,
            &ledger,
            CLIENT,
            1_000,
            0,
            5_000,
            VALID_PARAMS,
            &mut endpoint,
            &probe,
        );
        assert_eq!(out, Ok(scope), "{method}");
        assert!(probe.consent_consulted.get(), "{method}");
        assert!(probe.deadline_checked.get(), "{method}");
        assert!(probe.json_validated.get(), "{method}");
        assert!(probe.handler_contacted.get(), "{method}");
        // The live request stays queued for dispatch: nothing was reaped.
        assert_eq!(endpoint.pending_count(), 1, "{method}");
        assert_eq!(endpoint.request_len(), 1, "{method}");
    }
}
