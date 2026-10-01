use super::*;

#[cfg(any(test, feature = "test-support"))]
use bitty_ipc_api::error::IpcError;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

// ── test automation (CTX-0188, Amendment A1 candidate) ───────────────────────
//
// `synthesizeInput` (keystroke injection) and `captureFrame` (frame capture)
// for the headless verify harness. Security lens mandatory: fail closed
// everywhere.
//
// - Scopes: `synthesizeInput` requires `debug.control` + `terminal.input`;
//   `captureFrame` requires `debug.trace` + `terminal.inspect` (capability-
//   plus-scope intersection, `getSnapshot` parity). Either missing yields
//   `scope`/`ScopeDenied` with zero partial state.
// - Bearers: per-session single-terminal sub-grants bound to the owning
//   connection's session, principal, and consent generation (no IPC issuance
//   method, no env/config/flag path, never persisted, 10 min TTL). Production
//   issuance waits on the consent gesture (#1520); the context-free minters
//   are `test-support` only (#1519). Unscoped callers (absent, expired,
//   wrong-session, wrong-terminal, wrong-family) get `scope`/`ScopeDenied`.
// - Bounds: 64 events/call, 10 calls/s (`synthesizeInput`), 10 fps
//   (`captureFrame`), params 32 KiB, responses 32 KiB, frames 256 KiB.
// - Redaction: P0-AC-026 parity before any frame enters a response;
//   `pixels` is masked (zero text), per-call opt-in, audited.
// - Headless receipt semantics: `synthesizeInput` success means validated,
//   authorized, rate-checked, and marked synthetic (input-ring publish with
//   indelible `[synthetic]` marker); the servo applies injection on the main
//   thread as follow-up. `captureFrame` serves the redacted grid store.

/// Automation method family bound into each bearer (never widened: a
/// synthesize bearer cannot capture, a capture bearer cannot digest, and
/// vice versa — CTX-0244: widening `Capture` would silently upgrade every
/// outstanding 10-minute bearer into a digest oracle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutomationFamily {
    /// `synthesizeInput` family (`debug.control`).
    Synthesize,
    /// `captureFrame` family (`debug.trace`).
    Capture,
    /// `frameHash` digest family (CTX-0244; `debug.trace` +
    /// `terminal.inspect`, 2 min TTL cap, 2 digests/s).
    FrameDigest,
}

impl AutomationFamily {
    /// Canonical family token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Synthesize => "synthesize",
            Self::Capture => "capture",
            Self::FrameDigest => "frame-digest",
        }
    }
}

/// One issued automation bearer (server-side only, never persisted).
#[derive(Debug, Clone)]
struct AutomationBearerRecord {
    /// Session the bearer is bound to (revoked with the session).
    session_id: String,
    /// Principal the bearer is bound to; empty for the unbound legacy
    /// minters, which is why their bearers never satisfy an authority-bound
    /// context.
    principal_id: String,
    /// Consent generation at issuance; a later consent change voids it.
    consent_generation: u64,
    /// Single terminal it may address (`t:N`).
    terminal_id: String,
    /// Method family it may call.
    family: AutomationFamily,
    /// Expiry time (issuance + TTL, saturating; bearer-clock base matches
    /// `ServeContext::uptime_ms`).
    expires_at_ms: u64,
}

/// Terminal capability a family is bound to (never widened: see
/// [`AutomationFamily`]).
fn terminal_scope_for(family: AutomationFamily) -> bitty_ipc_api::scope::Scope {
    match family {
        AutomationFamily::Synthesize => bitty_ipc_api::scope::Scope::TerminalInput,
        AutomationFamily::Capture | AutomationFamily::FrameDigest => {
            bitty_ipc_api::scope::Scope::TerminalInspect
        }
    }
}

/// One audited frame-observation entry (bounded, drop-oldest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameAuditEntry {
    /// Caller session identity.
    pub session_id: String,
    /// Addressed terminal.
    pub terminal_id: String,
    /// Observation format (`semantic`, `pixels`, or `digest`).
    pub format: String,
    /// Bearer-clock time of capture.
    pub now_ms: u64,
    /// Presented frame sequence the entry attests to (`0` when no frame
    /// was observed, e.g. a denied digest call or a text capture).
    pub frame_seq: u64,
    /// Served digest hex for `digest` entries (uninvertible, safe to log);
    /// empty for `semantic`/`pixels` entries and denied calls.
    pub digest_hex: String,
}

/// Automation store: bearers plus per-bearer rate windows, synthetic sequence,
/// and pixels audit. In-memory only (never persisted, never exported).
#[derive(Debug, Default)]
pub(super) struct AutomationStore {
    /// Token to record.
    bearers: BTreeMap<String, AutomationBearerRecord>,
    /// Per-token `synthesizeInput` timestamps (1 s window).
    synth_hits: BTreeMap<String, std::collections::VecDeque<u64>>,
    /// Per-token `captureFrame` timestamps (1 s window).
    capture_hits: BTreeMap<String, std::collections::VecDeque<u64>>,
    /// Per-token `frameHash` timestamps (1 s window, CTX-0244).
    digest_hits: BTreeMap<String, std::collections::VecDeque<u64>>,
    /// Issuance counter (token uniqueness).
    counter: u64,
    /// Monotonic synthetic-event sequence.
    pub(super) synth_seq: u64,
    /// Bounded pixels/semantic audit (drop-oldest at 64).
    pub(super) audit: Vec<FrameAuditEntry>,
}

/// Global automation store (empty until consent issuance).
pub(super) fn automation_store() -> &'static Mutex<AutomationStore> {
    static STORE: OnceLock<Mutex<AutomationStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(AutomationStore::default()))
}

/// Random bytes in one bearer token (128 bits of CSPRNG output).
#[cfg(any(test, feature = "test-support"))]
const BEARER_TOKEN_BYTES: usize = 16;

/// Fill `dest` from the platform CSPRNG, on every platform.
///
/// `getrandom` is the in-tree entropy source (`bitty-rich` already mints its
/// clipboard grant tokens with it, same version line, same purpose): the
/// kernel CSPRNG on unix and `BCryptGenRandom` on Windows, behind one safe API.
/// There is deliberately no fallback and no platform cfg here — a bearer is the
/// authority token for automation synthesize, capture, and frame-digest, so a
/// platform that cannot produce unpredictable bytes must fail the issuance
/// closed rather than mint a token derived from anything weaker (CTX-0792,
/// #1403).
#[cfg(any(test, feature = "test-support"))]
fn fill_secure_random(dest: &mut [u8]) -> Result<(), IpcError> {
    getrandom::fill(dest).map_err(|err| IpcError::Unavailable {
        reason: format!("secure bearer source unavailable: {err}"),
    })
}

#[cfg(any(test, feature = "test-support"))]
fn random_bearer_token() -> Result<String, IpcError> {
    let mut bytes = [0u8; BEARER_TOKEN_BYTES];
    fill_secure_random(&mut bytes)?;
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        token.push_str(&format!("{byte:02x}"));
    }
    Ok(token)
}

/// Validate a session id for bearer binding (1..=64 chars, no NUL/control).
#[cfg(any(test, feature = "test-support"))]
fn validate_session_id(session_id: &str) -> Result<(), IpcError> {
    if session_id.is_empty() || session_id.len() > 64 {
        return Err(IpcError::InvalidRequest {
            reason: "session_id must be 1..=64 bytes".into(),
        });
    }
    if session_id.contains('\0') || session_id.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(IpcError::InvalidRequest {
            reason: "session_id must not contain control bytes".into(),
        });
    }
    Ok(())
}

/// Validate a bearer token shape (opaque, bounded, no control).
fn validate_bearer_shape(token: &str) -> Result<(), ()> {
    if token.is_empty() || token.len() > MAX_BEARER_TOKEN_CHARS {
        return Err(());
    }
    let ok = token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok { Ok(()) } else { Err(()) }
}

/// Issue an unbound automation bearer for one session/terminal/family.
///
/// Test support only (#1519, CORE-RUN-017): this context-free minter binds
/// an empty principal and consent generation 0, so its bearer can never
/// satisfy an authority-bound connection, and production builds do not
/// compile it. There is deliberately no IPC method, env var, config key,
/// flag, or child-inheritance path that issues bearers (P0-AC-023 parity;
/// no-bypass audit); production issuance goes through the connection
/// authority after explicit local-user consent (#1520). The bearer lives
/// in-memory only and expires after [`AUTOMATION_BEARER_TTL_MS`].
///
/// CTX-0244: [`AutomationFamily::FrameDigest`] cannot use this minter — its
/// 10-minute default TTL exceeds the 2-minute digest cap, so digest grants
/// require an explicit `ttl_ms` via
/// [`issue_automation_bearer_with_ttl`] (fail-closed `InvalidRequest`
/// here).
///
/// # Errors
///
/// Returns `InvalidRequest` for bad session/terminal ids and `LimitExceeded`
/// when the store is at capacity (fail-closed, no silent eviction).
#[cfg(any(test, feature = "test-support"))]
pub fn issue_automation_bearer(
    session_id: &str,
    terminal_id: &str,
    family: AutomationFamily,
    now_ms: u64,
) -> Result<String, IpcError> {
    if family == AutomationFamily::FrameDigest {
        return Err(IpcError::InvalidRequest {
            reason: format!(
                "frame-digest bearers require an explicit ttl_ms of 1..={}",
                crate::frame_digest::FRAME_DIGEST_TTL_MS
            ),
        });
    }
    issue_automation_bearer_with_ttl(
        session_id,
        terminal_id,
        family,
        now_ms,
        AUTOMATION_BEARER_TTL_MS,
    )
}

/// Issue with an explicit TTL (capped to [`AUTOMATION_BEARER_TTL_MS`]).
///
/// CTX-0244: [`AutomationFamily::FrameDigest`] bearers carry their own
/// stricter cap ([`crate::frame_digest::FRAME_DIGEST_TTL_MS`], 2 min);
/// larger digest TTLs fail closed.
///
/// # Errors
///
/// Same as [`issue_automation_bearer`], plus `InvalidRequest` when `ttl_ms`
/// is zero or exceeds the cap.
#[cfg(any(test, feature = "test-support"))]
pub fn issue_automation_bearer_with_ttl(
    session_id: &str,
    terminal_id: &str,
    family: AutomationFamily,
    now_ms: u64,
    ttl_ms: u64,
) -> Result<String, IpcError> {
    issue_automation_bearer_internal(
        session_id,
        terminal_id,
        family,
        now_ms,
        ttl_ms,
        BearerBinding::unbound(),
    )
}

/// Issue a bearer bound to one live connection (CTX-0792, #1403).
///
/// The bearer is bound to the connection's session, principal, and current
/// consent generation, and to exactly one terminal and method family. The
/// connection must hold the family's debug scope and terminal scope. Issuance
/// does not touch the connection's terminal capability map: the terminal
/// binding lives in the bearer record itself.
///
/// Test-only until explicit local-user consent is wired: the connection's
/// scopes are an operator ceiling, not consent (see
/// `ServeContext::issue_automation_bearer`).
#[cfg(test)]
pub(crate) fn issue_automation_bearer_for_connection(
    grant: &crate::ctl::ConnectionGrant,
    terminal_id: &str,
    family: AutomationFamily,
    now_ms: u64,
    ttl_ms: Option<u64>,
) -> Result<String, IpcError> {
    let snapshot = grant.snapshot()?;
    let debug_scope = match family {
        AutomationFamily::Synthesize => bitty_ipc_api::scope::Scope::DebugControl,
        AutomationFamily::Capture | AutomationFamily::FrameDigest => {
            bitty_ipc_api::scope::Scope::DebugTrace
        }
    };
    let terminal_scope = terminal_scope_for(family);
    if !snapshot.scopes.contains(debug_scope)
        || !snapshot.allows_terminal(Some(terminal_id), terminal_scope)
    {
        return Err(IpcError::ScopeDenied {
            scope: terminal_scope.as_str().into(),
            action: family.as_str().into(),
        });
    }
    let ttl = ttl_ms.unwrap_or(AUTOMATION_BEARER_TTL_MS);
    issue_automation_bearer_internal(
        &snapshot.identity.session_id,
        terminal_id,
        family,
        now_ms,
        ttl,
        BearerBinding {
            principal_id: snapshot.identity.principal_id.clone(),
            consent_generation: snapshot.identity.consent_generation,
        },
    )
}

/// Identity a minted bearer is bound to.
///
/// The context-free legacy minters pass an empty principal and generation 0,
/// which is why such a bearer can never satisfy an authority-bound check.
#[cfg(any(test, feature = "test-support"))]
struct BearerBinding {
    principal_id: String,
    consent_generation: u64,
}

#[cfg(any(test, feature = "test-support"))]
impl BearerBinding {
    fn unbound() -> Self {
        Self {
            principal_id: String::new(),
            consent_generation: 0,
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
fn issue_automation_bearer_internal(
    session_id: &str,
    terminal_id: &str,
    family: AutomationFamily,
    now_ms: u64,
    ttl_ms: u64,
    binding: BearerBinding,
) -> Result<String, IpcError> {
    validate_session_id(session_id)?;
    crate::ctl::parse_terminal_id(terminal_id)?;
    let ttl_cap = if family == AutomationFamily::FrameDigest {
        crate::frame_digest::FRAME_DIGEST_TTL_MS
    } else {
        AUTOMATION_BEARER_TTL_MS
    };
    if ttl_ms == 0 || ttl_ms > ttl_cap {
        return Err(IpcError::InvalidRequest {
            reason: format!("ttl_ms must be 1..={ttl_cap}"),
        });
    }
    let mut store = automation_store()
        .lock()
        .map_err(|_| IpcError::Unavailable {
            reason: "automation store unavailable".into(),
        })?;
    if store.bearers.len() >= MAX_AUTOMATION_BEARERS && !store.bearers.is_empty() {
        let expired: Vec<String> = store
            .bearers
            .iter()
            .filter(|(_, rec)| now_ms >= rec.expires_at_ms)
            .map(|(tok, _)| tok.clone())
            .collect();
        for tok in expired {
            store.bearers.remove(&tok);
            store.synth_hits.remove(&tok);
            store.capture_hits.remove(&tok);
            store.digest_hits.remove(&tok);
        }
        if store.bearers.len() >= MAX_AUTOMATION_BEARERS {
            return Err(IpcError::LimitExceeded {
                field: "automation_bearers".into(),
                limit: MAX_AUTOMATION_BEARERS,
                actual: store.bearers.len() + 1,
            });
        }
    }
    store.counter = store
        .counter
        .checked_add(1)
        .ok_or_else(|| IpcError::Denied {
            code: "BearerSequenceExhausted".into(),
            reason: "automation bearer sequence exhausted".into(),
        })?;
    let mut token = None;
    for _ in 0..8 {
        let candidate = random_bearer_token()?;
        if !store.bearers.contains_key(&candidate) {
            token = Some(candidate);
            break;
        }
    }
    let token = token.ok_or_else(|| IpcError::Unavailable {
        reason: "secure bearer source repeatedly collided".into(),
    })?;
    let record = AutomationBearerRecord {
        session_id: session_id.to_string(),
        principal_id: binding.principal_id,
        consent_generation: binding.consent_generation,
        terminal_id: terminal_id.to_string(),
        family,
        expires_at_ms: now_ms.saturating_add(ttl_ms),
    };
    store.bearers.insert(token.clone(), record);
    Ok(token)
}

/// Revoke one bearer immediately (explicit revoke + session-end parity).
/// Returns true when a bearer was present.
pub fn revoke_automation_bearer(token: &str) -> bool {
    let Ok(mut store) = automation_store().lock() else {
        return false;
    };
    let existed = store.bearers.remove(token).is_some();
    store.synth_hits.remove(token);
    store.capture_hits.remove(token);
    store.digest_hits.remove(token);
    existed
}

/// Revoke every bearer bound to `session_id` (session end, CTX-0792 #1403).
/// Returns true when at least one bearer was removed.
pub(super) fn revoke_automation_session(session_id: &str) -> bool {
    let Ok(mut store) = automation_store().lock() else {
        return false;
    };
    let tokens: Vec<String> = store
        .bearers
        .iter()
        .filter(|(_, record)| record.session_id == session_id)
        .map(|(token, _)| token.clone())
        .collect();
    for token in &tokens {
        store.bearers.remove(token);
        store.synth_hits.remove(token);
        store.capture_hits.remove(token);
        store.digest_hits.remove(token);
    }
    !tokens.is_empty()
}

/// Clear all automation state (test helper only; production never calls it).
pub fn clear_automation_for_tests() {
    if let Ok(mut store) = automation_store().lock() {
        store.bearers.clear();
        store.synth_hits.clear();
        store.capture_hits.clear();
        store.digest_hits.clear();
        store.counter = 0;
        store.synth_seq = 0;
        store.audit.clear();
    }
    // Input/grid/focus stores are cleared by the caller's introspection
    // helper; automation never clears them here (no cross-module coupling).
}

/// Whether any live [`AutomationFamily::FrameDigest`] bearer exists.
///
/// Production probe for the present path: the runtime publishes RGBA into
/// the digest store only while a digest grant is live, so the multi-MB
/// clone costs nothing when no test holds a grant. Expiry is enforced at
/// authorize time, not here — a stale record only causes bounded extra
/// publishing, never an extra served digest.
#[must_use]
pub fn frame_digest_publish_wanted() -> bool {
    automation_store().lock().is_ok_and(|store| {
        store
            .bearers
            .values()
            .any(|rec| rec.family == AutomationFamily::FrameDigest)
    })
}

/// Number of live bearers (test probe only).
pub fn automation_bearer_count_for_tests() -> usize {
    automation_store()
        .lock()
        .map(|s| s.bearers.len())
        .unwrap_or(0)
}

/// Current synthetic sequence (test probe only).
pub fn synthetic_seq_for_tests() -> u64 {
    automation_store().lock().map(|s| s.synth_seq).unwrap_or(0)
}

/// Number of audited frame captures (test probe only).
pub fn frame_audit_len_for_tests() -> usize {
    automation_store()
        .lock()
        .map(|s| s.audit.len())
        .unwrap_or(0)
}

/// Snapshot of the frame audit log, oldest first (test probe only).
/// Lets digest tests verify `format:"digest"` entries carry the served
/// digest hex; production callers never read the log.
pub fn frame_audit_snapshot_for_tests() -> Vec<FrameAuditEntry> {
    automation_store()
        .lock()
        .map(|s| s.audit.clone())
        .unwrap_or_default()
}

/// Authorize one automation call: scope intersection, bearer binding, expiry,
/// and per-method rate ceiling, atomically under one lock (no TOCTOU).
///
/// `required` holds the two scopes the caller must possess (debug + terminal
/// capability). Bearer failures and scope failures share the typed
/// `scope`/`ScopeDenied` shape (no oracle distinguishing token validity from
/// authority). Rate overruns yield `budget`/`RateLimited` with zero partial
/// state.
pub(super) fn authorize_automation(
    authorization: &crate::ctl::AuthorizationSnapshot,
    required: &[bitty_ipc_api::scope::Scope; 2],
    token_opt: Option<&str>,
    terminal_id: &str,
    family: AutomationFamily,
    now_ms: u64,
) -> Result<(), HandlerError> {
    for scope in required {
        if !authorization.scopes.contains(*scope) {
            return Err(HandlerError::new(
                "scope",
                "ScopeDenied",
                format!(
                    "permission denied: scope '{}' denied for automation (needs elevation)",
                    scope.as_str()
                ),
            ));
        }
    }
    let terminal_scope = terminal_scope_for(family);
    if !authorization.allows_terminal(Some(terminal_id), terminal_scope) {
        return Err(HandlerError::new(
            "scope",
            "ScopeDenied",
            format!(
                "permission denied: terminal capability denied for {}",
                family.as_str()
            ),
        ));
    }
    let Some(token) = token_opt else {
        return Err(HandlerError::new(
            "scope",
            "ScopeDenied",
            "permission denied: missing automation bearer".to_string(),
        ));
    };
    if validate_bearer_shape(token).is_err() {
        return Err(HandlerError::new(
            "scope",
            "ScopeDenied",
            "permission denied: invalid automation bearer".to_string(),
        ));
    }
    let mut store = automation_store().lock().map_err(|_| {
        HandlerError::new(
            "transport",
            "Unavailable",
            "automation store unavailable".to_string(),
        )
    })?;
    let record = match store.bearers.get(token) {
        Some(rec) => rec.clone(),
        None => {
            return Err(HandlerError::new(
                "scope",
                "ScopeDenied",
                "permission denied: unknown automation bearer".to_string(),
            ));
        }
    };
    if record.session_id != authorization.identity.session_id {
        return Err(HandlerError::new(
            "scope",
            "ScopeDenied",
            "permission denied: bearer bound to another session".to_string(),
        ));
    }
    if record.principal_id != authorization.identity.principal_id {
        return Err(HandlerError::new(
            "scope",
            "ScopeDenied",
            "permission denied: bearer bound to another principal".to_string(),
        ));
    }
    if record.consent_generation != authorization.identity.consent_generation {
        return Err(HandlerError::new(
            "scope",
            "ScopeDenied",
            "permission denied: bearer consent is no longer current".to_string(),
        ));
    }
    if record.terminal_id != terminal_id {
        return Err(HandlerError::new(
            "scope",
            "ScopeDenied",
            "permission denied: bearer bound to another terminal".to_string(),
        ));
    }
    if record.family != family {
        return Err(HandlerError::new(
            "scope",
            "ScopeDenied",
            "permission denied: bearer family mismatch".to_string(),
        ));
    }
    if now_ms >= record.expires_at_ms {
        store.bearers.remove(token);
        store.synth_hits.remove(token);
        store.capture_hits.remove(token);
        store.digest_hits.remove(token);
        return Err(HandlerError::new(
            "scope",
            "ScopeDenied",
            "permission denied: automation bearer expired".to_string(),
        ));
    }
    let (cap, hits) = match family {
        AutomationFamily::Synthesize => (MAX_SYNTH_CALLS_PER_SEC, &mut store.synth_hits),
        AutomationFamily::Capture => (MAX_CAPTURE_FPS, &mut store.capture_hits),
        AutomationFamily::FrameDigest => (
            crate::frame_digest::MAX_FRAME_DIGEST_PER_SEC,
            &mut store.digest_hits,
        ),
    };
    let queue = hits.entry(token.to_string()).or_default();
    while let Some(&front) = queue.front() {
        if now_ms.saturating_sub(front) >= 1_000 {
            queue.pop_front();
        } else {
            break;
        }
    }
    if queue.len() >= cap {
        return Err(HandlerError::new(
            "budget",
            "RateLimited",
            format!("rate limited: automation ceiling {cap}/s exceeded"),
        ));
    }
    queue.push_back(now_ms);
    Ok(())
}
