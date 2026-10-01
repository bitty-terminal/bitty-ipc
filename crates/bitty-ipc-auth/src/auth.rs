//! Peer-credential authentication for IPC (RFC OQ-018, `SO_PEERCRED`).
//!
//! The runtime creates its directory and socket with `0700`/`0600` and verifies
//! owner at connect via `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS) /
//! `SO_PEERCRED` equivalent on BSD. The check confirms that the connecting UID
//! equals the runtime UID. A second local user fails at authentication before
//! any request is parsed (T-09, P0-AC-021 parity).
//!
//! The runtime re-checks peer credentials before each privileged action, not
//! only at connect, so a passed file descriptor cannot be confused for a
//! different principal. It detects or prevents endpoint replacement/tampering:
//! if the directory owner or permissions have changed, it refuses to serve and
//! exits the endpoint rather than falling back to an unauthenticated path.
//!
//! Windows: the named pipe carries a current-user ACL (`GRANT` to the runtime
//! SID only, `DENY` to others at the pipe level). The runtime validates the
//! client token at connect via `GetNamedPipeClientProcessId` plus token SID
//! comparison, equivalent to the Unix peer-credential check.
//!
//! Child scopes: a child process spawned inside a terminal may receive a
//! short-lived, current-terminal scope token only for the narrow operation the
//! parent requested (e.g. one `terminal.text` read scoped to `t:4` with a
//! 60-second TTL). The token is delivered over the PTY-side fd, not via
//! environment, and is never placed in `BITTY_*` variables that shell startup
//! or SSH forwarding would leak (R-012, P0-AC-023 parity). Expiry is enforced
//! server-side; a replayed token after expiry fails closed.
//!
//! This module is **bounded and `forbid(unsafe)`**. The platform adapter uses
//! safe `rustix` or `nix` calls to obtain credentials from the connected Unix
//! stream; this module verifies the extracted triple and retains only the
//! sanitized UID marker. Windows named-pipe verification remains an explicit
//! unsupported result until a safe platform adapter is supplied.

use bitty_ipc_api::error::IpcError;
use bitty_ipc_api::scope::Scope;

// ── constants ───────────────────────────────────────────────────────────────

/// Unix socket directory mode (0700, owner only).
pub const DIR_MODE: u32 = 0o700;

/// Unix socket file mode (0600, owner read/write only).
pub const SOCKET_MODE: u32 = 0o600;

/// Default TTL for a short-lived child scope token (60 seconds per RFC).
pub const CHILD_TOKEN_TTL_MS: u64 = 60_000;

/// Maximum TTL allowed for any token (hard ceiling per `MAX_REQUEST_TIMEOUT_MS` parity).
pub const MAX_TOKEN_TTL_MS: u64 = 30_000 * 2; // 60s matches child token but keep explicit

/// Maximum length for a terminal/view identifier scoped to a child token.
pub const MAX_SCOPED_ID_BYTES: usize = 64;

/// Maximum number of active child tokens tracked per endpoint (bounded).
pub const MAX_CHILD_TOKENS: usize = 64;

// ── peer credentials ────────────────────────────────────────────────────────

/// Extracted peer credentials (owned and bounded).
///
/// The target-specific adapter obtains these from the connected `UnixStream`
/// through a safe platform API. This module verifies the extracted triple and
/// keeps credential bytes out of the serving path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(not(unix), allow(dead_code))]
pub struct PeerCredentials {
    uid: u32,
    gid: u32,
    pid: i32,
}

impl PeerCredentials {
    #[cfg(test)]
    pub fn new(uid: u32, gid: u32, pid: i32) -> Self {
        Self { uid, gid, pid }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn from_platform(uid: u32, gid: u32, pid: i32) -> Self {
        Self { uid, gid, pid }
    }
}

/// Verify that `peer`'s UID equals the runtime's expected UID.
///
/// This is the core `SO_PEERCRED` check: the runtime's UID (owner of the
/// socket directory / pipe ACL) must equal the peer's UID, otherwise the
/// peer is a second local user and fails before any request is parsed.
///
/// The check is re-run before each privileged action (not only at connect),
/// so a passed file descriptor cannot be confused for a different principal.
///
/// # Errors
///
/// Returns `IpcError::Unauthenticated` when UIDs differ.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn verify_peer_uid(peer: PeerCredentials, expected_uid: u32) -> Result<(), IpcError> {
    if peer.uid == expected_uid {
        Ok(())
    } else {
        Err(IpcError::Unauthenticated {
            reason: format!(
                "peer uid {} does not match runtime uid {}",
                peer.uid, expected_uid
            ),
        })
    }
}

/// Pre-verified peer marker: proof that UID equality was checked at the
/// accept boundary before any request byte was parsed.
///
/// The inner field is private so callers cannot forge it. Platform adapters
/// construct it only through [`verify_peer_for_connection`] after querying the
/// connected descriptor; a crate-private test constructor covers legacy
/// endpoint fixtures. It carries no credential bytes itself — only the
/// attested UID — so downstream serving and logging paths handle only this
/// sanitized marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerifiedPeer {
    peer_uid: u32,
}

impl VerifiedPeer {
    /// Test-only constructor for endpoint compatibility fixtures.
    ///
    /// The constructor re-verifies UID equality and is not compiled into the
    /// production library.
    #[cfg(test)]
    pub fn attested(peer: PeerCredentials, runtime_uid: u32) -> Result<Self, IpcError> {
        verify_peer_uid(peer, runtime_uid)?;
        Ok(Self {
            peer_uid: runtime_uid,
        })
    }

    /// UID this marker was attested for.
    #[must_use]
    pub fn peer_uid(&self) -> u32 {
        self.peer_uid
    }
}

/// Verify raw peer credentials at the accept boundary and return a sanitized
/// marker for the serving path.
///
/// Fail-closed: a UID mismatch returns `Unauthenticated` before any request
/// byte is read, and no marker is produced. The returned marker carries no
/// credential bytes; serving/logging code takes only the marker.
///
/// # Errors
///
/// Returns `IpcError::Unauthenticated` when UIDs differ.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn verify_peer_for_connection(
    peer: PeerCredentials,
    expected_uid: u32,
) -> Result<VerifiedPeer, IpcError> {
    verify_peer_uid(peer, expected_uid)?;
    Ok(VerifiedPeer {
        peer_uid: expected_uid,
    })
}

/// Verify Unix endpoint permissions headlessly.
///
/// Checks:
/// - directory mode must be 0o700,
/// - socket mode must be 0o600,
/// - directory/socket owner must equal `runtime_uid`,
/// - caller must equal `runtime_uid` (peer check).
///
/// If any check fails, the endpoint must refuse to serve and exit the
/// endpoint rather than falling back to an unauthenticated path (fail-closed).
#[cfg(test)]
pub fn verify_unix_endpoint(
    runtime_uid: u32,
    peer: PeerCredentials,
    dir_mode: u32,
    dir_owner_uid: u32,
    sock_mode: u32,
    sock_owner_uid: u32,
) -> Result<(), IpcError> {
    if dir_mode != DIR_MODE {
        return Err(IpcError::Unauthenticated {
            reason: format!(
                "directory mode {dir_mode:o} != {:o} (must be 0700)",
                DIR_MODE
            ),
        });
    }
    if sock_mode != SOCKET_MODE {
        return Err(IpcError::Unauthenticated {
            reason: format!(
                "socket mode {sock_mode:o} != {:o} (must be 0600)",
                SOCKET_MODE
            ),
        });
    }
    if dir_owner_uid != runtime_uid {
        return Err(IpcError::Unauthenticated {
            reason: format!("directory owner {dir_owner_uid} != runtime {runtime_uid}"),
        });
    }
    if sock_owner_uid != runtime_uid {
        return Err(IpcError::Unauthenticated {
            reason: format!("socket owner {sock_owner_uid} != runtime {runtime_uid}"),
        });
    }
    verify_peer_uid(peer, runtime_uid)
}

/// Verify Windows named-pipe ACL headlessly.
///
/// The pipe ACL must grant only the runtime SID; this stub models SID
/// equality as `u64` comparison for headless tests. Real Windows verification
/// uses `GetNamedPipeClientProcessId` plus token SID comparison in the
/// platform seam (requires `unsafe` there, not here).
#[cfg(test)]
pub fn verify_windows_pipe(peer_sid: u64, runtime_sid: u64) -> Result<(), IpcError> {
    if peer_sid == runtime_sid {
        Ok(())
    } else {
        Err(IpcError::Unauthenticated {
            reason: format!("pipe peer sid {peer_sid} != runtime sid {runtime_sid}"),
        })
    }
}

// ── child scope token ───────────────────────────────────────────────────────

/// Short-lived, narrow child scope token delivered over PTY fd (not env).
///
/// A child process spawned inside a terminal may receive a token only for the
/// narrow operation the parent requested (e.g. one `terminal.text` read scoped
/// to `t:4` with a 60-second TTL). The token is never placed in `BITTY_*`
/// variables that shell startup or SSH forwarding would leak.
///
/// Tokens are bounded (`<= 64` bytes id, `<= 64` tokens tracked) and expiry
/// is enforced server-side from caller-supplied `now_ms` (deterministic, never
/// wall-clock).
#[derive(Clone, PartialEq, Eq)]
pub struct ChildToken {
    /// Opaque token bytes (bounded, not a credential file).
    pub token: String,
    /// Scope granted to this token (single, narrow).
    pub scope: Scope,
    /// Identifier the scope is restricted to (e.g. `t:4`, `view:2`), bounded 64 bytes.
    pub scoped_id: String,
    /// Creation time (deterministic `now_ms`).
    pub created_at_ms: u64,
    /// Time-to-live in ms (1..=MAX_TOKEN_TTL_MS, default 60s).
    pub ttl_ms: u64,
}

impl std::fmt::Debug for ChildToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildToken")
            .field("scope", &self.scope)
            .field("scoped_id", &self.scoped_id)
            .field("created_at_ms", &self.created_at_ms)
            .field("ttl_ms", &self.ttl_ms)
            .field("token", &"***REDACTED***")
            .finish()
    }
}

impl ChildToken {
    /// Create a new child token, validating bounds.
    ///
    /// # Errors
    ///
    /// - `ScopeDenied` when `scope` is not child-eligible (only
    ///   `terminal.inspect` may be minted on a child token; anything wider
    ///   would be a runtime administrator token, R-012),
    /// - `InvalidRequest` when `token` empty or >128 bytes,
    /// - `PayloadTooLarge` when `scoped_id` > 64 bytes,
    /// - `InvalidRequest` when `ttl_ms` zero or > `MAX_TOKEN_TTL_MS`,
    /// - `InvalidRequest` when `token`/`scoped_id` carries control bytes.
    pub fn new(
        token: String,
        scope: Scope,
        scoped_id: String,
        created_at_ms: u64,
        ttl_ms: u64,
    ) -> Result<Self, IpcError> {
        if !is_child_eligible_scope(scope) {
            return Err(IpcError::ScopeDenied {
                scope: scope.as_str().into(),
                action: "child token mint".into(),
            });
        }
        if token.is_empty() || token.len() > 128 {
            return Err(IpcError::InvalidRequest {
                reason: format!("child token must be 1..=128 bytes, got {}", token.len()),
            });
        }
        if scoped_id.len() > MAX_SCOPED_ID_BYTES {
            return Err(IpcError::PayloadTooLarge {
                field: "scoped_id".into(),
                limit: MAX_SCOPED_ID_BYTES,
                actual: scoped_id.len(),
            });
        }
        if ttl_ms == 0 || ttl_ms > MAX_TOKEN_TTL_MS {
            return Err(IpcError::InvalidRequest {
                reason: format!("ttl_ms must be 1..={MAX_TOKEN_TTL_MS}, got {ttl_ms}"),
            });
        }
        // Tokens travel over the PTY-side fd: reject C0, DEL, and C1 controls.
        // C1 (U+0080..=U+009F) arrives as multi-byte UTF-8 and passes a
        // raw-byte scan, so check `char::is_control` (C0 + DEL + C1), which
        // also keeps tokens single-line (no CR/LF/ESC that could smuggle
        // `SendEnv`/`AcceptEnv` lines or PTY framing).
        if token.chars().any(|c| c.is_control()) || scoped_id.chars().any(|c| c.is_control()) {
            return Err(IpcError::InvalidRequest {
                reason: "token/scoped_id must not contain control bytes".into(),
            });
        }
        Ok(Self {
            token,
            scope,
            scoped_id,
            created_at_ms,
            ttl_ms,
        })
    }

    /// Absolute expiry (saturating).
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.created_at_ms.saturating_add(self.ttl_ms)
    }

    /// Whether `now_ms` is at or past expiry.
    #[must_use]
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms()
    }

    /// Whether the token authorizes `scope` on `scoped_id` at `now_ms`.
    #[must_use]
    pub fn authorizes(&self, scope: Scope, scoped_id: &str, now_ms: u64) -> bool {
        !self.is_expired(now_ms) && self.scope == scope && self.scoped_id == scoped_id
    }
}

/// Whether `scope` may be minted on a child scope token (R-012, P0-AC-023).
///
/// A child holds only a short-lived current-terminal scope, never a runtime
/// administrator token: only `terminal.inspect` (read-only text/list scoped
/// to one terminal id) is eligible. Every other scope fails closed at mint
/// time — including the sibling read-only inspects (`view`/`config`/`plugin`/
/// `debug`), which expose wider runtime state than the child's own terminal,
/// and all effectful scopes (`terminal.input/manage`, `config.modify`,
/// `plugin.manage`, `process.spawn`, `debug.trace/control`).
#[must_use]
pub fn is_child_eligible_scope(scope: Scope) -> bool {
    matches!(scope, Scope::TerminalInspect)
}

/// Bounded in-memory store for child tokens (server-side).
///
/// The runtime verifies every child request against this store; replay after
/// expiry fails closed, and the store never grows beyond `MAX_CHILD_TOKENS`.
#[derive(Default)]
pub struct ChildTokenStore {
    tokens: std::collections::BTreeMap<String, ChildToken>,
}

impl std::fmt::Debug for ChildTokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildTokenStore")
            .field("count", &self.tokens.len())
            .finish()
    }
}

impl ChildTokenStore {
    /// Create empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of active tokens (including expired until drained).
    #[must_use]
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Whether no tokens are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Insert a token; fail-closed when at capacity for a new key.
    pub fn insert(&mut self, token: ChildToken) -> Result<(), IpcError> {
        let is_new = !self.tokens.contains_key(&token.token);
        if is_new && self.tokens.len() >= MAX_CHILD_TOKENS {
            return Err(IpcError::LimitExceeded {
                field: "child_tokens".into(),
                limit: MAX_CHILD_TOKENS,
                actual: self.tokens.len() + 1,
            });
        }
        self.tokens.insert(token.token.clone(), token);
        Ok(())
    }

    /// Verify `token_str` authorizes `scope` on `scoped_id` at `now_ms`.
    ///
    /// Returns `Unauthenticated` when token missing or expired, `ScopeDenied`
    /// when scope/id mismatch. No partial state is created on denial (FS-IP1).
    pub fn verify(
        &self,
        token_str: &str,
        scope: Scope,
        scoped_id: &str,
        now_ms: u64,
    ) -> Result<(), IpcError> {
        let tok = self
            .tokens
            .get(token_str)
            .ok_or_else(|| IpcError::Unauthenticated {
                reason: String::from("unknown child token"),
            })?;
        if tok.is_expired(now_ms) {
            return Err(IpcError::Unauthenticated {
                reason: String::from("child token expired"),
            });
        }
        if tok.scope != scope || tok.scoped_id != scoped_id {
            return Err(IpcError::ScopeDenied {
                scope: scope.as_str().into(),
                action: format!("child token scope {} id {}", tok.scope, tok.scoped_id),
            });
        }
        Ok(())
    }

    /// Drain tokens whose expiry is at or past `now_ms`.
    pub fn drain_expired(&mut self, now_ms: u64) -> Vec<String> {
        let expired: Vec<String> = self
            .tokens
            .iter()
            .filter_map(|(k, tok)| {
                if tok.is_expired(now_ms) {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        for k in &expired {
            self.tokens.remove(k);
        }
        expired
    }

    /// Revoke a token immediately.
    pub fn revoke(&mut self, token_str: &str) -> bool {
        self.tokens.remove(token_str).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitty_ipc_api::scope::Scope;

    #[test]
    fn peer_uid_same_succeeds() {
        let peer = PeerCredentials::new(1000, 1000, 42);
        assert!(verify_peer_uid(peer, 1000).is_ok());
    }

    #[test]
    fn peer_uid_different_fails_unauthenticated() {
        let peer = PeerCredentials::new(1001, 1000, 42);
        let err = verify_peer_uid(peer, 1000).unwrap_err();
        assert!(matches!(err, IpcError::Unauthenticated { .. }));
        assert_eq!(err.error_class(), crate::error::ErrorClass::Unauthenticated);
    }

    #[test]
    fn unix_endpoint_ok() {
        let peer = PeerCredentials::new(1000, 1000, 1);
        assert!(verify_unix_endpoint(1000, peer, 0o700, 1000, 0o600, 1000).is_ok());
    }

    #[test]
    fn unix_endpoint_mode_mismatch_fails() {
        let peer = PeerCredentials::new(1000, 1000, 1);
        let err = verify_unix_endpoint(1000, peer, 0o755, 1000, 0o600, 1000).unwrap_err();
        assert!(matches!(err, IpcError::Unauthenticated { .. }));
        let err2 = verify_unix_endpoint(1000, peer, 0o700, 1000, 0o644, 1000).unwrap_err();
        assert!(matches!(err2, IpcError::Unauthenticated { .. }));
    }

    #[test]
    fn unix_endpoint_owner_mismatch_fails() {
        let peer = PeerCredentials::new(1000, 1000, 1);
        let err = verify_unix_endpoint(1000, peer, 0o700, 999, 0o600, 1000).unwrap_err();
        assert!(matches!(err, IpcError::Unauthenticated { .. }));
        let err2 = verify_unix_endpoint(1000, peer, 0o700, 1000, 0o600, 999).unwrap_err();
        assert!(matches!(err2, IpcError::Unauthenticated { .. }));
    }

    #[test]
    fn windows_pipe_ok_and_mismatch() {
        assert!(verify_windows_pipe(12345, 12345).is_ok());
        assert!(verify_windows_pipe(12345, 99999).is_err());
    }

    #[test]
    fn child_token_lifecycle() {
        let tok = ChildToken::new(
            "tok-abc".into(),
            Scope::TerminalInspect,
            "t:4".into(),
            0,
            60_000,
        )
        .unwrap();
        assert!(!tok.is_expired(59_999));
        assert!(tok.is_expired(60_000));
        assert!(tok.authorizes(Scope::TerminalInspect, "t:4", 10_000));
        assert!(!tok.authorizes(Scope::TerminalInput, "t:4", 10_000));
        assert!(!tok.authorizes(Scope::TerminalInspect, "t:5", 10_000));
    }

    #[test]
    fn child_token_validation() {
        assert!(ChildToken::new("".into(), Scope::TerminalInspect, "t:1".into(), 0, 1000).is_err());
        let long_id = "x".repeat(65);
        assert!(ChildToken::new("tok".into(), Scope::TerminalInspect, long_id, 0, 1000).is_err());
        assert!(ChildToken::new("tok".into(), Scope::TerminalInspect, "t:1".into(), 0, 0).is_err());
        assert!(
            ChildToken::new(
                "tok".into(),
                Scope::TerminalInspect,
                "t:1".into(),
                0,
                MAX_TOKEN_TTL_MS + 1
            )
            .is_err()
        );
        assert!(
            ChildToken::new(
                "bad\x01tok".into(),
                Scope::TerminalInspect,
                "t:1".into(),
                0,
                1000
            )
            .is_err()
        );
    }

    #[test]
    fn child_store_verify_and_expiry() {
        let mut store = ChildTokenStore::new();
        let tok =
            ChildToken::new("tok1".into(), Scope::TerminalInspect, "t:4".into(), 0, 1000).unwrap();
        store.insert(tok).unwrap();
        assert!(
            store
                .verify("tok1", Scope::TerminalInspect, "t:4", 500)
                .is_ok()
        );
        assert!(
            store
                .verify("tok1", Scope::TerminalInspect, "t:5", 500)
                .is_err()
        );
        assert!(
            store
                .verify("tok1", Scope::TerminalInspect, "t:4", 1000)
                .is_err()
        ); // expired
        assert!(
            store
                .verify("unknown", Scope::TerminalInspect, "t:4", 500)
                .is_err()
        );

        let drained = store.drain_expired(1000);
        assert_eq!(drained, vec!["tok1".to_string()]);
        assert!(store.is_empty());
    }

    #[test]
    fn child_store_cap() {
        let mut store = ChildTokenStore::new();
        for i in 0..MAX_CHILD_TOKENS {
            store
                .insert(
                    ChildToken::new(
                        format!("tok{i}"),
                        Scope::TerminalInspect,
                        format!("t:{i}"),
                        0,
                        60_000,
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        let err = store
            .insert(
                ChildToken::new(
                    "overflow".into(),
                    Scope::TerminalInspect,
                    "t:99".into(),
                    0,
                    1000,
                )
                .unwrap(),
            )
            .unwrap_err();
        assert!(matches!(err, IpcError::LimitExceeded { .. }));
    }

    #[test]
    fn bitty_env_not_used_for_auth() {
        // The BITTY_* env vars carry only opaque identifiers, never authority.
        // Forged env without owned socket must still fail peer credential check.
        let forged_peer = PeerCredentials::new(2000, 2000, 99);
        let runtime_uid = 1000;
        // Even if client forges BITTY_SOCKET="...",
        // peer check still fails because UID mismatch.
        assert!(verify_peer_uid(forged_peer, runtime_uid).is_err());
    }

    #[test]
    fn verified_peer_marker_is_fail_closed() {
        let good = PeerCredentials::new(1000, 1000, 1);
        let verified = verify_peer_for_connection(good, 1000).unwrap();
        assert_eq!(verified.peer_uid(), 1000);
        let foreign = PeerCredentials::new(2000, 2000, 99);
        let err = verify_peer_for_connection(foreign, 1000).unwrap_err();
        assert!(matches!(err, IpcError::Unauthenticated { .. }));
        // The test-only constructor also validates its inputs; production
        // markers come from the real connected-stream adapter.
        let attested = VerifiedPeer::attested(good, 1000).unwrap();
        let verified = verify_peer_for_connection(good, 1000).unwrap();
        assert_eq!(attested, verified);
        assert_eq!(attested.peer_uid(), 1000);
        // CTX-0656: the attested constructor validates its inputs — a
        // forged peer (UID mismatch) mints no marker.
        let forged = PeerCredentials::new(2000, 2000, 99);
        let err = VerifiedPeer::attested(forged, 1000).unwrap_err();
        assert!(matches!(err, IpcError::Unauthenticated { .. }));
        // Markers bind their UID: different UIDs never compare equal, so an
        // unverified peer cannot be mistaken for an attested one.
        let other = PeerCredentials::new(2000, 2000, 1);
        let other_verified = verify_peer_for_connection(other, 2000).unwrap();
        assert_ne!(attested, other_verified);
        assert_eq!(other_verified.peer_uid(), 2000);
    }

    /// CTX-0528 (IPC-001): a marker cannot be minted from endpoint ownership
    /// alone; a foreign UID fails before any byte is served.
    #[test]
    fn ipc001_attested_marker_requires_uid_equality() {
        let foreign = PeerCredentials::new(2000, 2000, 99);
        let err = verify_peer_for_connection(foreign, 1000).unwrap_err();
        let reason = match err {
            IpcError::Unauthenticated { reason } => reason,
            other => panic!("expected Unauthenticated, got {other:?}"),
        };
        // Token-free: the reason carries no credential bytes beyond the
        // numeric UIDs the serving path already logs (no fd/pid/secret).
        assert!(
            reason.contains("does not match"),
            "foreign UID must fail with a peer-mismatch reason, got: {reason}"
        );
        assert!(!reason.contains("secret"), "reason must be token-free");
    }

    /// CTX-0528 (IPC-001): error reasons on the peer-mismatch path must
    /// stay token-free (no credential bytes retained or echoed).
    #[test]
    fn ipc001_peer_mismatch_reason_is_token_free() {
        let foreign = PeerCredentials::new(65534, 65534, 9999);
        let err = verify_peer_uid(foreign, 1000).unwrap_err();
        let reason = match err {
            IpcError::Unauthenticated { reason } => reason,
            other => panic!("expected Unauthenticated, got {other:?}"),
        };
        assert!(
            !reason.contains("9999"),
            "peer pid must never reach the error reason: {reason}"
        );
        assert!(
            reason.contains("does not match"),
            "reason must name the mismatch class, got: {reason}"
        );
    }

    #[test]
    fn child_token_errors_are_token_free() {
        // Hostile: error reasons must never echo token material (which may
        // be logged). Unknown and expired paths return static strings.
        let mut store = ChildTokenStore::new();
        let secret = String::from("secret-token-abc123XYZ");
        store
            .insert(
                ChildToken::new(
                    secret.clone(),
                    Scope::TerminalInspect,
                    "t:4".into(),
                    0,
                    1000,
                )
                .unwrap(),
            )
            .unwrap();
        let unknown = store
            .verify(
                "attacker-probe-token-zzz999",
                Scope::TerminalInspect,
                "t:4",
                500,
            )
            .unwrap_err();
        let unknown_reason = match unknown {
            IpcError::Unauthenticated { reason } => reason,
            other => panic!("expected Unauthenticated, got {other:?}"),
        };
        assert!(
            !unknown_reason.contains("attacker-probe-token-zzz999"),
            "unknown-token error must not echo token: {unknown_reason}"
        );
        assert_eq!(unknown_reason, "unknown child token");

        let expired_err = store
            .verify(secret.as_str(), Scope::TerminalInspect, "t:4", 1000)
            .unwrap_err();
        let expired_reason = match expired_err {
            IpcError::Unauthenticated { reason } => reason,
            other => panic!("expected Unauthenticated, got {other:?}"),
        };
        assert!(
            !expired_reason.contains(&secret),
            "expired-token error must not echo token: {expired_reason}"
        );
        assert_eq!(expired_reason, "child token expired");
    }

    #[test]
    fn child_token_and_store_debug_redacts_tokens() {
        let secret = "super_secret_child_token_value";
        let token = ChildToken::new(
            secret.into(),
            Scope::TerminalInspect,
            "t:4".into(),
            100,
            60_000,
        )
        .unwrap();

        let token_debug = format!("{token:?}");
        assert!(
            !token_debug.contains(secret),
            "ChildToken Debug must not contain secret token value, got: {token_debug}"
        );
        assert!(
            token_debug.contains("***REDACTED***"),
            "ChildToken Debug must contain ***REDACTED***, got: {token_debug}"
        );

        let mut store = ChildTokenStore::new();
        store.insert(token).unwrap();

        let store_debug = format!("{store:?}");
        assert!(
            !store_debug.contains(secret),
            "ChildTokenStore Debug must not contain secret token value, got: {store_debug}"
        );
        assert!(
            store_debug.contains("count: 1"),
            "ChildTokenStore Debug must contain count: 1, got: {store_debug}"
        );
    }
}
