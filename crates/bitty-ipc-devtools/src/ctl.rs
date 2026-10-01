//! `bitty ctl` control plane: pure validation + scope mapping (CTX-0171).
//!
//! Canonical: `docs/interfaces/cli.md` (`ctl` section) as refined by
//! `docs/specifications/cli-contract-rfc.md` (`bitty ctl`, runtime class) and
//! `https://github.com/bitty-terminal/bitty-ai-docs/blob/main/specifications/ipc-agent-rfc.md` (scopes, instance selection).
//!
//! This module is pure data, bounded, headless, and `forbid(unsafe)`:
//! it owns no socket, spawns no thread, and performs no I/O. It defines the
//! control verbs that travel over the existing `BITTY_SOCKET` framing
//! (`bitty.debug/*` via [`crate::devtools`]) and maps each to its required
//! [`Scope`](bitty_ipc_api::scope::Scope). Server-side authorization uses
//! [`authorize_ctl_method`], which never trusts client-asserted scopes:
//! the caller passes the server-evaluated [`ScopeSet`](bitty_ipc_api::scope::ScopeSet)
//! derived from the authenticated peer identity, exactly like
//! [`bitty_ipc_api::scope::authorize_method`].
//!
//! # Wire methods
//!
//! Control verbs reuse the `bitty.debug/` prefix so the existing
//! [`crate::devtools::Dispatcher`], framing (`u32` BE + `<= 256 KiB`),
//! JSON-depth cap (32), and `auth`/`scope`/`role` rejection apply unchanged:
//!
//! | `ctl` verb | wire method | required scope |
//! |---|---|---|
//! | `instance list` | local discovery, no IPC | none (same-UID discovery) |
//! | `window list` | `bitty.debug/listWindows` | `view.inspect` |
//! | `view list` | `bitty.debug/listViews` | `view.inspect` |
//! | `terminal list` | `bitty.debug/listTerminals` | `terminal.inspect` |
//! | `terminal spawn` | `bitty.debug/spawnTerminal` | `terminal.manage` (elevation) |
//! | `terminal close` | `bitty.debug/closeTerminal` | `terminal.manage` (elevation) |
//! | `terminal send` | `bitty.debug/sendInput` | `terminal.input` |
//! | `terminal text` | `bitty.debug/getTerminalText` | `terminal.inspect` |
//! | `view split` | `bitty.debug/splitView` | `view.manage` |
//! | `view focus` | `bitty.debug/focusView` | `view.manage` |
//! | `workspace list` | `bitty.debug/listWorkspaces` | `view.inspect` |
//! | `workspace new` | `bitty.debug/createWorkspace` | `view.manage` |
//! | `workspace close` | `bitty.debug/closeWorkspace` | `terminal.manage` (elevation) |
//! | `workspace focus` | `bitty.debug/focusWorkspace` | `view.manage` |
//! | `workspace move` | `bitty.debug/moveWorkspace` | `view.manage` |
//! | `config reload` | `bitty.debug/reloadConfig` | `config.modify` (elevation) |
//! | (test mode only) | `bitty.debug/testExit` | `debug.control` (elevation) |
//!
//! `testExit` is the CTX-0506 deterministic teardown verb for a
//! `bitty --test-mode` instance: it is registered by
//! [`crate::devtools::Dispatcher::with_test_mode`] only, so a normal instance
//! answers `NotFound` (default-deny). It grants no new authority; the scope
//! is the accepted `debug.control` debug family and elevation follows the
//! same explicit allowlist as every other elevated verb.
//!
//! `terminal.manage`, `config.modify` require explicit elevation per the IPC
//! RFC (confirmation prompt or pre-granted per-instance allowlist). Without
//! elevation the server denies with `Denied/ScopeViolation` (CLI exit 7) and
//! creates no partial state.
//!
//! # Bounds (T-01 parity, fail closed)
//!
//! - Terminal ids: `t:<1..10 digits>` (e.g. `t:3`). View ids: `v:<1..10 digits>`.
//! - Workspace ids: `ws:<1..10 digits>` (stable creation sequence, e.g.
//!   `ws:2`; never a positional display index — CTX-0322).
//! - Send text: 1..=`MAX_SEND_TEXT_BYTES` bytes, no NUL, valid UTF-8 (checked by caller).
//! - `--cwd`: 1..=`MAX_CTL_CWD_LEN` bytes, no NUL.
//! - Split direction: `--left` | `--right` | `--up` | `--down` (exactly one; default `--right`).
//! - All params objects are `<= MAX_CTL_PARAMS_BYTES` and depth-checked by the
//!   devtools envelope before reaching here.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitty_ipc_api::error::IpcError;
use bitty_ipc_api::scope::{Scope, ScopeSet};

// ── bounds ────────────────────────────────────────────────────────────────

/// Server-side end-to-end budget for one `bitty ctl` round trip.
///
/// The reply wait in [`enqueue_control_and_wait`] ends exactly at
/// `enqueue + CTL_TIMEOUT` with the real reply, the no-effect timeout, or an
/// unknown-outcome reply. The client waits [`CTL_CLIENT_TIMEOUT`], a little
/// longer, because its read timer starts before the server enqueues; that
/// keeps the client from giving up before the server's terminal reply lands.
pub const CTL_TIMEOUT: Duration = Duration::from_secs(5);

/// Extra time the client allows past [`CTL_TIMEOUT`] for the server's deadline
/// reply to travel back (CTX-0792, #1403).
pub const CTL_CLIENT_REPLY_GRACE: Duration = Duration::from_secs(1);

/// Client socket read budget for one `bitty ctl` round trip.
pub const CTL_CLIENT_TIMEOUT: Duration = CTL_TIMEOUT.saturating_add(CTL_CLIENT_REPLY_GRACE);

/// Maximum bytes for `terminal send` text (fail-closed, well under frame bound).
pub const MAX_SEND_TEXT_BYTES: usize = 16 * 1024;

/// Maximum bytes for `terminal spawn --cwd`.
pub const MAX_CTL_CWD_LEN: usize = 4096;

/// Maximum bytes for a serialized control params object.
pub const MAX_CTL_PARAMS_BYTES: usize = 4096;

/// Maximum digits after `t:` / `v:` (u32 range with margin).
pub const MAX_CTL_ID_DIGITS: usize = 10;

/// Maximum live connection sessions one [`ControlAuthority`] tracks.
///
/// Above the RC-9 connection cap ([`bitty_ipc_core::limits::RC9_MAX_CONNECTIONS`]) so
/// the accept-path shed, not this bound, is what a normal overload hits; past
/// it `open_connection` fails closed with `LimitExceeded`.
pub const MAX_AUTHORITY_SESSIONS: usize = 64;
/// Maximum bytes of a minted principal or session identifier.
pub const MAX_AUTHORITY_ID_BYTES: usize = 64;
/// Maximum entries (wildcard plus per-terminal) in one [`TerminalCapabilities`].
pub const MAX_TERMINAL_CAPABILITY_ENTRIES: usize = 64;

/// Key of the connection-wide capability entry in [`TerminalCapabilities`].
///
/// A terminal without its own entry is answered by this wildcard; a terminal
/// with an entry is answered by that entry alone.
pub const WILDCARD_TERMINAL: &str = "*";

/// Server-minted identity of one accepted connection (CTX-0792, #1403).
///
/// Never client-asserted: `open_connection` mints the principal and session
/// from one process-wide, non-reusing counter, so two connections can never
/// share a session and a bearer or queued control bound to one connection
/// cannot be satisfied by another. The identifiers are not secrets; bearers
/// are the secret material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionIdentity {
    /// Opaque caller identity the authority evaluates grants against.
    pub principal_id: String,
    /// Debug/automation session bound to this connection's lifetime.
    pub session_id: String,
    /// Bumped on every consent change; a snapshot taken under an older
    /// generation no longer authorizes anything.
    pub consent_generation: u64,
}

/// Per-terminal capability map (CTX-0792, #1404).
///
/// Holds the connection wildcard ([`WILDCARD_TERMINAL`]) plus bounded
/// per-terminal entries. Authorization reads it through
/// [`AuthorizationSnapshot::allows_terminal`], which also requires the scope
/// itself; an authority-owned map is additionally clamped to the session's
/// scopes at open and on revocation, so an entry can only narrow what the
/// connection holds, never widen it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TerminalCapabilities {
    grants: BTreeMap<String, ScopeSet>,
}

impl TerminalCapabilities {
    /// An empty map: no wildcard, so every terminal is denied.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the connection wildcard entry (`"*"`).
    ///
    /// The wildcard is the ceiling for every per-terminal entry: a grant can
    /// only ever narrow it (see [`TerminalCapabilities::grant`]).
    #[must_use]
    pub fn from_scopes(scopes: &ScopeSet) -> Self {
        let mut grants = BTreeMap::new();
        grants.insert(String::from(WILDCARD_TERMINAL), scopes.clone());
        Self { grants }
    }

    /// Add `scope` to `terminal_id`'s per-terminal entry.
    ///
    /// The per-terminal entry is the intersection surface: once a terminal has
    /// an entry, [`TerminalCapabilities::allows`] answers from that entry
    /// alone and the wildcard no longer applies to it. Grants are additive per
    /// terminal (no order dependence: capture then synthesize yields the union)
    /// and a terminal id is validated and entry-count bounded
    /// ([`MAX_TERMINAL_CAPABILITY_ENTRIES`]).
    ///
    /// This is the map primitive only. A map handed to
    /// [`ControlAuthority::open_connection`] is clamped to the session's
    /// scopes, so a per-terminal entry can never widen what a connection holds.
    ///
    /// # Errors
    ///
    /// [`IpcError::InvalidRequest`] for a malformed terminal id and
    /// [`IpcError::LimitExceeded`] past
    /// [`MAX_TERMINAL_CAPABILITY_ENTRIES`] distinct terminals.
    pub fn grant(&mut self, terminal_id: &str, scope: Scope) -> Result<(), IpcError> {
        parse_terminal_id(terminal_id)?;
        if !self.grants.contains_key(terminal_id)
            && self.grants.len() >= MAX_TERMINAL_CAPABILITY_ENTRIES
        {
            return Err(IpcError::LimitExceeded {
                field: "terminal_capabilities".into(),
                limit: MAX_TERMINAL_CAPABILITY_ENTRIES,
                actual: self.grants.len() + 1,
            });
        }
        self.grants
            .entry(terminal_id.to_string())
            .or_default()
            .insert(scope);
        Ok(())
    }

    /// Drop `scope` from `terminal_id`'s entry; an emptied entry is removed so
    /// the terminal falls back to the wildcard again.
    pub fn revoke(&mut self, terminal_id: &str, scope: Scope) -> bool {
        let Some(entry) = self.grants.get_mut(terminal_id) else {
            return false;
        };
        let had = entry.contains(scope);
        entry.remove(scope);
        if entry.is_empty() {
            self.grants.remove(terminal_id);
        }
        had
    }

    /// Whether the connection wildcard entry allows `scope` (the ceiling a
    /// per-terminal entry is read against when no entry exists).
    #[must_use]
    pub fn wildcard_allows(&self, scope: Scope) -> bool {
        self.grants
            .get(WILDCARD_TERMINAL)
            .is_some_and(|scopes| scopes.contains(scope))
    }

    /// Intersection check: the per-terminal entry when one exists, else the
    /// wildcard. A terminal with an entry is never answered by the wildcard.
    ///
    /// This is the map half only; authorization decisions go through
    /// [`AuthorizationSnapshot::allows_terminal`].
    #[must_use]
    pub fn allows(&self, terminal_id: &str, scope: Scope) -> bool {
        self.grants
            .get(terminal_id)
            .or_else(|| self.grants.get(WILDCARD_TERMINAL))
            .is_some_and(|scopes| scopes.contains(scope))
    }

    /// Remove `scope` from every entry (wildcard included), dropping entries
    /// that become empty. Used when consent for `scope` is revoked so the map
    /// never outlives the connection's scopes.
    fn revoke_everywhere(&mut self, scope: Scope) {
        self.grants.retain(|terminal, scopes| {
            scopes.remove(scope);
            terminal == WILDCARD_TERMINAL || !scopes.is_empty()
        });
    }

    /// Intersect every entry with `ceiling`, dropping per-terminal entries that
    /// become empty, so the map can never allow a scope the session lacks.
    fn clamp_to(&mut self, ceiling: &ScopeSet) {
        self.grants.retain(|terminal, scopes| {
            for scope in Scope::all() {
                if !ceiling.contains(*scope) {
                    scopes.remove(*scope);
                }
            }
            terminal == WILDCARD_TERMINAL || !scopes.is_empty()
        });
    }

    /// Add `scope` to the wildcard entry (creating it when absent).
    fn extend_wildcard(&mut self, scope: Scope) {
        self.grants
            .entry(String::from(WILDCARD_TERMINAL))
            .or_default()
            .insert(scope);
    }

    /// Whether every entry (wildcard and per-terminal) allows `scope`: the
    /// answer for surfaces whose data is not attributed to one terminal.
    #[must_use]
    pub fn allows_every_terminal(&self, scope: Scope) -> bool {
        self.wildcard_allows(scope) && self.grants.values().all(|scopes| scopes.contains(scope))
    }

    /// Number of entries (wildcard included).
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Whether the map has no entries at all (not even a wildcard).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }
}

/// Immutable authorization context captured for one request or queue item.
///
/// A queued control carries the snapshot taken at enqueue; the drain
/// re-validates it against the live authority ([`ControlAuthority::authorize_snapshot`])
/// immediately before mutation, so a revoked session or a consent change in
/// between denies the mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationSnapshot {
    /// Connection identity and consent generation the snapshot was taken under.
    pub identity: ConnectionIdentity,
    /// Scopes the connection held at that generation.
    pub scopes: ScopeSet,
    /// Per-terminal capability map at that generation.
    pub terminal_capabilities: TerminalCapabilities,
}

impl AuthorizationSnapshot {
    /// Terminal capability intersection (CTX-0792, #1404): the connection must
    /// hold `scope`, and the terminal's entry (or the wildcard, when the
    /// terminal has no entry) must allow it. `None` names no terminal and is
    /// answered by the wildcard.
    #[must_use]
    pub fn allows_terminal(&self, terminal_id: Option<&str>, scope: Scope) -> bool {
        self.scopes.contains(scope)
            && self
                .terminal_capabilities
                .allows(terminal_id.unwrap_or(WILDCARD_TERMINAL), scope)
    }

    /// Intersection for data that is not attributed to one terminal (the
    /// published grid and input stores today): the connection must hold
    /// `scope` and every entry must allow it, because the data may belong to
    /// any terminal. A client-named terminal can therefore never select a
    /// looser entry for an unattributed read.
    #[must_use]
    pub fn allows_every_terminal(&self, scope: Scope) -> bool {
        self.scopes.contains(scope) && self.terminal_capabilities.allows_every_terminal(scope)
    }
}

#[derive(Clone, Debug)]
struct SessionRecord {
    identity: ConnectionIdentity,
    scopes: ScopeSet,
    terminal_capabilities: TerminalCapabilities,
}

#[derive(Debug)]
struct AuthorityState {
    sessions: BTreeMap<String, SessionRecord>,
}

/// Process-wide, non-reusing connection counter behind every minted identity.
///
/// One counter for every [`ControlAuthority`] in the process, so a session id
/// is unique even across authorities (the automation bearer store is
/// process-wide and keyed by session). Exhaustion is terminal: once the
/// counter cannot advance, no further identity is minted.
fn next_connection_number() -> Result<u64, IpcError> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_update(
        std::sync::atomic::Ordering::SeqCst,
        std::sync::atomic::Ordering::SeqCst,
        |current| current.checked_add(1),
    )
    .map_err(|_| IpcError::Denied {
        code: "AuthorityExhausted".into(),
        reason: "connection identity space exhausted".into(),
    })
}

/// Server-owned consent/session service for accepted connections
/// (CTX-0792, #1403/#1404).
///
/// Mints one principal/session per connection, holds each session's scopes and
/// per-terminal capabilities, and is the only place a consent change or a
/// session end takes effect. Cheap to clone: clones share one state.
#[derive(Clone, Debug)]
pub struct ControlAuthority {
    state: Arc<Mutex<AuthorityState>>,
}

impl Default for ControlAuthority {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlAuthority {
    /// A fresh authority with no sessions.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(AuthorityState {
                sessions: BTreeMap::new(),
            })),
        }
    }

    /// Mint the principal/session for one accepted connection.
    ///
    /// `scopes` is the operator-consented ceiling for the connection and
    /// `terminal_capabilities` its initial per-terminal map. The returned
    /// grant revokes the session when dropped.
    ///
    /// # Errors
    ///
    /// `LimitExceeded` past [`MAX_AUTHORITY_SESSIONS`], `Denied`
    /// (`AuthorityExhausted`) when the identity counter is exhausted, and
    /// `Unavailable` when the authority lock is poisoned.
    pub fn open_connection(
        &self,
        scopes: ScopeSet,
        terminal_capabilities: TerminalCapabilities,
    ) -> Result<ConnectionGrant, IpcError> {
        let mut state = self.state.lock().map_err(|_| IpcError::Unavailable {
            reason: "control authority unavailable".into(),
        })?;
        if state.sessions.len() >= MAX_AUTHORITY_SESSIONS {
            return Err(IpcError::LimitExceeded {
                field: "authority_sessions".into(),
                limit: MAX_AUTHORITY_SESSIONS,
                actual: state.sessions.len() + 1,
            });
        }
        let connection = next_connection_number()?;
        let principal_id = bounded_identity("principal", connection)?;
        let session_id = bounded_identity("session", connection)?;
        let identity = ConnectionIdentity {
            principal_id,
            session_id: session_id.clone(),
            consent_generation: 1,
        };
        // The map can only ever narrow the session's scopes (#1404).
        let mut terminal_capabilities = terminal_capabilities;
        terminal_capabilities.clamp_to(&scopes);
        let record = SessionRecord {
            identity: identity.clone(),
            scopes,
            terminal_capabilities,
        };
        let snapshot = AuthorizationSnapshot {
            identity,
            scopes: record.scopes.clone(),
            terminal_capabilities: record.terminal_capabilities.clone(),
        };
        state.sessions.insert(session_id, record);
        Ok(ConnectionGrant {
            authority: self.clone(),
            initial: snapshot,
        })
    }

    /// Current authorization for a live session.
    ///
    /// # Errors
    ///
    /// `Unauthenticated` once the session is gone (closed, revoked, or its
    /// consent generation exhausted); `Unavailable` on a poisoned lock.
    pub fn snapshot(&self, session_id: &str) -> Result<AuthorizationSnapshot, IpcError> {
        let state = self.state.lock().map_err(|_| IpcError::Unavailable {
            reason: "control authority unavailable".into(),
        })?;
        let record = state
            .sessions
            .get(session_id)
            .ok_or_else(|| IpcError::Unauthenticated {
                reason: "connection authority is no longer active".into(),
            })?;
        Ok(AuthorizationSnapshot {
            identity: record.identity.clone(),
            scopes: record.scopes.clone(),
            terminal_capabilities: record.terminal_capabilities.clone(),
        })
    }

    /// Re-validate a captured snapshot against the live session, then
    /// authorize `method` (scope plus terminal capability) under the live
    /// session state.
    ///
    /// This is the drain-time recheck: the session must still exist and its
    /// identity, including the consent generation, must equal the snapshot's,
    /// so any consent change or session end after enqueue denies the action.
    /// The authorization itself reads the live scopes and terminal capability
    /// map, never the enqueue-time copy, so a narrowing in between is honored.
    ///
    /// # Errors
    ///
    /// `Unauthenticated` for a gone or changed session, and every error of
    /// [`authorize_ctl_action`].
    pub fn authorize_snapshot(
        &self,
        snapshot: &AuthorizationSnapshot,
        method: &str,
        params: Option<&str>,
    ) -> Result<Scope, IpcError> {
        let live = {
            let state = self.state.lock().map_err(|_| IpcError::Unavailable {
                reason: "control authority unavailable".into(),
            })?;
            let record = state
                .sessions
                .get(&snapshot.identity.session_id)
                .ok_or_else(|| IpcError::Unauthenticated {
                    reason: "connection authority is no longer active".into(),
                })?;
            if record.identity != snapshot.identity {
                return Err(IpcError::Unauthenticated {
                    reason: "connection consent is no longer current".into(),
                });
            }
            AuthorizationSnapshot {
                identity: record.identity.clone(),
                scopes: record.scopes.clone(),
                terminal_capabilities: record.terminal_capabilities.clone(),
            }
        };
        authorize_ctl_action(method, params, &live)
    }

    /// Add `scope` to a live session (and to its connection-wide wildcard
    /// entry) and advance its consent generation, so every snapshot (and
    /// bearer) minted before the change stops authorizing. Returns `false`
    /// when the session is gone or already holds `scope`.
    pub fn grant_scope(&self, session_id: &str, scope: Scope) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let Some(record) = state.sessions.get_mut(session_id) else {
            return false;
        };
        if record.scopes.contains(scope) {
            return false;
        }
        record.scopes.insert(scope);
        record.terminal_capabilities.extend_wildcard(scope);
        let Some(next_generation) = record.identity.consent_generation.checked_add(1) else {
            state.sessions.remove(session_id);
            return true;
        };
        record.identity.consent_generation = next_generation;
        true
    }

    /// Narrow one terminal of a live session (test support for the
    /// per-terminal intersection; production has no per-terminal consent
    /// writer yet).
    ///
    /// Fail-closed on every path: an unknown session, a malformed terminal id,
    /// a scope the connection's scopes do not allow, or a full capability map
    /// all refuse the grant instead of widening anything.
    #[cfg(test)]
    pub(crate) fn grant_terminal_capability(
        &self,
        session_id: &str,
        terminal_id: &str,
        scope: Scope,
    ) -> Result<(), IpcError> {
        let mut state = self.state.lock().map_err(|_| IpcError::Unavailable {
            reason: "control authority unavailable".into(),
        })?;
        let Some(record) = state.sessions.get_mut(session_id) else {
            return Err(IpcError::Unauthenticated {
                reason: "connection authority is no longer active".into(),
            });
        };
        if !record.scopes.contains(scope) {
            return Err(IpcError::ScopeDenied {
                scope: scope.as_str().into(),
                action: format!("terminal capability grant for {terminal_id}"),
            });
        }
        record.terminal_capabilities.grant(terminal_id, scope)
    }

    /// Drop `scope` from one terminal entry, restoring wildcard coverage for
    /// that terminal once its last capability is released (test support).
    #[cfg(test)]
    pub(crate) fn release_terminal_capability(
        &self,
        session_id: &str,
        terminal_id: &str,
        scope: Scope,
    ) -> bool {
        self.state
            .lock()
            .map(|mut state| {
                state
                    .sessions
                    .get_mut(session_id)
                    .is_some_and(|record| record.terminal_capabilities.revoke(terminal_id, scope))
            })
            .unwrap_or(false)
    }

    /// Revoke `scope` from a live session (consent revocation): the scope is
    /// removed from the session and from every terminal capability entry, and
    /// the consent generation advances so queued controls and bearers issued
    /// under the old consent are denied before any mutation. Returns `false`
    /// when the session is gone or did not hold `scope`.
    pub fn revoke_scope(&self, session_id: &str, scope: Scope) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let Some(record) = state.sessions.get_mut(session_id) else {
            return false;
        };
        if !record.scopes.remove(scope) {
            return false;
        }
        record.terminal_capabilities.revoke_everywhere(scope);
        let Some(next_generation) = record.identity.consent_generation.checked_add(1) else {
            state.sessions.remove(session_id);
            return true;
        };
        record.identity.consent_generation = next_generation;
        true
    }

    /// End a session: every later snapshot, queued control, or bearer bound to
    /// it fails closed. Returns `false` when it was already gone.
    pub fn revoke_session(&self, session_id: &str) -> bool {
        self.state
            .lock()
            .map(|mut state| state.sessions.remove(session_id).is_some())
            .unwrap_or(false)
    }

    /// Number of live sessions (observability and tests).
    pub fn active_sessions(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.sessions.len())
            .unwrap_or(0)
    }
}

/// Render a bounded, non-secret identifier (`<prefix>-<n>`).
fn bounded_identity(prefix: &str, value: u64) -> Result<String, IpcError> {
    let id = format!("{prefix}-{value}");
    if id.len() > MAX_AUTHORITY_ID_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "authority_id".into(),
            limit: MAX_AUTHORITY_ID_BYTES,
            actual: id.len(),
        });
    }
    Ok(id)
}

/// Live authority for one accepted connection.
///
/// Deliberately **not** `Clone`: [`Drop`] revokes the session, so a stray
/// clone leaving scope would tear down the live connection's authority and
/// every later `authorize` would fail closed. Hand out the borrowed
/// [`ControlAuthority`] instead ([`ConnectionGrant::authority`]).
#[derive(Debug)]
pub struct ConnectionGrant {
    authority: ControlAuthority,
    /// Snapshot minted at `open_connection`. Identity fields never change for
    /// the session; scopes and capabilities are read live via
    /// [`ConnectionGrant::snapshot`], never from this copy.
    initial: AuthorizationSnapshot,
}

impl ConnectionGrant {
    /// The authority that owns this connection's session.
    #[must_use]
    pub fn authority(&self) -> &ControlAuthority {
        &self.authority
    }

    /// Identity minted for this connection (consent generation as of open).
    #[must_use]
    pub fn identity(&self) -> &ConnectionIdentity {
        &self.initial.identity
    }

    /// Session identifier bound to this connection.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.initial.identity.session_id
    }

    /// Principal identifier bound to this connection.
    #[must_use]
    pub fn principal_id(&self) -> &str {
        &self.initial.identity.principal_id
    }

    /// The snapshot minted at open (identity, initial scopes, initial map).
    #[must_use]
    pub fn initial_snapshot(&self) -> &AuthorizationSnapshot {
        &self.initial
    }

    /// Fresh authorization for the live session.
    ///
    /// # Errors
    ///
    /// `Unauthenticated` once the session is closed or revoked.
    pub fn snapshot(&self) -> Result<AuthorizationSnapshot, IpcError> {
        self.authority.snapshot(self.session_id())
    }

    /// Authorize `method` under the live session (scope plus terminal
    /// capability).
    ///
    /// # Errors
    ///
    /// See [`ControlAuthority::authorize_snapshot`].
    pub fn authorize(&self, method: &str, params: Option<&str>) -> Result<Scope, IpcError> {
        let snapshot = self.snapshot()?;
        self.authority.authorize_snapshot(&snapshot, method, params)
    }

    /// End the session now (idempotent; `Drop` does the same).
    pub fn close(&self) {
        self.authority.revoke_session(self.session_id());
    }
}

impl Drop for ConnectionGrant {
    fn drop(&mut self) {
        self.authority.revoke_session(self.session_id());
    }
}

/// Terminal capability a terminal-addressed control verb requires on the
/// addressed terminal, beyond its method scope (CTX-0792, #1404). `None` for
/// verbs that address no terminal.
#[must_use]
pub fn required_terminal_capability_for_ctl_method(method: &str) -> Option<Scope> {
    match method {
        METHOD_GET_TERMINAL_TEXT => Some(Scope::TerminalInspect),
        METHOD_SEND_INPUT => Some(Scope::TerminalInput),
        METHOD_CLOSE_TERMINAL => Some(Scope::TerminalManage),
        _ => None,
    }
}

/// Authorize one control action under `authorization`: the method scope
/// first, then, for terminal-addressed verbs, the capability intersection on
/// the terminal the params address (CTX-0792, #1404). Both halves deny before
/// any store or runtime access.
///
/// # Errors
///
/// Every error of [`authorize_ctl_method`], `InvalidRequest` for malformed
/// terminal params, and `ScopeDenied` when the terminal capability is absent.
pub fn authorize_ctl_action(
    method: &str,
    params: Option<&str>,
    authorization: &AuthorizationSnapshot,
) -> Result<Scope, IpcError> {
    let required = authorize_ctl_method(method, &authorization.scopes)?;
    // Workspace close kills every pane session in the workspace, and those
    // terminals are not named in the params, so every terminal entry must
    // allow `terminal.manage` (same rule as the unattributed debug reads).
    if method == METHOD_CLOSE_WORKSPACE {
        return if authorization.allows_every_terminal(Scope::TerminalManage) {
            Ok(required)
        } else {
            Err(IpcError::ScopeDenied {
                scope: Scope::TerminalManage.as_str().into(),
                action: method.into(),
            })
        };
    }
    let Some(capability) = required_terminal_capability_for_ctl_method(method) else {
        return Ok(required);
    };
    let terminal_id = match method {
        METHOD_SEND_INPUT => parse_send_params(params)?.0,
        METHOD_GET_TERMINAL_TEXT | METHOD_CLOSE_TERMINAL => parse_terminal_id_params(params)?,
        _ => {
            return Err(IpcError::NotFound {
                reason: "unknown terminal action".into(),
            });
        }
    };
    if authorization.allows_terminal(Some(&terminal_id), capability) {
        Ok(required)
    } else {
        Err(IpcError::ScopeDenied {
            scope: capability.as_str().into(),
            action: method.into(),
        })
    }
}

// ── wire method names ─────────────────────────────────────────────────────

/// Wire method for `ctl window list`.
pub const METHOD_LIST_WINDOWS: &str = "bitty.debug/listWindows";
/// Wire method for `ctl view list`.
pub const METHOD_LIST_VIEWS: &str = "bitty.debug/listViews";
/// Wire method for `ctl terminal list`.
pub const METHOD_LIST_TERMINALS: &str = "bitty.debug/listTerminals";
/// Wire method for `ctl terminal spawn`.
pub const METHOD_SPAWN_TERMINAL: &str = "bitty.debug/spawnTerminal";
/// Wire method for `ctl terminal close`.
pub const METHOD_CLOSE_TERMINAL: &str = "bitty.debug/closeTerminal";
/// Wire method for `ctl terminal send`.
pub const METHOD_SEND_INPUT: &str = "bitty.debug/sendInput";
/// Wire method for `ctl terminal text`.
pub const METHOD_GET_TERMINAL_TEXT: &str = "bitty.debug/getTerminalText";
/// Wire method for `ctl view split`.
pub const METHOD_SPLIT_VIEW: &str = "bitty.debug/splitView";
/// Wire method for `ctl view focus`.
pub const METHOD_FOCUS_VIEW: &str = "bitty.debug/focusView";
/// Wire method for `ctl workspace list`.
pub const METHOD_LIST_WORKSPACES: &str = "bitty.debug/listWorkspaces";
/// Wire method for `ctl workspace new`.
pub const METHOD_NEW_WORKSPACE: &str = "bitty.debug/createWorkspace";
/// Wire method for `ctl workspace close`.
pub const METHOD_CLOSE_WORKSPACE: &str = "bitty.debug/closeWorkspace";
/// Wire method for `ctl workspace focus`.
pub const METHOD_FOCUS_WORKSPACE: &str = "bitty.debug/focusWorkspace";
/// Wire method for `ctl workspace move` (CTX-0259: move focused window to ws:N).
pub const METHOD_MOVE_WORKSPACE: &str = "bitty.debug/moveWorkspace";
/// Wire method for `ctl workspace rename` (issue #1333: rename ws:N).
pub const METHOD_RENAME_WORKSPACE: &str = "bitty.debug/renameWorkspace";
/// Wire method for `ctl workspace move-panel` (issue #1333: reposition the
/// focused panel at a 1-based leaf position within its workspace).
pub const METHOD_MOVE_PANEL: &str = "bitty.debug/movePanel";
/// Wire method for `ctl config reload`.
pub const METHOD_RELOAD_CONFIG: &str = "bitty.debug/reloadConfig";

/// All control wire methods (excluding local `instance list`).
#[must_use]
pub fn all_control_methods() -> &'static [&'static str] {
    &[
        METHOD_LIST_WINDOWS,
        METHOD_LIST_VIEWS,
        METHOD_LIST_TERMINALS,
        METHOD_SPAWN_TERMINAL,
        METHOD_CLOSE_TERMINAL,
        METHOD_SEND_INPUT,
        METHOD_GET_TERMINAL_TEXT,
        METHOD_SPLIT_VIEW,
        METHOD_FOCUS_VIEW,
        METHOD_LIST_WORKSPACES,
        METHOD_NEW_WORKSPACE,
        METHOD_CLOSE_WORKSPACE,
        METHOD_FOCUS_WORKSPACE,
        METHOD_MOVE_WORKSPACE,
        METHOD_RENAME_WORKSPACE,
        METHOD_MOVE_PANEL,
        METHOD_RELOAD_CONFIG,
    ]
}

/// Control wire methods registered only while `--test-mode` is active.
///
/// Kept separate from [`all_control_methods`] because a normal instance never
/// registers the test surface: these methods must answer `NotFound` there
/// (fail-closed default-deny), never `ScopeDenied`/`InvalidMethod`.
#[must_use]
pub fn all_test_mode_control_methods() -> &'static [&'static str] {
    &[crate::devtools::METHOD_TEST_EXIT]
}

/// Map a control wire method to its required scope.
///
/// Returns `None` for unknown methods (fail-closed `NotFound`, no partial state).
#[must_use]
pub fn required_scope_for_ctl_method(method: &str) -> Option<Scope> {
    match method {
        METHOD_LIST_WINDOWS | METHOD_LIST_VIEWS => Some(Scope::ViewInspect),
        METHOD_LIST_TERMINALS | METHOD_GET_TERMINAL_TEXT => Some(Scope::TerminalInspect),
        METHOD_SEND_INPUT => Some(Scope::TerminalInput),
        METHOD_SPAWN_TERMINAL | METHOD_CLOSE_TERMINAL => Some(Scope::TerminalManage),
        METHOD_SPLIT_VIEW | METHOD_FOCUS_VIEW => Some(Scope::ViewManage),
        // Workspace entry (CTX-0257): list/new/focus ride the view scopes
        // (no elevation, like view list/split/focus); close can kill live
        // pane sessions, so it needs `terminal.manage` elevation exactly
        // like `terminal close`. CTX-0259 move never kills (session moves
        // with the leaf), so it rides `view.manage` like new/focus.
        METHOD_LIST_WORKSPACES => Some(Scope::ViewInspect),
        METHOD_NEW_WORKSPACE | METHOD_FOCUS_WORKSPACE | METHOD_MOVE_WORKSPACE => {
            Some(Scope::ViewManage)
        }
        // Issue #1333: rename changes a display name only (no session
        // touched) and move-panel reparents within the live tree without
        // killing, so both ride `view.manage` like new/focus/move.
        METHOD_RENAME_WORKSPACE | METHOD_MOVE_PANEL => Some(Scope::ViewManage),
        METHOD_CLOSE_WORKSPACE => Some(Scope::TerminalManage),
        METHOD_RELOAD_CONFIG => Some(Scope::ConfigModify),
        // CTX-0506 test-mode surface: `testExit` stops the `--test-mode`
        // servo loop. It is registered only while test mode is active (see
        // `Dispatcher::with_test_mode`) and requires the accepted
        // `debug.control` debug scope, exactly like every other elevated
        // control verb: no new scope and no bypass.
        crate::devtools::METHOD_TEST_EXIT => Some(Scope::DebugControl),
        _ => None,
    }
}

/// Server-side authorization for control methods.
///
/// Validates the `bitty.debug/*` grammar via the devtools prefix rule
/// (ASCII alphanumeric/`_`/`-` suffix, bounded) and denies unknown methods
/// with `NotFound`. Known methods require the mapped scope in `granted`;
/// otherwise denies with `ScopeDenied` (no partial state, fail-closed).
/// Clients never assert scopes: `granted` is the server-evaluated set.
///
/// # Errors
///
/// - `InvalidMethod` when the method violates the wire grammar.
/// - `NotFound` when the method is well-formed but not a control method.
/// - `ScopeDenied` when `granted` lacks the required scope.
pub fn authorize_ctl_method(method: &str, granted: &ScopeSet) -> Result<Scope, IpcError> {
    validate_ctl_method_name(method)?;
    let required = required_scope_for_ctl_method(method).ok_or_else(|| IpcError::NotFound {
        reason: format!("unknown control method '{method}'"),
    })?;
    if granted.contains(required) {
        Ok(required)
    } else {
        Err(IpcError::ScopeDenied {
            scope: required.as_str().into(),
            action: method.into(),
        })
    }
}

/// Validate a `bitty.debug/*` control method name (bounded, ASCII).
fn validate_ctl_method_name(method: &str) -> Result<(), IpcError> {
    const PREFIX: &str = "bitty.debug/";
    if method.len() > crate::devtools::MAX_DEVTOOLS_METHOD_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "method".into(),
            limit: crate::devtools::MAX_DEVTOOLS_METHOD_BYTES,
            actual: method.len(),
        });
    }
    let Some(suffix) = method.strip_prefix(PREFIX) else {
        return Err(IpcError::InvalidMethod {
            method: method.to_string(),
            reason: "control method must start with bitty.debug/".into(),
        });
    };
    if suffix.is_empty() || suffix.len() > crate::devtools::MAX_METHOD_SUFFIX_LEN {
        return Err(IpcError::InvalidMethod {
            method: method.to_string(),
            reason: "control method suffix must be 1..=64".into(),
        });
    }
    let ok = suffix
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !ok {
        return Err(IpcError::InvalidMethod {
            method: method.to_string(),
            reason: "control method suffix must be ascii alphanumeric".into(),
        });
    }
    Ok(())
}

// ── id validation ─────────────────────────────────────────────────────────

/// Validate a terminal id (`t:<digits>`), returning the numeric id.
///
/// Shape-only: existence is resolved server-side (`NotFound` when absent).
pub fn parse_terminal_id(raw: &str) -> Result<u32, IpcError> {
    let digits = raw
        .strip_prefix("t:")
        .ok_or_else(|| IpcError::InvalidRequest {
            reason: format!("terminal id must match ^t:[0-9]+$, got '{raw}'"),
        })?;
    parse_id_digits(digits, "t")
}

/// Validate a view id (`v:<digits>`), returning the numeric id.
pub fn parse_view_id(raw: &str) -> Result<u32, IpcError> {
    let digits = raw
        .strip_prefix("v:")
        .ok_or_else(|| IpcError::InvalidRequest {
            reason: format!("view id must match ^v:[0-9]+$, got '{raw}'"),
        })?;
    parse_id_digits(digits, "v")
}

/// Validate a workspace id (`ws:<digits>`, stable creation sequence),
/// returning the numeric id.
///
/// CTX-0322: the id is the same stable sequence `workspace list` names
/// (`ws{seq}`), so an id reported by `new`/`list` round-trips through
/// `focus`/`close`/`move`. Shape-only: existence resolves server-side
/// (`NotFound` when absent).
pub fn parse_workspace_id(raw: &str) -> Result<u32, IpcError> {
    let digits = raw
        .strip_prefix("ws:")
        .ok_or_else(|| IpcError::InvalidRequest {
            reason: format!("workspace id must match ^ws:[0-9]+$, got '{raw}'"),
        })?;
    parse_id_digits(digits, "ws")
}

fn parse_id_digits(digits: &str, prefix: &str) -> Result<u32, IpcError> {
    if digits.is_empty() || digits.len() > MAX_CTL_ID_DIGITS {
        return Err(IpcError::InvalidRequest {
            reason: format!("{prefix}: id must be 1..={MAX_CTL_ID_DIGITS} digits"),
        });
    }
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(IpcError::InvalidRequest {
            reason: format!("{prefix}: id must match ^{prefix}:[0-9]+$"),
        });
    }
    // Reject leading zeros (`t:007`) to keep `t:7` canonical; `t:0` itself
    // parses (existence resolves server-side to NotFound).
    if digits.len() > 1 && digits.starts_with('0') {
        return Err(IpcError::InvalidRequest {
            reason: format!("{prefix}: id must not have leading zeros"),
        });
    }
    digits.parse::<u32>().map_err(|_| IpcError::InvalidRequest {
        reason: format!("{prefix}: id out of range"),
    })
}

/// Validate `terminal send` text (non-empty, bounded, no NUL).
pub fn validate_send_text(text: &str) -> Result<(), IpcError> {
    if text.is_empty() {
        return Err(IpcError::InvalidRequest {
            reason: "send text must be non-empty".into(),
        });
    }
    if text.len() > MAX_SEND_TEXT_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "text".into(),
            limit: MAX_SEND_TEXT_BYTES,
            actual: text.len(),
        });
    }
    if text.contains('\0') {
        return Err(IpcError::InvalidRequest {
            reason: "send text must not contain NUL".into(),
        });
    }
    Ok(())
}

/// Validate `terminal spawn --cwd` (non-empty, bounded, no NUL).
pub fn validate_ctl_cwd(cwd: &str) -> Result<(), IpcError> {
    if cwd.is_empty() || cwd.len() > MAX_CTL_CWD_LEN {
        return Err(IpcError::InvalidRequest {
            reason: format!("cwd must be 1..={MAX_CTL_CWD_LEN} bytes"),
        });
    }
    if cwd.contains('\0') {
        return Err(IpcError::InvalidRequest {
            reason: "cwd must not contain NUL".into(),
        });
    }
    Ok(())
}

// ── split direction ───────────────────────────────────────────────────────

/// Split direction for `ctl view split`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitDirection {
    Left,
    Right,
    Up,
    Down,
}

impl SplitDirection {
    /// Canonical wire token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Right => "right",
            Self::Up => "up",
            Self::Down => "down",
        }
    }

    /// Parse a direction token (`left|right|up|down`, case-insensitive).
    pub fn parse(raw: &str) -> Result<Self, IpcError> {
        match raw.to_ascii_lowercase().as_str() {
            "left" => Ok(Self::Left),
            "right" => Ok(Self::Right),
            "up" => Ok(Self::Up),
            "down" => Ok(Self::Down),
            _ => Err(IpcError::InvalidRequest {
                reason: format!("split direction must be left|right|up|down, got '{raw}'"),
            }),
        }
    }
}

// ── params builders (client) ──────────────────────────────────────────────

/// Escape a string as JSON string content (no surrounding quotes).
fn json_escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7F => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

/// Build `{ "terminal_id": "t:N" }` params for close/text.
#[must_use]
pub fn params_terminal_id(terminal_id: &str) -> String {
    let mut out = String::from("{\"terminal_id\":\"");
    json_escape_into(&mut out, terminal_id);
    out.push_str("\"}");
    out
}

/// Build `{ "terminal_id": "t:N", "text": "..." }` params for send.
#[must_use]
pub fn params_send_input(terminal_id: &str, text: &str) -> String {
    let mut out = String::from("{\"terminal_id\":\"");
    json_escape_into(&mut out, terminal_id);
    out.push_str("\",\"text\":\"");
    json_escape_into(&mut out, text);
    out.push_str("\"}");
    out
}

/// Build `{ "cwd": "..." }` or `{}` params for spawn.
#[must_use]
pub fn params_spawn(cwd: Option<&str>) -> String {
    match cwd {
        None => String::from("{}"),
        Some(dir) => {
            let mut out = String::from("{\"cwd\":\"");
            json_escape_into(&mut out, dir);
            out.push_str("\"}");
            out
        }
    }
}

/// Build `{ "direction": "right" }` params for split.
#[must_use]
pub fn params_split(direction: SplitDirection) -> String {
    format!("{{\"direction\":\"{}\"}}", direction.as_str())
}

/// Build `{ "view_id": "v:N" }` params for focus.
#[must_use]
pub fn params_focus(view_id: &str) -> String {
    let mut out = String::from("{\"view_id\":\"");
    json_escape_into(&mut out, view_id);
    out.push_str("\"}");
    out
}

/// Build `{ "workspace_id": "ws:N" }` params for workspace close/focus.
#[must_use]
pub fn params_workspace(workspace_id: &str) -> String {
    let mut out = String::from("{\"workspace_id\":\"");
    json_escape_into(&mut out, workspace_id);
    out.push_str("\"}");
    out
}

/// Maximum workspace rename bytes on the wire (issue #1333). The runtime
/// truncates to its 32-char display bound; this cap only bounds transport.
pub const MAX_WORKSPACE_RENAME_BYTES: usize = 256;

/// Maximum 1-based panel position accepted on the wire (issue #1333).
/// Shape-only: existence resolves server-side (`NotFound`/`Conflict` when
/// the position is beyond the live leaf count).
pub const MAX_PANEL_POSITION: u64 = 256;

/// Build `{ "workspace_id": "ws:N", "name": "..." }` params for rename.
#[must_use]
pub fn params_workspace_rename(workspace_id: &str, name: &str) -> String {
    let mut out = String::from("{\"workspace_id\":\"");
    json_escape_into(&mut out, workspace_id);
    out.push_str("\",\"name\":\"");
    json_escape_into(&mut out, name);
    out.push_str("\"}");
    out
}

/// Build `{ "position": N }` params for move-panel (1-based display position).
#[must_use]
pub fn params_move_panel(position: u64) -> String {
    format!("{{\"position\":{position}}}")
}

// ── params parsing (server, bounded, no new deps) ─────────────────────────

/// Extract a top-level string field from a flat params object.
///
/// Bounded, quote-aware, backslash-aware; rejects nested objects for the
/// requested key (control params are flat). Returns `None` when absent.
fn extract_string_field(params: &str, key: &str) -> Option<String> {
    extract_optional_string_field(params, key).ok().flatten()
}

/// Like [`extract_string_field`] but distinguishes an absent key (`Ok(None)`)
/// from a present key whose value is not a plain string (`Err(())`), so an
/// optional-field parser can accept absence and reject a malformed value
/// instead of silently treating both as "not provided".
fn extract_optional_string_field(params: &str, key: &str) -> Result<Option<String>, ()> {
    let needle = format!("\"{key}\"");
    let mut search = 0usize;
    let bytes = params.as_bytes();
    while let Some(pos) = params[search..].find(&needle) {
        let abs = search + pos;
        // Key must be followed by optional ws + `:`.
        let mut i = abs + needle.len();
        while i < bytes.len()
            && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n' || bytes[i] == b'\r')
        {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b':' {
            search = abs + needle.len();
            continue;
        }
        i += 1;
        while i < bytes.len()
            && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n' || bytes[i] == b'\r')
        {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'"' {
            return Err(());
        }
        i += 1;
        let mut out = String::new();
        while i < bytes.len() {
            match bytes[i] {
                b'"' => return Ok(Some(out)),
                b'\\' => {
                    i += 1;
                    if i >= bytes.len() {
                        return Err(());
                    }
                    match bytes[i] {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            // Minimal \uXXXX (BMP only, no surrogate handling:
                            // control params never need astral escapes).
                            if i + 4 >= bytes.len() {
                                return Err(());
                            }
                            let hex = params.get(i + 1..i + 5).ok_or(())?;
                            let code = u32::from_str_radix(hex, 16).map_err(|_| ())?;
                            out.push(char::from_u32(code).ok_or(())?);
                            i += 4;
                        }
                        _ => return Err(()),
                    }
                    i += 1;
                }
                _ => {
                    // Raw UTF-8: advance by char.
                    let ch = params[i..].chars().next().ok_or(())?;
                    out.push(ch);
                    i += ch.len_utf8();
                }
            }
        }
        return Err(());
    }
    Ok(None)
}

/// Parse `close`/`text` params (`{ "terminal_id": "t:N" }`).
pub fn parse_terminal_id_params(params: Option<&str>) -> Result<String, IpcError> {
    let raw = params.ok_or_else(|| IpcError::InvalidRequest {
        reason: "missing params.terminal_id".into(),
    })?;
    if raw.len() > MAX_CTL_PARAMS_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "params".into(),
            limit: MAX_CTL_PARAMS_BYTES,
            actual: raw.len(),
        });
    }
    let id = extract_string_field(raw, "terminal_id").ok_or_else(|| IpcError::InvalidRequest {
        reason: "params.terminal_id must be a string like \"t:3\"".into(),
    })?;
    parse_terminal_id(&id)?;
    Ok(id)
}

/// Parse an optional `terminal_id`/`terminalId` params field.
///
/// Same parser (and same [`MAX_CTL_PARAMS_BYTES`] bound) as
/// [`parse_terminal_id_params`], for read surfaces where the terminal is
/// optional: a request that names none is answered by the connection wildcard,
/// a request that names one is validated exactly like the control verbs.
/// Callers that use the value as a security decision input must use this
/// rather than scanning the raw params text.
pub fn parse_optional_terminal_id_params(params: Option<&str>) -> Result<Option<String>, IpcError> {
    let Some(raw) = params else {
        return Ok(None);
    };
    if raw.len() > MAX_CTL_PARAMS_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "params".into(),
            limit: MAX_CTL_PARAMS_BYTES,
            actual: raw.len(),
        });
    }
    // Both spellings are accepted; the first one present wins, and a present
    // but malformed value is rejected instead of being read as "not provided".
    let found = match extract_optional_string_field(raw, "terminal_id") {
        Ok(Some(value)) => Some(value),
        Ok(None) => extract_optional_string_field(raw, "terminalId").map_err(|()| {
            IpcError::InvalidRequest {
                reason: "params.terminal_id must be a string like \"t:3\"".into(),
            }
        })?,
        Err(()) => {
            return Err(IpcError::InvalidRequest {
                reason: "params.terminal_id must be a string like \"t:3\"".into(),
            });
        }
    };
    let Some(id) = found else {
        return Ok(None);
    };
    parse_terminal_id(&id)?;
    Ok(Some(id))
}

/// Parse `send` params (`{ "terminal_id": "t:N", "text": "..." }`).
pub fn parse_send_params(params: Option<&str>) -> Result<(String, String), IpcError> {
    let raw = params.ok_or_else(|| IpcError::InvalidRequest {
        reason: "missing params.terminal_id/params.text".into(),
    })?;
    if raw.len() > MAX_CTL_PARAMS_BYTES + MAX_SEND_TEXT_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "params".into(),
            limit: MAX_CTL_PARAMS_BYTES + MAX_SEND_TEXT_BYTES,
            actual: raw.len(),
        });
    }
    let id = extract_string_field(raw, "terminal_id").ok_or_else(|| IpcError::InvalidRequest {
        reason: "params.terminal_id must be a string like \"t:1\"".into(),
    })?;
    parse_terminal_id(&id)?;
    let text = extract_string_field(raw, "text").ok_or_else(|| IpcError::InvalidRequest {
        reason: "params.text must be a non-empty string".into(),
    })?;
    validate_send_text(&text)?;
    Ok((id, text))
}

/// Parse `spawn` params (`{}` or `{ "cwd": "..." }`).
pub fn parse_spawn_params(params: Option<&str>) -> Result<Option<String>, IpcError> {
    let Some(raw) = params else {
        return Ok(None);
    };
    if raw.len() > MAX_CTL_PARAMS_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "params".into(),
            limit: MAX_CTL_PARAMS_BYTES,
            actual: raw.len(),
        });
    }
    match extract_string_field(raw, "cwd") {
        None => Ok(None),
        Some(cwd) => {
            validate_ctl_cwd(&cwd)?;
            Ok(Some(cwd))
        }
    }
}

/// Parse `split` params (`{ "direction": "left|right|up|down" }`, default right).
pub fn parse_split_params(params: Option<&str>) -> Result<SplitDirection, IpcError> {
    let Some(raw) = params else {
        return Ok(SplitDirection::Right);
    };
    if raw.len() > MAX_CTL_PARAMS_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "params".into(),
            limit: MAX_CTL_PARAMS_BYTES,
            actual: raw.len(),
        });
    }
    match extract_string_field(raw, "direction") {
        None => Ok(SplitDirection::Right),
        Some(dir) => SplitDirection::parse(&dir),
    }
}

/// Parse `focus` params (`{ "view_id": "v:N" }`).
pub fn parse_focus_params(params: Option<&str>) -> Result<String, IpcError> {
    let raw = params.ok_or_else(|| IpcError::InvalidRequest {
        reason: "missing params.view_id".into(),
    })?;
    if raw.len() > MAX_CTL_PARAMS_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "params".into(),
            limit: MAX_CTL_PARAMS_BYTES,
            actual: raw.len(),
        });
    }
    let id = extract_string_field(raw, "view_id").ok_or_else(|| IpcError::InvalidRequest {
        reason: "params.view_id must be a string like \"v:3\"".into(),
    })?;
    parse_view_id(&id)?;
    Ok(id)
}

/// Parse workspace `close`/`focus` params (`{ "workspace_id": "ws:N" }`).
pub fn parse_workspace_params(params: Option<&str>) -> Result<String, IpcError> {
    let raw = params.ok_or_else(|| IpcError::InvalidRequest {
        reason: "missing params.workspace_id".into(),
    })?;
    if raw.len() > MAX_CTL_PARAMS_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "params".into(),
            limit: MAX_CTL_PARAMS_BYTES,
            actual: raw.len(),
        });
    }
    let id = extract_string_field(raw, "workspace_id").ok_or_else(|| IpcError::InvalidRequest {
        reason: "params.workspace_id must be a string like \"ws:2\"".into(),
    })?;
    parse_workspace_id(&id)?;
    Ok(id)
}

/// Parse workspace `rename` params
/// (`{ "workspace_id": "ws:N", "name": "..." }`).
///
/// The name must be non-blank after trimming and within
/// [`MAX_WORKSPACE_RENAME_BYTES`]; the runtime applies its own
/// char-boundary truncation to the display bound.
pub fn parse_workspace_rename_params(params: Option<&str>) -> Result<(String, String), IpcError> {
    let raw = params.ok_or_else(|| IpcError::InvalidRequest {
        reason: "missing params.workspace_id".into(),
    })?;
    if raw.len() > MAX_CTL_PARAMS_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "params".into(),
            limit: MAX_CTL_PARAMS_BYTES,
            actual: raw.len(),
        });
    }
    let id = extract_string_field(raw, "workspace_id").ok_or_else(|| IpcError::InvalidRequest {
        reason: "params.workspace_id must be a string like \"ws:2\"".into(),
    })?;
    parse_workspace_id(&id)?;
    let name = extract_string_field(raw, "name").ok_or_else(|| IpcError::InvalidRequest {
        reason: "params.name must be a non-empty string".into(),
    })?;
    if name.trim().is_empty() {
        return Err(IpcError::InvalidRequest {
            reason: "params.name must be a non-empty string".into(),
        });
    }
    if name.len() > MAX_WORKSPACE_RENAME_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "params.name".into(),
            limit: MAX_WORKSPACE_RENAME_BYTES,
            actual: name.len(),
        });
    }
    Ok((id, name))
}

/// Extract a top-level unsigned integer field from a flat params object
/// (`{ "position": 3 }`). Returns `None` when absent or malformed.
fn extract_u64_field(params: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let mut search = 0usize;
    let bytes = params.as_bytes();
    while let Some(pos) = params[search..].find(&needle) {
        let abs = search + pos;
        let mut i = abs + needle.len();
        while i < bytes.len()
            && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n' || bytes[i] == b'\r')
        {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b':' {
            search = abs + needle.len();
            continue;
        }
        i += 1;
        while i < bytes.len()
            && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n' || bytes[i] == b'\r')
        {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if start == i {
            return None;
        }
        return params[start..i].parse::<u64>().ok();
    }
    None
}

/// Parse move-panel params (`{ "position": N }`, 1-based display position).
pub fn parse_move_panel_params(params: Option<&str>) -> Result<u64, IpcError> {
    let raw = params.ok_or_else(|| IpcError::InvalidRequest {
        reason: "missing params.position".into(),
    })?;
    if raw.len() > MAX_CTL_PARAMS_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "params".into(),
            limit: MAX_CTL_PARAMS_BYTES,
            actual: raw.len(),
        });
    }
    let position = extract_u64_field(raw, "position").ok_or_else(|| IpcError::InvalidRequest {
        reason: "params.position must be an integer 1..=256".into(),
    })?;
    if position == 0 || position > MAX_PANEL_POSITION {
        return Err(IpcError::InvalidRequest {
            reason: "params.position must be an integer 1..=256".into(),
        });
    }
    Ok(position)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitty_ipc_api::scope::ScopeSet;

    #[test]
    fn ctl_timeout_budget_is_pinned() {
        // CTX-0301: one server budget for the control channel; the client
        // read timeout in `bitty-terminal` `ctl_roundtrip` is this plus a fixed
        // reply grace (CTX-0792), so the client outlives the server's
        // deadline reply.
        assert_eq!(CTL_TIMEOUT, std::time::Duration::from_secs(5));
        assert_eq!(CTL_TIMEOUT.as_secs(), 5);
        assert!(CTL_CLIENT_TIMEOUT > CTL_TIMEOUT);
        assert!(CTL_APPLY_MARGIN < CTL_TIMEOUT);
    }

    #[test]
    fn authority_mints_distinct_principals_and_sessions() {
        let authority = ControlAuthority::new();
        let grant_a = authority
            .open_connection(
                ScopeSet::all(),
                TerminalCapabilities::from_scopes(&ScopeSet::all()),
            )
            .expect("first connection");
        let grant_b = authority
            .open_connection(
                ScopeSet::all(),
                TerminalCapabilities::from_scopes(&ScopeSet::all()),
            )
            .expect("second connection");
        assert_ne!(grant_a.principal_id(), grant_b.principal_id());
        assert_ne!(grant_a.session_id(), grant_b.session_id());
        assert_eq!(authority.active_sessions(), 2);
        grant_a.close();
        assert!(grant_a.authorize(METHOD_LIST_VIEWS, None).is_err());
        assert!(grant_b.authorize(METHOD_LIST_VIEWS, None).is_ok());
    }

    #[test]
    fn authority_intersects_terminal_capability_per_action() {
        let mut capabilities = TerminalCapabilities::new();
        capabilities
            .grant("t:1", Scope::TerminalInspect)
            .expect("terminal capability");
        let authority = ControlAuthority::new();
        let grant = authority
            .open_connection(ScopeSet::all(), capabilities)
            .expect("connection");
        let text = params_terminal_id("t:1");
        let input = params_send_input("t:1", "x");
        assert!(
            grant
                .authorize(METHOD_GET_TERMINAL_TEXT, Some(&text))
                .is_ok()
        );
        assert!(grant.authorize(METHOD_SEND_INPUT, Some(&input)).is_err());
        let other = params_terminal_id("t:2");
        assert!(
            grant
                .authorize(METHOD_GET_TERMINAL_TEXT, Some(&other))
                .is_err()
        );
    }

    #[test]
    fn authority_terminal_capability_grant_narrows_and_releases() {
        let authority = ControlAuthority::new();
        let grant = authority
            .open_connection(
                ScopeSet::all(),
                TerminalCapabilities::from_scopes(&ScopeSet::all()),
            )
            .expect("connection");
        let session = grant.session_id().to_string();
        let text = params_terminal_id("t:1");
        let input = params_send_input("t:1", "x");
        let other_input = params_send_input("t:2", "x");

        // Narrow t:1 to inspect: the connection may read it, never drive it.
        assert!(
            authority
                .grant_terminal_capability(&session, "t:1", Scope::TerminalInspect)
                .is_ok()
        );
        assert!(
            grant
                .authorize(METHOD_GET_TERMINAL_TEXT, Some(&text))
                .is_ok()
        );
        assert!(grant.authorize(METHOD_SEND_INPUT, Some(&input)).is_err());
        // The narrowing is per terminal, not per connection.
        assert!(
            grant
                .authorize(METHOD_SEND_INPUT, Some(&other_input))
                .is_ok()
        );

        // Grants are additive: a second capability widens that terminal back.
        assert!(
            authority
                .grant_terminal_capability(&session, "t:1", Scope::TerminalInput)
                .is_ok()
        );
        assert!(grant.authorize(METHOD_SEND_INPUT, Some(&input)).is_ok());

        // Releasing the last capability restores wildcard coverage.
        assert!(authority.release_terminal_capability(&session, "t:1", Scope::TerminalInput));
        assert!(authority.release_terminal_capability(&session, "t:1", Scope::TerminalInspect));
        assert!(
            grant
                .authorize(METHOD_GET_TERMINAL_TEXT, Some(&text))
                .is_ok()
        );
        assert!(grant.authorize(METHOD_SEND_INPUT, Some(&input)).is_ok());
        assert!(!authority.release_terminal_capability(&session, "t:1", Scope::TerminalInput));
    }

    #[test]
    fn authority_terminal_capability_grant_never_widens() {
        let authority = ControlAuthority::new();
        let scopes = ScopeSet::single(Scope::TerminalInspect);
        let grant = authority
            .open_connection(scopes.clone(), TerminalCapabilities::from_scopes(&scopes))
            .expect("connection");
        let session = grant.session_id().to_string();
        // A grant the connection's own scopes do not allow is refused, and the
        // refusal leaves no entry behind that could answer for t:1.
        assert!(matches!(
            authority.grant_terminal_capability(&session, "t:1", Scope::TerminalInput),
            Err(IpcError::ScopeDenied { .. })
        ));
        assert!(
            !grant
                .snapshot()
                .expect("snapshot")
                .terminal_capabilities
                .allows("t:1", Scope::TerminalInput)
        );
        // Unknown session and malformed terminal id fail closed too.
        assert!(matches!(
            authority.grant_terminal_capability("session-absent", "t:1", Scope::TerminalInspect),
            Err(IpcError::Unauthenticated { .. })
        ));
        assert!(matches!(
            authority.grant_terminal_capability(&session, "not-an-id", Scope::TerminalInspect),
            Err(IpcError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn await_control_reply_reports_unknown_outcome_when_apply_is_in_flight() {
        let (tx, rx) = std::sync::mpsc::channel::<ControlReply>();
        let budget = CTL_APPLY_MARGIN + std::time::Duration::from_millis(200);
        let item = PendingControl::with_deadline(
            METHOD_LIST_VIEWS,
            None,
            "1",
            tx,
            std::time::Instant::now() + budget,
        )
        .expect("pending control");
        // The drain claimed the entry and started applying: the effect is in
        // flight and the waiter must never await it a second time.
        assert!(item.claim());
        assert!(item.begin_apply());
        let started = std::time::Instant::now();
        let reply = await_control_reply(&rx, item.deadline, item.seq, &item.ticket());
        let elapsed = started.elapsed();
        assert!(!reply.ok);
        assert_eq!(reply.code, "Unavailable");
        assert!(
            reply.message.contains("outcome unknown"),
            "an in-flight apply is never reported as a no-effect timeout: {}",
            reply.message
        );
        assert!(
            elapsed < budget + std::time::Duration::from_millis(600),
            "one deadline is the whole bound, got {elapsed:?}"
        );
        // The in-flight apply keeps the ticket: the timeout neither withdraws
        // nor mutates a phase the drain already owns.
        assert!(!item.ticket().cancel());
        assert!(!withdraw_control_by_seq(item.seq));
    }

    #[test]
    fn await_control_reply_withdraws_a_claimed_entry_before_apply() {
        let (tx, rx) = std::sync::mpsc::channel::<ControlReply>();
        let item = PendingControl::with_deadline(
            METHOD_SPLIT_VIEW,
            Some(&params_split(SplitDirection::Right)),
            "1",
            tx,
            std::time::Instant::now() + std::time::Duration::from_millis(50),
        )
        .expect("pending control");
        // Popped by the drain but not started: the waiter's timeout withdraws
        // it, so the drain's `begin_apply` must refuse.
        assert!(item.claim());
        let reply = await_control_reply(&rx, item.deadline, item.seq, &item.ticket());
        assert_eq!(reply.code, "Unavailable");
        assert!(reply.message.contains("timed out"), "{}", reply.message);
        assert!(!item.begin_apply(), "a withdrawn entry never applies");
    }

    #[test]
    fn begin_apply_refuses_an_entry_inside_the_apply_margin() {
        let (tx, rx) = std::sync::mpsc::channel::<ControlReply>();
        let item = PendingControl::with_deadline(
            METHOD_SPLIT_VIEW,
            Some(&params_split(SplitDirection::Right)),
            "1",
            tx,
            std::time::Instant::now() + CTL_APPLY_MARGIN / 2,
        )
        .expect("pending control");
        assert!(item.claim());
        assert!(
            !item.begin_apply(),
            "an apply that cannot answer inside the deadline never starts"
        );
        let reply = rx.try_recv().expect("immediate no-effect reply");
        assert!(!reply.ok);
        assert!(reply.message.contains("timed out"), "{}", reply.message);
    }

    #[test]
    fn begin_apply_refuses_a_claimed_entry_past_its_deadline() {
        let (tx, _rx) = std::sync::mpsc::channel::<ControlReply>();
        let item = PendingControl::with_deadline(
            METHOD_SPLIT_VIEW,
            Some(&params_split(SplitDirection::Right)),
            "1",
            tx,
            std::time::Instant::now() - std::time::Duration::from_millis(1),
        )
        .expect("pending control");
        assert!(item.claim());
        assert!(!item.begin_apply(), "expired entry must never apply");
        // Withdrawn, so the client-side cancel has nothing left to cancel and
        // the drain cannot pick it up again.
        assert!(!item.ticket().cancel());
    }

    #[test]
    fn authority_grant_scope_invalidates_stale_snapshot() {
        let authority = ControlAuthority::new();
        let grant = authority
            .open_connection(ScopeSet::new(), TerminalCapabilities::new())
            .expect("connection");
        let stale = grant.snapshot().expect("initial snapshot");
        assert!(grant.authorize(METHOD_LIST_VIEWS, None).is_err());
        assert!(authority.grant_scope(grant.session_id(), Scope::ViewInspect));
        assert!(grant.authorize(METHOD_LIST_VIEWS, None).is_ok());
        assert!(
            authority
                .authorize_snapshot(&stale, METHOD_LIST_VIEWS, None)
                .is_err()
        );
        assert!(!authority.grant_scope(grant.session_id(), Scope::ViewInspect));
    }

    /// CTX-0792 (#1404): revoking a scope strips it from the terminal
    /// capability map too (wildcard and per-terminal entries), so the map can
    /// never keep authorizing a terminal read the connection no longer holds.
    #[test]
    fn authority_revoke_scope_strips_terminal_capabilities() {
        let mut scopes = ScopeSet::new();
        scopes.insert(Scope::TerminalInspect);
        scopes.insert(Scope::TerminalInput);
        let authority = ControlAuthority::new();
        let grant = authority
            .open_connection(scopes.clone(), TerminalCapabilities::from_scopes(&scopes))
            .expect("connection");
        authority
            .grant_terminal_capability(grant.session_id(), "t:1", Scope::TerminalInspect)
            .expect("per-terminal grant");
        let before = grant.snapshot().expect("snapshot");
        assert!(before.allows_terminal(None, Scope::TerminalInspect));
        assert!(before.allows_terminal(Some("t:1"), Scope::TerminalInspect));

        assert!(authority.revoke_scope(grant.session_id(), Scope::TerminalInspect));
        let after = grant.snapshot().expect("snapshot");
        assert!(!after.allows_terminal(None, Scope::TerminalInspect));
        assert!(!after.allows_terminal(Some("t:1"), Scope::TerminalInspect));
        assert!(
            !after.allows_terminal(Some("t:2"), Scope::TerminalInspect),
            "the wildcard lost the scope as well"
        );
        assert!(
            after.allows_terminal(Some("t:2"), Scope::TerminalInput),
            "unrelated scopes are untouched"
        );
        assert_ne!(
            before.identity.consent_generation, after.identity.consent_generation,
            "revocation advances the consent generation"
        );
    }

    /// CTX-0792 (#1404, CodeRabbit): closing a workspace kills sessions that
    /// the params do not name, so a narrowed terminal entry that lacks
    /// `terminal.manage` denies it just like `closeTerminal` on that terminal.
    #[test]
    fn close_workspace_requires_manage_on_every_terminal() {
        let mut scopes = ScopeSet::cli_default();
        scopes.insert(Scope::TerminalManage);
        let mut narrowed = TerminalCapabilities::from_scopes(&scopes);
        narrowed
            .grant("t:1", Scope::TerminalInspect)
            .expect("entry");
        let authority = ControlAuthority::new();
        let open = authority
            .open_connection(scopes.clone(), TerminalCapabilities::from_scopes(&scopes))
            .expect("open connection");
        let close = params_workspace("ws:1");
        assert!(open.authorize(METHOD_CLOSE_WORKSPACE, Some(&close)).is_ok());
        let narrow = authority
            .open_connection(scopes, narrowed)
            .expect("narrowed connection");
        assert!(matches!(
            narrow.authorize(METHOD_CLOSE_WORKSPACE, Some(&close)),
            Err(IpcError::ScopeDenied { .. })
        ));
        assert!(matches!(
            narrow.authorize(METHOD_CLOSE_TERMINAL, Some(&params_terminal_id("t:1"))),
            Err(IpcError::ScopeDenied { .. })
        ));
    }

    /// CodeRabbit: a `\uXXXX` escape whose four bytes cross a multibyte char
    /// boundary is a parse error, never a panic.
    #[test]
    fn unicode_escape_across_a_char_boundary_is_rejected_not_panicking() {
        let params = "{\"terminalId\":\"\\uab\u{20ac}\"}";
        assert!(matches!(
            parse_optional_terminal_id_params(Some(params)),
            Err(IpcError::InvalidRequest { .. })
        ));
    }

    /// CTX-0792 (#1403/#1404): the drain recheck reads the live terminal
    /// capability map, so a narrowing between enqueue and drain is honored
    /// even though it does not advance the consent generation.
    #[test]
    fn drain_recheck_reads_the_live_terminal_capability_map() {
        let mut scopes = ScopeSet::new();
        scopes.insert(Scope::TerminalInput);
        scopes.insert(Scope::TerminalInspect);
        let authority = ControlAuthority::new();
        let grant = authority
            .open_connection(scopes.clone(), TerminalCapabilities::from_scopes(&scopes))
            .expect("connection");
        let (tx, _rx) = std::sync::mpsc::channel::<ControlReply>();
        let item = PendingControl::with_connection(
            METHOD_SEND_INPUT,
            Some(&params_send_input("t:1", "x")),
            "1",
            tx,
            &grant,
        )
        .expect("pending control");
        assert!(item.authorize_at_drain(&ScopeSet::new()).is_ok());
        // Narrow t:1 to inspect-only after enqueue.
        authority
            .grant_terminal_capability(grant.session_id(), "t:1", Scope::TerminalInspect)
            .expect("narrowing entry");
        assert!(matches!(
            item.authorize_at_drain(&ScopeSet::new()),
            Err(IpcError::ScopeDenied { .. })
        ));
    }

    /// CTX-0792 (#1404): a map handed to `open_connection` is clamped to the
    /// session's scopes, and `grant_scope` extends the wildcard, so the map
    /// never disagrees with the scopes.
    #[test]
    fn open_connection_clamps_the_map_and_grant_scope_extends_the_wildcard() {
        let authority = ControlAuthority::new();
        let grant = authority
            .open_connection(
                ScopeSet::single(Scope::DebugInspect),
                TerminalCapabilities::from_scopes(&ScopeSet::all()),
            )
            .expect("connection");
        let snapshot = grant.snapshot().expect("snapshot");
        assert!(
            !snapshot
                .terminal_capabilities
                .wildcard_allows(Scope::TerminalInspect)
        );
        assert!(!snapshot.allows_every_terminal(Scope::TerminalInspect));
        assert!(authority.grant_scope(grant.session_id(), Scope::TerminalInspect));
        let widened = grant.snapshot().expect("snapshot");
        assert!(widened.allows_terminal(None, Scope::TerminalInspect));
        assert!(widened.allows_every_terminal(Scope::TerminalInspect));
    }

    /// CTX-0792 (#1403): identities come from one process-wide counter, so two
    /// independent authorities can never mint the same session id (the
    /// automation bearer store is process-wide and keyed by session).
    #[test]
    fn independent_authorities_never_share_a_session_id() {
        let first = ControlAuthority::new()
            .open_connection(ScopeSet::new(), TerminalCapabilities::new())
            .expect("first");
        let second = ControlAuthority::new()
            .open_connection(ScopeSet::new(), TerminalCapabilities::new())
            .expect("second");
        assert_ne!(first.session_id(), second.session_id());
        assert_ne!(first.principal_id(), second.principal_id());
    }

    #[test]
    fn control_sequence_exhaustion_is_terminal() {
        let mut state = ControlSequenceState {
            next: Some(u64::MAX),
        };
        assert_eq!(allocate_control_seq(&mut state), Ok(u64::MAX));
        assert!(matches!(
            allocate_control_seq(&mut state),
            Err(IpcError::Denied { ref code, .. }) if code == "SequenceExhausted"
        ));
    }

    /// CTX-0529 (LIVE-IPC-004) failing-first: a queued control whose deadline
    /// passed must never be handed over for execution. An entry stamped in
    /// the past arrives expired and the pop side must withdraw it (dropping
    /// the reply without applying) instead of returning it to the drain.
    #[test]
    fn expired_queued_control_is_withdrawn_not_applied() {
        let _guard = ControlWakeGuard::take();
        let (tx, rx) = std::sync::mpsc::channel::<ControlReply>();
        global_control_queue()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push_back(
                PendingControl::with_deadline(
                    METHOD_LIST_VIEWS,
                    None,
                    "1",
                    tx,
                    std::time::Instant::now()
                        .checked_sub(std::time::Duration::from_secs(1))
                        .unwrap_or_else(std::time::Instant::now),
                )
                .expect("sequence allocation"),
            );
        assert!(
            pop_pending_control().is_none(),
            "an expired entry must be withdrawn, never handed to the drain"
        );
        let reply = rx
            .try_recv()
            .expect("expired entry gets one terminal reply");
        assert!(!reply.ok);
        assert_eq!(reply.code, "Unavailable");
        assert!(
            pop_pending_control().is_none(),
            "the withdrawal must leave nothing behind for a later drain"
        );
    }

    /// CTX-0529 failing-first: a stale entry ahead of a live one must be
    /// skipped in FIFO order — the live verb behind it still drains.
    #[test]
    fn expired_head_does_not_block_live_tail() {
        let _guard = ControlWakeGuard::take();
        let (stale_tx, _stale_rx) = std::sync::mpsc::channel::<ControlReply>();
        let (live_tx, _live_rx) = std::sync::mpsc::channel::<ControlReply>();
        {
            let mut guard = global_control_queue()
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            guard.push_back(
                PendingControl::with_deadline(
                    METHOD_LIST_VIEWS,
                    None,
                    "1",
                    stale_tx,
                    std::time::Instant::now()
                        .checked_sub(std::time::Duration::from_secs(1))
                        .unwrap_or_else(std::time::Instant::now),
                )
                .expect("sequence allocation"),
            );
            guard.push_back(
                PendingControl::new(METHOD_LIST_VIEWS, None, "2", live_tx)
                    .expect("sequence allocation"),
            );
        }
        let live = pop_pending_control().expect("live tail must still drain");
        assert_eq!(live.id_raw, "2");
        assert!(pop_pending_control().is_none());
    }

    /// CTX-0529 failing-first: the waiter side must give an honest timeout.
    /// When nobody drains, `enqueue_control_and_wait` returns `Unavailable`
    /// and withdraws its own entry so a slow drain can never apply it after
    /// the caller already observed failure.
    #[test]
    fn timed_out_enqueue_withdraws_its_entry() {
        use std::time::Duration;
        let _guard = ControlWakeGuard::take();
        // Shrink the production budget only for this test via an explicit
        // short-deadline enqueue (same withdraw path the 5 s waiter uses).
        let (tx, rx) = std::sync::mpsc::channel::<ControlReply>();
        global_control_queue()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push_back(
                PendingControl::with_deadline(
                    METHOD_LIST_VIEWS,
                    None,
                    "1",
                    tx,
                    std::time::Instant::now() + Duration::from_millis(50),
                )
                .expect("sequence allocation"),
            );
        // Wait out the deadline exactly like the waiter does, then withdraw.
        assert!(
            rx.recv_timeout(Duration::from_millis(500)).is_err(),
            "nothing drains, so the reply must time out"
        );
        withdraw_expired_controls(std::time::Instant::now());
        assert!(
            pop_pending_control().is_none(),
            "post-timeout drain must find nothing: the entry was withdrawn"
        );
    }

    /// CTX-0529 failing-first: concurrent timeout+arrival is race-safe. A
    /// waiter that already gave up and a drain arriving at the same instant
    /// must agree: either the drain wins before the deadline (success on both
    /// sides) or the withdrawal wins (honest timeout, no effect). The drain
    /// side re-checks the deadline under no queue lock, so a reply send to an
    /// abandoned waiter is best-effort and never resurrects the effect.
    #[test]
    fn timeout_arrival_race_stays_honest() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;
        let _guard = ControlWakeGuard::take();
        let (tx, rx) = std::sync::mpsc::channel::<ControlReply>();
        let item = PendingControl::with_deadline(
            METHOD_LIST_VIEWS,
            None,
            "1",
            tx,
            std::time::Instant::now() + Duration::from_millis(20),
        )
        .expect("sequence allocation");
        assert!(!item.is_expired(std::time::Instant::now()));
        global_control_queue()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push_back(item);
        // Simulate the arrival side winning just before the deadline.
        let won = std::sync::Arc::new(AtomicBool::new(false));
        let won_clone = std::sync::Arc::clone(&won);
        let drain = std::thread::spawn(move || {
            let item = pop_pending_control();
            if let Some(item) = item {
                // `send` fails only when the waiter already withdrew; the
                // effect decision was already made at pop (pre-deadline).
                let _ = item.reply.send(ControlReply {
                    ok: true,
                    result_json: String::from("{\"views\":[]}"),
                    category: "",
                    code: "",
                    message: String::new(),
                });
                won_clone.store(true, Ordering::SeqCst);
            }
        });
        let reply = rx.recv_timeout(Duration::from_secs(2));
        drain.join().expect("drain thread must finish");
        // Exactly one outcome: drain won pre-deadline (success reply) — the
        // expired path would have withdrawn instead of replying.
        assert!(won.load(Ordering::SeqCst), "pre-deadline drain must win");
        let reply = reply.expect("waiter must observe the pre-deadline reply");
        assert!(
            reply.ok,
            "pre-deadline reply must be the success: {reply:?}"
        );
        assert!(pop_pending_control().is_none());
    }

    #[test]
    fn control_methods_map_to_expected_scopes() {
        assert_eq!(
            required_scope_for_ctl_method(METHOD_SEND_INPUT),
            Some(Scope::TerminalInput)
        );
        assert_eq!(
            required_scope_for_ctl_method(METHOD_CLOSE_TERMINAL),
            Some(Scope::TerminalManage)
        );
        assert_eq!(
            required_scope_for_ctl_method(METHOD_SPAWN_TERMINAL),
            Some(Scope::TerminalManage)
        );
        assert_eq!(
            required_scope_for_ctl_method(METHOD_SPLIT_VIEW),
            Some(Scope::ViewManage)
        );
        assert_eq!(
            required_scope_for_ctl_method(METHOD_FOCUS_VIEW),
            Some(Scope::ViewManage)
        );
        assert_eq!(
            required_scope_for_ctl_method(METHOD_RELOAD_CONFIG),
            Some(Scope::ConfigModify)
        );
        // Workspace entry (CTX-0257): list rides view.inspect, new/focus
        // ride view.manage (no elevation), close needs terminal.manage
        // (kill power, elevation — like terminal close).
        assert_eq!(
            required_scope_for_ctl_method(METHOD_LIST_WORKSPACES),
            Some(Scope::ViewInspect)
        );
        assert_eq!(
            required_scope_for_ctl_method(METHOD_NEW_WORKSPACE),
            Some(Scope::ViewManage)
        );
        assert_eq!(
            required_scope_for_ctl_method(METHOD_FOCUS_WORKSPACE),
            Some(Scope::ViewManage)
        );
        assert_eq!(
            required_scope_for_ctl_method(METHOD_MOVE_WORKSPACE),
            Some(Scope::ViewManage)
        );
        assert_eq!(
            required_scope_for_ctl_method(METHOD_CLOSE_WORKSPACE),
            Some(Scope::TerminalManage)
        );
        assert_eq!(
            required_scope_for_ctl_method(METHOD_LIST_TERMINALS),
            Some(Scope::TerminalInspect)
        );
        assert_eq!(
            required_scope_for_ctl_method(METHOD_GET_TERMINAL_TEXT),
            Some(Scope::TerminalInspect)
        );
        assert_eq!(required_scope_for_ctl_method("bitty.debug/nope"), None);
    }

    #[test]
    fn cli_default_allows_send_split_focus_text_but_not_close_spawn_reload() {
        let cli = ScopeSet::cli_default();
        // Allowed without elevation.
        assert!(authorize_ctl_method(METHOD_SEND_INPUT, &cli).is_ok());
        assert!(authorize_ctl_method(METHOD_SPLIT_VIEW, &cli).is_ok());
        assert!(authorize_ctl_method(METHOD_FOCUS_VIEW, &cli).is_ok());
        assert!(authorize_ctl_method(METHOD_GET_TERMINAL_TEXT, &cli).is_ok());
        assert!(authorize_ctl_method(METHOD_LIST_TERMINALS, &cli).is_ok());
        // CTX-0257: workspace list/new/focus ride the view scopes (no
        // elevation); workspace close needs terminal.manage like the other
        // kill verb. CTX-0259 move rides view.manage (no kill, no elevation).
        assert!(authorize_ctl_method(METHOD_LIST_WORKSPACES, &cli).is_ok());
        assert!(authorize_ctl_method(METHOD_NEW_WORKSPACE, &cli).is_ok());
        assert!(authorize_ctl_method(METHOD_FOCUS_WORKSPACE, &cli).is_ok());
        assert!(authorize_ctl_method(METHOD_MOVE_WORKSPACE, &cli).is_ok());
        assert!(authorize_ctl_method(METHOD_CLOSE_WORKSPACE, &cli).is_err());
        // Require explicit elevation: unscoped CLI callers are rejected.
        assert!(authorize_ctl_method(METHOD_CLOSE_TERMINAL, &cli).is_err());
        assert!(authorize_ctl_method(METHOD_SPAWN_TERMINAL, &cli).is_err());
        assert!(authorize_ctl_method(METHOD_RELOAD_CONFIG, &cli).is_err());
    }

    #[test]
    fn unscoped_callers_rejected_for_every_control_op() {
        let empty = ScopeSet::new();
        for method in all_control_methods() {
            let err = authorize_ctl_method(method, &empty).unwrap_err();
            assert!(
                matches!(err, IpcError::ScopeDenied { .. }),
                "{method} with empty scopes must be ScopeDenied, got {err:?}"
            );
        }
    }

    #[test]
    fn workspace_rename_and_move_panel_params_round_trip() {
        // Issue #1333: rename/move-panel params build and parse back.
        let params = params_workspace_rename("ws:2", "editor");
        let (id, name) = parse_workspace_rename_params(Some(&params)).expect("rename parses");
        assert_eq!(id, "ws:2");
        assert_eq!(name, "editor");
        let params = params_move_panel(3);
        assert_eq!(
            parse_move_panel_params(Some(&params)).expect("position parses"),
            3
        );
        // New verbs ride view.manage (no elevation, no kill).
        assert_eq!(
            required_scope_for_ctl_method(METHOD_RENAME_WORKSPACE),
            Some(Scope::ViewManage)
        );
        assert_eq!(
            required_scope_for_ctl_method(METHOD_MOVE_PANEL),
            Some(Scope::ViewManage)
        );
        assert!(all_control_methods().contains(&METHOD_RENAME_WORKSPACE));
        assert!(all_control_methods().contains(&METHOD_MOVE_PANEL));
        // Fail closed: blank names, missing fields, bad shapes, out-of-range
        // positions, oversized payloads.
        assert!(parse_workspace_rename_params(None).is_err());
        assert!(parse_workspace_rename_params(Some("{\"workspace_id\":\"ws:2\"}")).is_err());
        assert!(
            parse_workspace_rename_params(Some("{\"workspace_id\":\"ws:2\",\"name\":\"   \"}"))
                .is_err()
        );
        assert!(
            parse_workspace_rename_params(Some("{\"workspace_id\":\"v:2\",\"name\":\"x\"}"))
                .is_err()
        );
        let big = "y".repeat(MAX_WORKSPACE_RENAME_BYTES + 1);
        assert!(
            parse_workspace_rename_params(Some(&params_workspace_rename("ws:1", &big))).is_err()
        );
        assert!(parse_move_panel_params(None).is_err());
        assert!(parse_move_panel_params(Some("{\"position\":0}")).is_err());
        assert!(parse_move_panel_params(Some("{\"position\":257}")).is_err());
        assert!(parse_move_panel_params(Some("{\"position\":\"3\"}")).is_err());
        assert!(parse_move_panel_params(Some("{}")).is_err());
    }

    #[test]
    fn test_exit_requires_debug_control_elevation() {
        let method = crate::devtools::METHOD_TEST_EXIT;
        assert_eq!(
            required_scope_for_ctl_method(method),
            Some(Scope::DebugControl)
        );
        // CLI default holds no debug scope: denied fail-closed.
        let cli = ScopeSet::cli_default();
        let err = authorize_ctl_method(method, &cli).unwrap_err();
        assert!(matches!(err, IpcError::ScopeDenied { .. }), "got {err:?}");
        // Explicit elevation allowlist grants it, exactly like other verbs.
        let elevated = elevation_from_env(Some("debug.control"));
        assert!(authorize_ctl_method(method, &elevated).is_ok());
        // Unknown names grant nothing.
        let bogus = elevation_from_env(Some("debug-control"));
        assert!(authorize_ctl_method(method, &bogus).is_err());
    }

    #[test]
    fn mcp_readonly_cannot_send_or_manage() {
        let mcp = ScopeSet::mcp_default();
        assert!(authorize_ctl_method(METHOD_LIST_TERMINALS, &mcp).is_ok());
        assert!(authorize_ctl_method(METHOD_LIST_WORKSPACES, &mcp).is_ok());
        assert!(authorize_ctl_method(METHOD_SEND_INPUT, &mcp).is_err());
        assert!(authorize_ctl_method(METHOD_NEW_WORKSPACE, &mcp).is_err());
        assert!(authorize_ctl_method(METHOD_FOCUS_WORKSPACE, &mcp).is_err());
        assert!(authorize_ctl_method(METHOD_MOVE_WORKSPACE, &mcp).is_err());
        assert!(authorize_ctl_method(METHOD_CLOSE_TERMINAL, &mcp).is_err());
        assert!(authorize_ctl_method(METHOD_CLOSE_WORKSPACE, &mcp).is_err());
        assert!(authorize_ctl_method(METHOD_RELOAD_CONFIG, &mcp).is_err());
    }

    #[test]
    fn elevated_all_allows_every_control_op() {
        let all = ScopeSet::all();
        for method in all_control_methods() {
            assert!(
                authorize_ctl_method(method, &all).is_ok(),
                "{method} with all scopes must succeed"
            );
        }
    }

    #[test]
    fn terminal_and_view_ids_validate_shape_only() {
        assert_eq!(parse_terminal_id("t:3").unwrap(), 3);
        assert_eq!(parse_view_id("v:12").unwrap(), 12);
        assert_eq!(parse_workspace_id("ws:2").unwrap(), 2);
        assert!(parse_terminal_id("t:0").is_ok());
        assert!(parse_terminal_id("t:").is_err());
        assert!(parse_terminal_id("t:007").is_err());
        assert!(parse_terminal_id("3").is_err());
        assert!(parse_terminal_id("t:abc").is_err());
        assert!(parse_terminal_id("t:1;rm").is_err());
        assert!(parse_view_id("v:").is_err());
        assert!(parse_view_id("t:3").is_err());
        assert!(parse_workspace_id("ws:").is_err());
        assert!(parse_workspace_id("ws:007").is_err());
        assert!(
            parse_workspace_id("ws:0").is_ok(),
            "shape-only; existence is server-side"
        );
        assert!(parse_workspace_id("v:2").is_err());
        assert!(parse_workspace_id("t:2").is_err());
        assert!(parse_workspace_id("2").is_err());
        assert!(parse_workspace_id("ws:abc").is_err());
    }

    #[test]
    fn send_text_bounds_hold() {
        assert!(validate_send_text("cargo test").is_ok());
        assert!(validate_send_text("").is_err());
        assert!(validate_send_text("a\0b").is_err());
        let big = "x".repeat(MAX_SEND_TEXT_BYTES + 1);
        assert!(validate_send_text(&big).is_err());
    }

    #[test]
    fn send_params_roundtrip() {
        let params = params_send_input("t:1", "cargo test");
        let (id, text) = parse_send_params(Some(&params)).unwrap();
        assert_eq!(id, "t:1");
        assert_eq!(text, "cargo test");
    }

    #[test]
    fn workspace_params_roundtrip() {
        let params = params_workspace("ws:2");
        assert_eq!(parse_workspace_params(Some(&params)).unwrap(), "ws:2");
        assert!(parse_workspace_params(None).is_err());
        assert!(parse_workspace_params(Some("{\"workspace_id\":\"v:2\"}")).is_err());
        assert!(parse_workspace_params(Some("{\"workspace_id\":\"ws:007\"}")).is_err());
    }

    #[test]
    fn split_params_default_right() {
        assert_eq!(parse_split_params(None).unwrap(), SplitDirection::Right);
        let params = params_split(SplitDirection::Left);
        assert_eq!(
            parse_split_params(Some(&params)).unwrap(),
            SplitDirection::Left
        );
        assert!(parse_split_params(Some("{\"direction\":\"diagonal\"}")).is_err());
    }

    #[test]
    fn unknown_control_method_is_not_found_not_ambient() {
        let cli = ScopeSet::cli_default();
        let err = authorize_ctl_method("bitty.debug/rmRf", &cli).unwrap_err();
        assert!(matches!(err, IpcError::NotFound { .. }));
    }

    #[test]
    fn denial_returns_permission_without_enqueue() {
        // CTX-0231: a scope denial must fail fast as a permission error and
        // must never touch the control queue (no enqueue means no 5 s drain
        // wait, so a denial can never surface as a timeout). No timing
        // asserts: the queue-emptiness check is the proof.
        // CTX-0287: hold the global-queue serial guard for the whole body;
        // without it this test races enqueue_fires_control_waker (queue
        // theft both directions, CI run 34455962423).
        let _guard = ControlWakeGuard::take();
        let empty = ScopeSet::new();
        for method in all_control_methods() {
            let required = required_scope_for_ctl_method(method).expect("known method");
            let reply = enqueue_control_and_wait(method, None, "1", &empty);
            assert!(!reply.ok, "{method} with empty scopes must fail");
            assert_eq!(
                reply.category, "auth",
                "{method} denial must be auth, got {:?}",
                reply.category
            );
            assert_eq!(
                reply.code, "ScopeDenied",
                "{method} denial must be ScopeDenied, got {:?}",
                reply.code
            );
            assert!(
                reply.message.contains(required.as_str()),
                "{method} denial must name scope '{}', got {:?}",
                required.as_str(),
                reply.message
            );
            assert!(
                reply.message.contains("BITTY_CTL_ELEVATE"),
                "{method} denial must name the elevation surface, got {:?}",
                reply.message
            );
            assert!(
                !reply.message.contains("timed out"),
                "{method} denial must never read as a timeout, got {:?}",
                reply.message
            );
        }
        assert!(
            pop_pending_control().is_none(),
            "denials must not enqueue (nothing to drain, nothing to time out)"
        );
    }

    /// RAII hermeticity for the process-global queue + waker slot: other
    /// tests share both, so restore unconditionally on drop.
    /// CTX-0287: also serializes the two global-queue tests. Rust runs tests
    /// in parallel threads, so the denial test's drain/assert pair can steal
    /// (or observe) the waker test's enqueued item and vice versa (CI run
    /// 34455962423: complementary panics at :858 queue non-empty vs :919
    /// queue empty; 3/60 local repro). Every test that touches the globals
    /// holds `lock_control_queue_for_test` for its whole queue+waker
    /// sequence via `ControlWakeGuard::take`; pure-parser tests need no
    /// guard. Same `OnceLock<Mutex<()>>` idiom as devtools
    /// `introspection_test_lock`. Test-only: production paths never take
    /// this lock (lock order is always serial-guard then queue/waker locks,
    /// never the reverse, so no deadlock). Poison-safe so a panicking holder
    /// cannot cascade-fail the suite.
    struct ControlWakeGuard {
        _serial: std::sync::MutexGuard<'static, ()>,
    }

    fn control_queue_test_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    fn lock_control_queue_for_test() -> std::sync::MutexGuard<'static, ()> {
        control_queue_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    impl ControlWakeGuard {
        fn take() -> Self {
            let serial = lock_control_queue_for_test();
            while pop_pending_control().is_some() {}
            set_control_waker(None);
            Self { _serial: serial }
        }
    }

    impl Drop for ControlWakeGuard {
        fn drop(&mut self) {
            set_control_waker(None);
            while pop_pending_control().is_some() {}
            // `_serial` drops here, releasing the serial guard last.
        }
    }

    #[test]
    fn enqueue_fires_control_waker_without_any_drain() {
        // CTX-0235 regression: on an idle window the event loop sleeps in
        // `Wait` with no PTY damage, so nothing drains the control queue and
        // every verb times out. The enqueue path must therefore wake the
        // loop. This crate has no runtime and no render tick, so a wake that
        // fires here proves the wakeup precedes any drain.
        use std::sync::atomic::{AtomicUsize, Ordering};

        let _guard = ControlWakeGuard::take();
        let wakes = std::sync::Arc::new(AtomicUsize::new(0));
        let (wake_tx, wake_rx) = std::sync::mpsc::channel::<()>();
        let probe = std::sync::Arc::clone(&wakes);
        set_control_waker(Some(std::sync::Arc::new(move || {
            probe.fetch_add(1, Ordering::SeqCst);
            let _ = wake_tx.send(());
        })));

        let granted = ScopeSet::cli_default();
        let worker = std::thread::spawn(move || {
            enqueue_control_and_wait(METHOD_LIST_VIEWS, None, "1", &granted)
        });

        // The wakeup must fire promptly while the waiter is still blocked
        // and nothing has drained: pre-fix this times out (no waker exists).
        wake_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("enqueue must wake the event loop without any drain running");
        assert!(
            wakes.load(Ordering::SeqCst) >= 1,
            "waker must fire at least once per enqueue"
        );

        // Complete the waiter's reply with a single pop (the drain side is
        // the app's job; here we only prove the waiter unblocks with the
        // reply it was given).
        let item = pop_pending_control().expect("enqueue must have queued one action");
        assert_eq!(item.method, METHOD_LIST_VIEWS);
        item.reply
            .send(ControlReply {
                ok: true,
                result_json: String::from("{\"views\":[]}"),
                category: "",
                code: "",
                message: String::new(),
            })
            .expect("waiter must still be blocked on the reply");
        let reply = worker.join().expect("worker thread must finish");
        assert!(reply.ok, "waiter must receive the drained reply: {reply:?}");

        // Security lens: denials authorize-fail before enqueue, so they must
        // neither queue nor wake (the wakeup grants nothing and fires only
        // on successful enqueue).
        let wakes_before = wakes.load(Ordering::SeqCst);
        let empty = ScopeSet::new();
        let denied = enqueue_control_and_wait(METHOD_CLOSE_TERMINAL, None, "2", &empty);
        assert!(!denied.ok);
        assert_eq!(denied.code, "ScopeDenied");
        assert_eq!(
            wakes.load(Ordering::SeqCst),
            wakes_before,
            "scope denials must not wake the event loop"
        );
        assert!(pop_pending_control().is_none());
    }
}

// ── elevation allowlist (pre-granted per-instance, explicit) ───────────────

/// Server-side elevation allowlist from `BITTY_CTL_ELEVATE`.
///
/// Comma-separated scopes (e.g. `terminal.manage,config.modify`); unknown
/// names are ignored (fail-closed: they grant nothing). Starts from the CLI
/// default and adds each named scope. Empty/unset means no elevation.
#[must_use]
pub fn elevation_from_env(raw: Option<&str>) -> ScopeSet {
    use std::str::FromStr as _;
    let mut set = ScopeSet::cli_default();
    let Some(list) = raw else {
        return set;
    };
    for token in list.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if let Ok(scope) = Scope::from_str(token) {
            set.insert(scope);
        }
    }
    set
}

// ── cross-thread control queue (servo producers, main-thread consumer) ─────
//
// `Runtime` is `!Send`, so it never crosses threads: IPC connection threads
// (via `devtools` control handlers) enqueue [`PendingControl`] (pure data +
// reply channel) and block on the reply; the main thread (sole `Runtime`
// owner) drains via `pop_pending_control` and applies each action, then
// replies. Bounded (drop-newest at cap, fail-closed).

/// Maximum queued control actions (drop-newest past this, fail-closed).
pub const MAX_QUEUED_CONTROLS: usize = 64;

/// Part of the [`CTL_TIMEOUT`] budget reserved for applying and answering
/// (CTX-0792, #1403).
///
/// The drain only starts an apply while at least this much of the entry's
/// deadline remains, so a normal apply finishes and its real reply reaches the
/// waiter before the waiter's own timeout. An apply that still overruns the
/// margin is reported as an unknown outcome, never as a plain timeout that
/// would claim no effect landed.
pub const CTL_APPLY_MARGIN: Duration = Duration::from_millis(500);

/// Process-wide control sequence allocator state (non-reusing).
#[derive(Debug)]
struct ControlSequenceState {
    /// Next value to hand out; `None` once the space is exhausted.
    next: Option<u64>,
}

fn control_sequence_state() -> &'static Mutex<ControlSequenceState> {
    static STATE: std::sync::OnceLock<Mutex<ControlSequenceState>> = std::sync::OnceLock::new();
    STATE.get_or_init(|| Mutex::new(ControlSequenceState { next: Some(1) }))
}

/// Checked, non-reusing allocation (CORE-RUN-024): a value is never handed
/// out twice, and exhaustion is terminal (`SequenceExhausted`) instead of
/// wrapping onto a live entry's sequence.
fn allocate_control_seq(state: &mut ControlSequenceState) -> Result<u64, IpcError> {
    let value = state.next.ok_or_else(|| IpcError::Denied {
        code: "SequenceExhausted".into(),
        reason: "control sequence space exhausted".into(),
    })?;
    state.next = value.checked_add(1);
    Ok(value)
}

fn next_control_seq() -> Result<u64, IpcError> {
    let mut state = control_sequence_state()
        .lock()
        .map_err(|_| IpcError::Unavailable {
            reason: "control sequence allocator unavailable".into(),
        })?;
    allocate_control_seq(&mut state)
}

/// Queue-item lifecycle with exactly one completion owner (CORE-RUN-018).
///
/// `Queued -> Claimed -> Applying -> Applied`, or `Withdrawn` from `Queued`
/// or `Claimed`. Only the drain moves past `Claimed`; a timed-out waiter can
/// withdraw only an entry the drain has not started applying.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlPhase {
    Queued,
    Claimed,
    Applying,
    Applied,
    Withdrawn,
}

/// Shared handle on one queued control's phase.
#[derive(Clone, Debug)]
pub struct ControlTicket {
    state: Arc<Mutex<ControlPhase>>,
}

impl ControlTicket {
    /// Withdraw the entry if the drain has not started applying it.
    /// Returns `true` when this call withdrew it.
    pub fn cancel(&self) -> bool {
        let Ok(mut phase) = self.state.lock() else {
            return false;
        };
        if matches!(*phase, ControlPhase::Queued | ControlPhase::Claimed) {
            *phase = ControlPhase::Withdrawn;
            true
        } else {
            false
        }
    }

    /// Whether the drain has started (or finished) applying the entry.
    fn apply_started(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|phase| matches!(*phase, ControlPhase::Applying | ControlPhase::Applied))
    }
}

/// One queued control action (all `Send`; `Runtime` never crosses threads).
///
/// Carries the immutable authorization snapshot taken at enqueue plus the
/// authority that minted it, so the drain can re-validate consent and session
/// immediately before mutation (CTX-0792, #1403).
pub struct PendingControl {
    /// Wire method (e.g. `bitty.debug/sendInput`).
    pub method: String,
    /// Raw params object (if any). Redacted from `Debug`.
    pub params: Option<String>,
    /// Verbatim numeric id token for response correlation.
    pub id_raw: String,
    /// Reply channel back to the connection thread.
    pub reply: std::sync::mpsc::Sender<ControlReply>,
    /// Non-reusing owner sequence for targeted withdrawal (CTX-0529).
    pub seq: u64,
    /// Absolute deadline: `enqueue Instant + CTL_TIMEOUT`. The drain never
    /// starts an apply at or past `deadline - CTL_APPLY_MARGIN`.
    pub deadline: std::time::Instant,
    authority: Option<ControlAuthority>,
    authorization: Option<AuthorizationSnapshot>,
    ticket: ControlTicket,
}

impl fmt::Debug for PendingControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingControl")
            .field("method", &self.method)
            .field("params", &"<redacted>")
            .field("id_raw", &self.id_raw)
            .field("seq", &self.seq)
            .field("deadline", &self.deadline)
            .field("authority_bound", &self.authority.is_some())
            .finish()
    }
}

impl PendingControl {
    /// Stamp an authority-less entry: deadline is one full [`CTL_TIMEOUT`]
    /// budget from now. Without an authority snapshot the drain can only
    /// authorize it against the drain's fallback scopes, which production
    /// passes empty (fail closed).
    ///
    /// # Errors
    ///
    /// `SequenceExhausted` once the control sequence space is exhausted.
    pub fn new(
        method: &str,
        params: Option<&str>,
        id_raw: &str,
        reply: std::sync::mpsc::Sender<ControlReply>,
    ) -> Result<Self, IpcError> {
        Self::with_deadline(
            method,
            params,
            id_raw,
            reply,
            std::time::Instant::now() + CTL_TIMEOUT,
        )
    }

    /// Build an authority-less entry with an explicit deadline (tests use this
    /// to stage already-expired or short-lived entries).
    ///
    /// # Errors
    ///
    /// `SequenceExhausted` once the control sequence space is exhausted.
    pub fn with_deadline(
        method: &str,
        params: Option<&str>,
        id_raw: &str,
        reply: std::sync::mpsc::Sender<ControlReply>,
        deadline: std::time::Instant,
    ) -> Result<Self, IpcError> {
        Self::with_authority_and_deadline(method, params, id_raw, reply, deadline, None, None)
    }

    /// Build an entry bound to one connection: it carries the connection's
    /// live authorization snapshot and authority for the drain-time recheck.
    ///
    /// # Errors
    ///
    /// `Unauthenticated` when the connection's session is gone, and
    /// `SequenceExhausted` once the control sequence space is exhausted.
    pub fn with_connection(
        method: &str,
        params: Option<&str>,
        id_raw: &str,
        reply: std::sync::mpsc::Sender<ControlReply>,
        grant: &ConnectionGrant,
    ) -> Result<Self, IpcError> {
        Self::with_authority_and_deadline(
            method,
            params,
            id_raw,
            reply,
            std::time::Instant::now() + CTL_TIMEOUT,
            Some(grant.authority().clone()),
            Some(grant.snapshot()?),
        )
    }

    fn with_authority_and_deadline(
        method: &str,
        params: Option<&str>,
        id_raw: &str,
        reply: std::sync::mpsc::Sender<ControlReply>,
        deadline: std::time::Instant,
        authority: Option<ControlAuthority>,
        authorization: Option<AuthorizationSnapshot>,
    ) -> Result<Self, IpcError> {
        Ok(Self {
            method: method.to_string(),
            params: params.map(str::to_string),
            id_raw: id_raw.to_string(),
            reply,
            seq: next_control_seq()?,
            deadline,
            authority,
            authorization,
            ticket: ControlTicket {
                state: Arc::new(Mutex::new(ControlPhase::Queued)),
            },
        })
    }

    /// Shared handle on this entry's phase (the waiter keeps one).
    #[must_use]
    pub fn ticket(&self) -> ControlTicket {
        self.ticket.clone()
    }

    /// Authorization snapshot captured at enqueue, if connection-bound.
    #[must_use]
    pub fn authorization(&self) -> Option<&AuthorizationSnapshot> {
        self.authorization.as_ref()
    }

    /// Authority that minted the snapshot, if connection-bound.
    #[must_use]
    pub fn authority(&self) -> Option<&ControlAuthority> {
        self.authority.as_ref()
    }

    /// Drain-time authorization: a connection-bound entry is re-validated
    /// against the live authority (session, consent generation, scope, and
    /// terminal capability); an authority-less entry only against `fallback`.
    ///
    /// # Errors
    ///
    /// See [`ControlAuthority::authorize_snapshot`] and
    /// [`authorize_ctl_method`].
    pub fn authorize_at_drain(&self, fallback: &ScopeSet) -> Result<Scope, IpcError> {
        if let (Some(authority), Some(snapshot)) = (&self.authority, &self.authorization) {
            authority.authorize_snapshot(snapshot, &self.method, self.params.as_deref())
        } else {
            authorize_ctl_method(&self.method, fallback)
        }
    }

    /// Scopes the apply path may use: the snapshot's, never wider.
    #[must_use]
    pub fn effective_scopes(&self, fallback: &ScopeSet) -> ScopeSet {
        self.authorization
            .as_ref()
            .map(|snapshot| snapshot.scopes.clone())
            .unwrap_or_else(|| fallback.clone())
    }

    /// Whether `now` is at or past the entry deadline.
    #[must_use]
    pub fn is_expired(&self, now: std::time::Instant) -> bool {
        now >= self.deadline
    }

    /// Whether too little of the deadline remains to start an apply
    /// ([`CTL_APPLY_MARGIN`]).
    fn too_late_to_apply(&self, now: std::time::Instant) -> bool {
        self.deadline.saturating_duration_since(now) < CTL_APPLY_MARGIN
    }

    fn claim(&self) -> bool {
        let Ok(mut phase) = self.ticket.state.lock() else {
            return false;
        };
        if *phase == ControlPhase::Queued {
            *phase = ControlPhase::Claimed;
            true
        } else {
            false
        }
    }

    /// Claim the apply phase, refusing an entry too close to its deadline.
    ///
    /// A client-side timeout is final, so the deadline is re-checked under the
    /// same lock as the phase transition: a claimed entry with less than
    /// [`CTL_APPLY_MARGIN`] left is withdrawn instead of applied, so the apply
    /// and its reply fit inside the waiter's budget. Once the phase is
    /// `Applying` the effect is in flight and is never abandoned.
    pub fn begin_apply(&self) -> bool {
        let Ok(mut phase) = self.ticket.state.lock() else {
            return false;
        };
        if *phase != ControlPhase::Claimed {
            return false;
        }
        if self.too_late_to_apply(std::time::Instant::now()) {
            *phase = ControlPhase::Withdrawn;
            // Answer now with the honest no-effect timeout instead of leaving
            // the waiter to run out its remaining budget.
            let _ = self.reply.send(timed_out_control_reply());
            return false;
        }
        *phase = ControlPhase::Applying;
        true
    }

    fn cancel(&self) -> bool {
        self.ticket.cancel()
    }

    /// Mark an in-flight apply as committed.
    pub fn finish_apply(&self) {
        if let Ok(mut phase) = self.ticket.state.lock() {
            if *phase == ControlPhase::Applying {
                *phase = ControlPhase::Applied;
            }
        }
    }

    /// Mark an entry as withdrawn without effect after a drain-time denial.
    ///
    /// Only valid before any mutation for this entry has started: the drain
    /// calls it when the recheck that runs between `begin_apply` and the
    /// mutation denies. `Applied` entries are never changed.
    pub fn finish_without_apply(&self) {
        if let Ok(mut phase) = self.ticket.state.lock() {
            if matches!(*phase, ControlPhase::Claimed | ControlPhase::Applying) {
                *phase = ControlPhase::Withdrawn;
            }
        }
    }
}

/// Synchronous control result for the reply channel (all `Send`).
#[derive(Debug, Clone)]
pub struct ControlReply {
    /// Whether the action succeeded.
    pub ok: bool,
    /// Result JSON on success (already bounded).
    pub result_json: String,
    /// Error category on failure.
    pub category: &'static str,
    /// Error code on failure.
    pub code: &'static str,
    /// Human message on failure.
    pub message: String,
}

/// Global control queue shared between IPC connection threads and the main thread.
pub fn global_control_queue()
-> &'static std::sync::Mutex<std::collections::VecDeque<PendingControl>> {
    static QUEUE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::VecDeque<PendingControl>>,
    > = std::sync::OnceLock::new();
    QUEUE.get_or_init(|| std::sync::Mutex::new(std::collections::VecDeque::new()))
}

/// Pop one queued action (main-thread consumer).
///
/// CTX-0529: skips (withdraws) entries at or past their deadline instead of
/// handing them over for execution — the ctl-queue form of the CTX-0483
/// never-execute-after-deadline rule. A withdrawn entry is simply dropped:
/// its waiter already holds (or is about to observe) the honest timeout from
/// its own `recv_timeout`, so the pop side must not fabricate a second reply
/// that could race the timeout and read as a late success. Returns the first
/// live entry, or `None` when the queue drained or only expired entries
/// remained.
pub fn pop_pending_control() -> Option<PendingControl> {
    loop {
        let item = global_control_queue()
            .lock()
            .map(|mut q| q.pop_front())
            .unwrap_or(None)?;
        if !item.claim() {
            continue;
        }
        if item.is_expired(std::time::Instant::now()) {
            item.cancel();
            let _ = item.reply.send(timed_out_control_reply());
            continue;
        }
        return Some(item);
    }
}

/// Honest timeout reply shared by the waiter and the withdraw path.
///
/// Both sides must name the same outcome so a client can never observe a
/// success for an effect that never landed (or a timeout for one that did
/// pre-deadline — that case still carries the real reply).
fn timed_out_control_reply() -> ControlReply {
    ControlReply {
        ok: false,
        result_json: String::new(),
        category: "transport",
        code: "Unavailable",
        message: String::from("control timed out (no live runtime draining)"),
    }
}

/// Withdraw entries at or past `now` without applying them (CTX-0529).
///
/// Same withdraw semantics as [`pop_pending_control`] but queue-wide: used
/// by a timed-out waiter to reclaim its own entry so a slow drain can never
/// apply it afterwards. Returns the number withdrawn. Targeted by `seq`
/// when `Some` (a waiter reclaims exactly its own entry; live entries from
/// other callers are untouched), or sweeps every expired entry when `None`.
pub fn withdraw_expired_controls(now: std::time::Instant) -> usize {
    withdraw_controls_where(|item| item.is_expired(now), None)
}

/// Withdraw the queued entry owned by `seq` regardless of deadline.
///
/// Called by a waiter that timed out while its entry was still queued: the
/// caller already observed failure, so the entry must never apply later.
/// Returns `true` when an entry was found and withdrawn (drain will never
/// see it); `false` when the drain already popped it (the real reply — or
/// the pop-time withdraw — already decided the outcome).
pub fn withdraw_control_by_seq(seq: u64) -> bool {
    withdraw_controls_where(|_| true, Some(seq)) > 0
}

fn withdraw_controls_where(
    mut expired: impl FnMut(&PendingControl) -> bool,
    seq: Option<u64>,
) -> usize {
    // Single lock, drain + partition + requeue: the queue is tiny (<= 64)
    // and neither caller holds another lock, so the brief requeue window is
    // safe. Replies go out after the lock drops so a blocked receiver can
    // never stall queue operations.
    let mut dropped: Vec<PendingControl> = Vec::new();
    if let Ok(mut guard) = global_control_queue().lock() {
        let mut kept = std::collections::VecDeque::with_capacity(guard.len());
        while let Some(item) = guard.pop_front() {
            let owned = seq.is_none_or(|want| item.seq == want);
            if owned && expired(&item) && item.cancel() {
                dropped.push(item);
            } else {
                kept.push_back(item);
            }
        }
        *guard = kept;
    } else {
        return 0;
    }
    let count = dropped.len();
    for item in dropped {
        let _ = item.reply.send(timed_out_control_reply());
    }
    count
}

/// Clear the queue (test hook only; drops pending replies).
#[cfg(test)]
pub fn clear_control_queue_for_tests() {
    if let Ok(mut guard) = global_control_queue().lock() {
        guard.clear();
    }
}

/// Cross-thread event-loop wakeup hook (CTX-0235).
///
/// The control queue is drained by the main thread inside its event loop
/// (`drive_tick`), which sleeps in `ControlFlow::Wait` when idle. Without a
/// wakeup, an enqueue on an idle window sits until incidental damage wakes
/// the loop, so every verb times out. The hook is plain `std` (no winit
/// dependency in this crate): the app installs a closure that pings its
/// `EventLoopProxy`, and [`enqueue_control_and_wait`] fires it once per
/// successful enqueue, after the item is queued. Best-effort: a missing or
/// failed wake only restores the pre-CTX-0235 timing behavior; the drain
/// path and its scope/elevation checks are unchanged.
pub type ControlWaker = std::sync::Arc<dyn Fn() + Send + Sync + 'static>;

fn control_waker_slot() -> &'static std::sync::Mutex<Option<ControlWaker>> {
    static WAKER: std::sync::OnceLock<std::sync::Mutex<Option<ControlWaker>>> =
        std::sync::OnceLock::new();
    WAKER.get_or_init(|| std::sync::Mutex::new(None))
}

/// Install (or clear with `None`) the event-loop wakeup hook.
///
/// Called once by the app when it receives its event-loop proxy; tests use
/// `None` to restore the hermetic default.
pub fn set_control_waker(waker: Option<ControlWaker>) {
    if let Ok(mut slot) = control_waker_slot().lock() {
        *slot = waker;
    }
}

/// Fire the installed wakeup hook once (best-effort, never panics).
///
/// The slot lock is released before invoking the hook so a waker can never
/// deadlock against queue operations.
fn wake_event_loop_for_control() {
    let waker: Option<ControlWaker> = control_waker_slot()
        .lock()
        .map(|slot| (*slot).clone())
        .unwrap_or(None);
    if let Some(wake) = waker {
        wake();
    }
}

/// Stable `(category, code)` class for a control [`IpcError`], shared by the
/// enqueue path and the drain so one error never maps to two wire codes
/// (no new wire codes; see the CLI error taxonomy).
#[must_use]
pub fn control_error_class(err: &IpcError) -> (&'static str, &'static str) {
    match err {
        IpcError::ScopeDenied { .. } => ("auth", "ScopeDenied"),
        // Identity/sequence exhaustion is a terminal service state, not a
        // permission decision: `Unavailable` (transport, exit 6).
        IpcError::Denied { code, .. } if is_exhaustion_code(code) => ("transport", "Unavailable"),
        IpcError::Denied { .. } => ("auth", "Denied"),
        IpcError::Unauthenticated { .. } => ("auth", "Unauthenticated"),
        IpcError::NotFound { .. } => ("usage", "NotFound"),
        IpcError::InvalidMethod { .. } => ("usage", "InvalidMethod"),
        IpcError::InvalidRequest { .. } => ("usage", "InvalidParams"),
        // Authority/store capacity is a budget; any other bound is a payload
        // bound on the request itself.
        IpcError::LimitExceeded { field, .. } if is_capacity_field(field) => {
            ("budget", "RateLimited")
        }
        IpcError::LimitExceeded { .. } => ("transport", "PayloadTooLarge"),
        _ => ("transport", "Unavailable"),
    }
}

/// Whether a `LimitExceeded` field names server capacity (sessions, bearers,
/// capability entries) rather than a request payload bound.
fn is_capacity_field(field: &str) -> bool {
    matches!(
        field,
        "authority_sessions" | "terminal_capabilities" | "automation_bearers"
    )
}

/// Whether a `Denied` code names an exhausted identity or sequence space.
fn is_exhaustion_code(code: &str) -> bool {
    matches!(
        code,
        "SequenceExhausted" | "AuthorityExhausted" | "BearerSequenceExhausted"
    )
}

/// Map a pre-enqueue or drain-time [`IpcError`] onto the stable control
/// reply taxonomy ([`control_error_class`]); messages never echo params or
/// secrets.
#[must_use]
pub fn control_reply_from_error(ipc_err: IpcError) -> ControlReply {
    let (category, code) = control_error_class(&ipc_err);
    let message = match ipc_err {
        IpcError::ScopeDenied { scope, action } => format!(
            "permission denied: scope '{scope}' for {action} (needs elevation via BITTY_CTL_ELEVATE)"
        ),
        IpcError::Denied { code, reason } if is_exhaustion_code(&code) => {
            format!("control service unavailable: {code}: {reason}")
        }
        IpcError::Denied { code, reason } => {
            format!("permission denied: [{code}] {reason} (needs elevation via BITTY_CTL_ELEVATE)")
        }
        IpcError::Unauthenticated { .. } => {
            String::from("permission denied: connection authority is not active")
        }
        IpcError::NotFound { .. } => String::from("unknown control method"),
        IpcError::InvalidMethod { .. } => String::from("control method rejected"),
        IpcError::InvalidRequest { .. } => String::from("control request parameters rejected"),
        IpcError::LimitExceeded { field, .. } if is_capacity_field(&field) => {
            String::from("control authority limit exceeded; try again")
        }
        IpcError::LimitExceeded { .. } => String::from("control request exceeds a size bound"),
        _ => String::from("control service unavailable"),
    };
    ControlReply {
        ok: false,
        result_json: String::new(),
        category,
        code,
        message,
    }
}

/// Reply for a waiter whose deadline passed while the drain was applying:
/// the effect may have landed, so this never reads as the no-effect timeout.
fn outcome_unknown_control_reply() -> ControlReply {
    ControlReply {
        ok: false,
        result_json: String::new(),
        category: "transport",
        code: "Unavailable",
        message: String::from(
            "control outcome unknown: the apply was in flight at the deadline; re-read state before retrying",
        ),
    }
}

/// Wait for the drain's reply under exactly one deadline.
///
/// The control's own deadline is the single bound (the same [`CTL_TIMEOUT`] the
/// client uses for its socket timeouts), so worst-case per-call server
/// occupancy is one timeout, never two. On expiry the entry is withdrawn when
/// the drain has not started it (honest no-effect timeout). An apply already
/// in flight is not awaited again; the waiter reports an unknown outcome
/// instead of claiming nothing happened, and the drain's late reply is dropped
/// with the receiver.
fn await_control_reply(
    rx: &std::sync::mpsc::Receiver<ControlReply>,
    deadline: std::time::Instant,
    own_seq: u64,
    ticket: &ControlTicket,
) -> ControlReply {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    match rx.recv_timeout(remaining) {
        Ok(reply) => reply,
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => ControlReply {
            ok: false,
            result_json: String::new(),
            category: "transport",
            code: "Unavailable",
            message: String::from("control completion unavailable"),
        },
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            // Withdraws only when the entry is still queued: the drain owns a
            // popped entry and completes or withdraws it under its own phases.
            let _ = withdraw_control_by_seq(own_seq);
            // A claimed-but-not-started entry is withdrawn here too, so the
            // drain's `begin_apply` refuses it.
            let _ = ticket.cancel();
            if ticket.apply_started() {
                // The drain may have answered in the gap; prefer the real reply.
                return rx
                    .try_recv()
                    .unwrap_or_else(|_| outcome_unknown_control_reply());
            }
            timed_out_control_reply()
        }
    }
}

/// Enqueue an authority-less control action and wait for the main thread.
///
/// Authorizes via `granted` before enqueue (fail-closed, no partial state).
/// The entry carries no authorization snapshot, so the production drain
/// (empty fallback scopes) denies it; served connections use
/// [`enqueue_control_and_wait_with_connection`]. Waits up to [`CTL_TIMEOUT`];
/// timeout or a full queue becomes `Unavailable` / `RateLimited`.
pub fn enqueue_control_and_wait(
    method: &str,
    params: Option<&str>,
    id_raw: &str,
    granted: &ScopeSet,
) -> ControlReply {
    if let Err(ipc_err) = authorize_ctl_method(method, granted) {
        return control_reply_from_error(ipc_err);
    }
    let (tx, rx) = std::sync::mpsc::channel::<ControlReply>();
    let pending = match PendingControl::new(method, params, id_raw, tx) {
        Ok(pending) => pending,
        Err(err) => return control_reply_from_error(err),
    };
    enqueue_pending_and_wait(pending, &rx)
}

/// Enqueue a control action bound to one connection and wait for the drain.
///
/// Authorizes under the connection's live authority before enqueue, stamps
/// the authorization snapshot into the entry, and lets the drain re-validate
/// it immediately before mutation (CTX-0792, #1403). Waits up to one
/// [`CTL_TIMEOUT`].
pub fn enqueue_control_and_wait_with_connection(
    method: &str,
    params: Option<&str>,
    id_raw: &str,
    grant: &ConnectionGrant,
) -> ControlReply {
    if let Err(ipc_err) = grant.authorize(method, params) {
        return control_reply_from_error(ipc_err);
    }
    let (tx, rx) = std::sync::mpsc::channel::<ControlReply>();
    let pending = match PendingControl::with_connection(method, params, id_raw, tx, grant) {
        Ok(pending) => pending,
        Err(err) => return control_reply_from_error(err),
    };
    enqueue_pending_and_wait(pending, &rx)
}

/// Push `pending` (bounded, drop-newest), wake the drain, and wait.
fn enqueue_pending_and_wait(
    pending: PendingControl,
    rx: &std::sync::mpsc::Receiver<ControlReply>,
) -> ControlReply {
    let own_seq = pending.seq;
    let deadline = pending.deadline;
    let ticket = pending.ticket();
    {
        let queue = global_control_queue();
        let mut guard = queue.lock().unwrap_or_else(|poison| poison.into_inner());
        if guard.len() >= MAX_QUEUED_CONTROLS {
            return ControlReply {
                ok: false,
                result_json: String::new(),
                category: "budget",
                code: "RateLimited",
                message: String::from("control queue full; try again"),
            };
        }
        guard.push_back(pending);
    }
    // CTX-0235: wake the event loop after queueing (never while holding the
    // queue lock) so an idle window drains promptly instead of timing out.
    // The wakeup grants nothing and bypasses no check.
    wake_event_loop_for_control();
    await_control_reply(rx, deadline, own_seq, &ticket)
}
