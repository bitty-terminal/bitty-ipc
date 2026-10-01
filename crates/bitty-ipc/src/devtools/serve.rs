use super::*;

use super::handlers::json_escape_into;
use super::json::truncate_chars;

use crate::auth::VerifiedPeer;
#[cfg(unix)]
use crate::auth::{DIR_MODE, SOCKET_MODE};
#[cfg(all(test, unix))]
use crate::auth::{PeerCredentials, verify_peer_uid};
use crate::error::IpcError;
#[cfg(unix)]
use crate::frame::{MAX_FRAME_BYTES, encode_frame};
use crate::limits::RC9_MAX_CONNECTIONS;
#[cfg(unix)]
use crate::limits::RateLimiter;
use std::fmt;
#[cfg(unix)]
use std::io::{Read, Write};
use std::sync::Arc;
#[cfg(unix)]
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// ── socket path ─────────────────────────────────────────────────────────────

/// Resolve the Unix socket path with `auth.ts` precedence but a portable
/// `AF_UNIX` bound.
///
/// Precedence: non-empty `bitty_socket` (`BITTY_SOCKET`, advisory) wins
/// verbatim; otherwise `<base>/bitty/<instance>.sock` where `base` is
/// `xdg_runtime_dir` (`XDG_RUNTIME_DIR`) or `/run/user/<uid>`, and `instance`
/// is `instance_id` (`BITTY_INSTANCE_ID`) or `"default"`.
///
/// This function is pure advisory path resolution only: a non-empty
/// `BITTY_SOCKET` is returned after NUL/length checks with no ownership or
/// peer verification. Callers must verify the returned path before bind or
/// connect via [`verify_socket_endpoint_for_connect`] (client pre-connect,
/// which returns the endpoint identity) followed by
/// [`verify_connected_endpoint`] on the live stream (CTX-0539), or the
/// bind-time [`prepare_socket_dir`] + [`attest_bound_socket`] pair plus
/// the connected-stream binding used by the server accept path. The
/// pre-connect check alone is defense in depth: a checked-then-swapped
/// `BITTY_SOCKET` path is caught only by the post-connect binding.
/// Connecting to or serving an unverified `BITTY_SOCKET` path fails closed
/// at those boundaries, never here.
///
/// Validation: socket paths over [`MAX_SOCKET_PATH_BYTES`] payload bytes or
/// containing NUL are rejected fail-closed; instance ids must be 1..=64 ASCII
/// alphanumeric/`-`/`_` (`auth.ts` regex `^[a-z0-9_-]+$`, case-insensitive).
/// Lengths are measured in bytes here (Rust) rather than UTF-16 code units
/// (TypeScript); for the ASCII paths this contract admits, the two agree.
///
/// When the constructed `<base>/bitty/<instance>.sock` exceeds the portable
/// bound, the instance id is clamped to a deterministic 16-hex FNV-1a hash
/// (`<base>/bitty/<hash>.sock`) to keep short names stable; when even the
/// hashed form is too long the base directory itself is too long and
/// resolution fails closed with a clear `AF_UNIX`/`SUN_LEN` error. `auth.ts`
/// parity is precedence and instance grammar only: its 512-byte length check
/// is not portable to `bind` (Linux 108 / macOS 104 incl. NUL) and is not
/// adopted here.
///
/// # Errors
///
/// Returns [`IpcError::InvalidRequest`] for overlong/NUL paths, invalid
/// instance ids, and overlong base directories.
pub fn resolve_socket_path(
    runtime_uid: u32,
    xdg_runtime_dir: Option<&str>,
    bitty_socket: Option<&str>,
    instance_id: Option<&str>,
) -> Result<String, IpcError> {
    if let Some(sock) = bitty_socket {
        if !sock.is_empty() {
            if sock.contains('\0') {
                return Err(IpcError::InvalidRequest {
                    reason: "BITTY_SOCKET contains NUL".into(),
                });
            }
            if sock.len() > MAX_SOCKET_PATH_BYTES {
                return Err(IpcError::InvalidRequest {
                    reason: format!(
                        "BITTY_SOCKET path too long for AF_UNIX ({} > {MAX_SOCKET_PATH_BYTES} payload bytes; portable SUN_LEN: Linux {SUN_LEN_LINUX} / macOS {SUN_LEN_MACOS} incl. NUL)",
                        sock.len()
                    ),
                });
            }
            return Ok(sock.to_string());
        }
    }
    let instance = instance_id.unwrap_or(DEFAULT_INSTANCE_ID);
    validate_instance_id(instance)?;
    let base = match xdg_runtime_dir {
        Some(dir) if !dir.is_empty() => dir.to_string(),
        _ => format!("/run/user/{runtime_uid}"),
    };
    let direct = format!("{base}/{SOCKET_LEAF_DIR}/{instance}.sock");
    if direct.len() <= MAX_SOCKET_PATH_BYTES {
        return Ok(direct);
    }
    let hashed = format!(
        "{base}/{SOCKET_LEAF_DIR}/{}.sock",
        short_instance_hash(instance)
    );
    if hashed.len() <= MAX_SOCKET_PATH_BYTES {
        return Ok(hashed);
    }
    Err(IpcError::InvalidRequest {
        reason: format!(
            "socket base dir too long for AF_UNIX ({} > {MAX_SOCKET_PATH_BYTES} payload bytes even with hashed instance; portable SUN_LEN: Linux {SUN_LEN_LINUX} / macOS {SUN_LEN_MACOS} incl. NUL; shorten XDG_RUNTIME_DIR or set BITTY_SOCKET)",
            hashed.len()
        ),
    })
}

/// Deterministic 64-bit FNV-1a hash rendered as 16 lowercase hex chars.
///
/// `std`-only (no new dependencies): used solely to clamp long instance ids
/// into short, stable socket leaf names that fit the portable `AF_UNIX`
/// bound. Not a security hash; collision handling is fail-soft via live
/// socket reclaim in the servo.
fn short_instance_hash(instance: &str) -> String {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET;
    for byte in instance.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

/// Validate an instance id per `auth.ts` (`1..64`, `^[a-z0-9_-]+$`).
fn validate_instance_id(instance: &str) -> Result<(), IpcError> {
    if instance.is_empty() || instance.len() > MAX_INSTANCE_ID_LEN {
        return Err(IpcError::InvalidRequest {
            reason: format!(
                "instanceId must be 1..={MAX_INSTANCE_ID_LEN}, got {}",
                instance.len()
            ),
        });
    }
    let ok = instance
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !ok {
        return Err(IpcError::InvalidRequest {
            reason: "instanceId must match ^[a-z0-9_-]+$".into(),
        });
    }
    Ok(())
}

/// Advisory environment input for socket discovery.
///
/// `BITTY_SOCKET`, `XDG_RUNTIME_DIR`, and `BITTY_INSTANCE_ID` are identifiers,
/// never credentials; a forged value still fails peer-credential verification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketEnv {
    /// Value of `BITTY_SOCKET`, when set.
    pub bitty_socket: Option<String>,
    /// Value of `XDG_RUNTIME_DIR`, when set.
    pub xdg_runtime_dir: Option<String>,
    /// Value of `BITTY_INSTANCE_ID`, when set.
    pub instance_id: Option<String>,
}

impl SocketEnv {
    /// Read discovery variables from the process environment (advisory only).
    #[must_use]
    pub fn from_process_env() -> Self {
        Self {
            bitty_socket: std::env::var("BITTY_SOCKET").ok(),
            xdg_runtime_dir: std::env::var("XDG_RUNTIME_DIR").ok(),
            instance_id: std::env::var("BITTY_INSTANCE_ID").ok(),
        }
    }

    /// Effective instance id after defaulting (`"default"`).
    #[must_use]
    pub fn effective_instance(&self) -> String {
        match self.instance_id.as_deref() {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => DEFAULT_INSTANCE_ID.to_string(),
        }
    }
}

/// Resolve `(socket_path, instance)` from advisory environment.
///
/// `runtime_uid` is only needed to derive the last-resort base
/// `/run/user/<uid>` when neither `BITTY_SOCKET` nor `XDG_RUNTIME_DIR` is
/// set. The servo passes `None` (it has no `getuid` without new
/// dependencies); in that case a missing base fails closed with
/// [`IpcError::Unavailable`] instead of guessing.
///
/// # Errors
///
/// Forwards [`resolve_socket_path`] validation failures, or `Unavailable`
/// when the default base cannot be derived.
pub fn resolve_socket_path_from_env(
    env: &SocketEnv,
    runtime_uid: Option<u32>,
) -> Result<(String, String), IpcError> {
    let has_socket = env.bitty_socket.as_deref().is_some_and(|s| !s.is_empty());
    let has_base = env
        .xdg_runtime_dir
        .as_deref()
        .is_some_and(|s| !s.is_empty());
    if !has_socket && !has_base && runtime_uid.is_none() {
        return Err(IpcError::Unavailable {
            reason: "cannot derive socket base without uid; set XDG_RUNTIME_DIR or BITTY_SOCKET"
                .into(),
        });
    }
    let uid = runtime_uid.unwrap_or(0);
    let path = resolve_socket_path(
        uid,
        env.xdg_runtime_dir.as_deref(),
        env.bitty_socket.as_deref(),
        env.instance_id.as_deref(),
    )?;
    Ok((path, env.effective_instance()))
}

// ── server info ─────────────────────────────────────────────────────────────

/// Static server description captured at serve time (wired by `bitty-terminal`).
///
/// All fields are startup facts, never live terminal content: live grid
/// introspection is CTX-0159. `cols`/`rows` are the grid geometry the runtime
/// was configured with when serving started.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    /// Instance id scoping this socket (validated 1..=64).
    pub instance: String,
    /// Socket path being served.
    pub socket_path: String,
    /// Serving process id.
    pub pid: u32,
    /// Crate version of the serving binary's `bitty-ipc` (workspace version).
    pub app_version: String,
    /// Grid columns at startup.
    pub cols: usize,
    /// Grid rows at startup.
    pub rows: usize,
    /// Wall-clock start time (unix millis, informational only).
    pub started_unix_ms: u64,
    /// Monotonic start time for uptime accounting.
    pub started_at: Instant,
}

impl ServerInfo {
    /// Capture server facts. Total; clock failure yields `started_unix_ms`
    /// zero rather than aborting startup (fail-soft).
    #[must_use]
    pub fn new(instance: String, socket_path: String, cols: usize, rows: usize) -> Self {
        let started_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0);
        Self {
            instance,
            socket_path,
            pid: std::process::id(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            cols,
            rows,
            started_unix_ms,
            started_at: Instant::now(),
        }
    }

    /// Milliseconds since [`ServerInfo::new`] (saturating).
    #[must_use]
    pub fn uptime_ms(&self) -> u64 {
        let millis = self.started_at.elapsed().as_millis();
        u64::try_from(millis).unwrap_or(u64::MAX)
    }
}

#[cfg(unix)]
use crate::peer::StreamIdentity;

type PeerRecheck = dyn Fn() -> Result<VerifiedPeer, IpcError> + Send + Sync;

#[derive(Clone)]
pub struct ConnectedPeerProof {
    identity: VerifiedPeer,
    #[cfg(unix)]
    stream_identity: StreamIdentity,
    recheck: Arc<PeerRecheck>,
}

impl ConnectedPeerProof {
    #[must_use]
    pub fn identity(&self) -> VerifiedPeer {
        self.identity
    }

    #[cfg(unix)]
    fn same_binding(&self, other: &Self) -> bool {
        self.identity == other.identity
            && self.stream_identity == other.stream_identity
            && Arc::ptr_eq(&self.recheck, &other.recheck)
    }

    #[cfg(unix)]
    fn matches_stream_with<F>(
        &self,
        stream: &std::os::unix::net::UnixStream,
        stream_identity: F,
    ) -> Result<bool, IpcError>
    where
        F: FnOnce(&std::os::unix::net::UnixStream) -> Result<StreamIdentity, IpcError>,
    {
        Ok(stream_identity(stream)? == self.stream_identity)
    }

    #[cfg(all(test, unix))]
    pub(crate) fn stream_identity_for_test(&self) -> StreamIdentity {
        self.stream_identity
    }
}

/// Per-request dispatch context: static server facts plus fresh uptime.
///
/// `granted` is the server-evaluated scope set for the authenticated peer
/// (CLI default plus explicit `BITTY_CTL_ELEVATE` allowlist). Read-only
/// handlers ignore it (any authenticated same-UID peer may read); control
/// and automation handlers authorize against it on every request (never
/// ambient authority). `session_id` binds automation bearers to one debug
/// session: a bearer issued for another session fails closed with
/// `ScopeDenied` even when the token is otherwise valid.
/// Not `Clone`: it owns the connection's [`crate::ctl::ConnectionGrant`], and a
/// clone would share (and revoke) one connection's authority.
///
/// `local_attested` and `peer` stay private (CTX-0768, P0-AC-021): the only way
/// to reach the local-transport mark is
/// [`attest_local_peer`](ServeContext::attest_local_peer), which requires a
/// [`VerifiedPeer`] marker that equals the bound [`ConnectedPeerProof`], and
/// the only way to bind that proof is a real accepted-stream attestation.
/// A `pub` field would let any caller set the mark directly and would defeat
/// the per-dispatch recheck. Debug is hand-written below because
/// `ConnectedPeerProof` is not `Debug`; it deliberately reports
/// `local_attested` and `peer_bound` for peer-proof diagnostics.
pub struct ServeContext {
    /// Server facts.
    pub server: ServerInfo,
    /// Uptime at request time (millis). Automation handlers reuse this as
    /// the deterministic bearer/rate clock (headless, no wall-clock).
    pub uptime_ms: u64,
    /// Construction-time scopes: the hermetic contexts' answer. Authority-bound
    /// contexts never read it for a decision; use
    /// [`ServeContext::current_authorization`]. Private so no caller can
    /// widen it or mistake it for live authority.
    granted: crate::scope::ScopeSet,
    /// Opaque debug-session identity used for bearer binding and audit
    /// attribution; minted by the connection authority on served connections.
    session_id: String,
    local_attested: bool,
    peer: Option<ConnectedPeerProof>,
    #[cfg(test)]
    test_dispatch: bool,
    /// Server-owned connection authority (CTX-0792, #1403). `None` only on
    /// hermetic test/harness constructors, which set `authority_required` to
    /// `false` so they cannot silently authorize production traffic.
    connection_grant: Option<crate::ctl::ConnectionGrant>,
    /// Server-owned per-terminal capability intersection (CTX-0792, #1404).
    /// Authoritative value is read from the live grant via
    /// [`Self::current_authorization`]; this copy is the hermetic answer for
    /// `authority_required == false` contexts only.
    terminal_capabilities: crate::ctl::TerminalCapabilities,
    authority_required: bool,
}

impl fmt::Debug for ServeContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServeContext")
            .field("server", &self.server)
            .field("uptime_ms", &self.uptime_ms)
            .field("granted", &self.granted)
            .field("session_id", &self.session_id)
            .field("local_attested", &self.local_attested)
            .field("peer_bound", &self.peer.is_some())
            .field("authority_required", &self.authority_required)
            .finish()
    }
}

impl Drop for ServeContext {
    /// Session end on every exit path (including unwinding): the connection
    /// authority and its automation bearers never outlive the context.
    fn drop(&mut self) {
        self.close_connection();
    }
}

impl ServeContext {
    /// Build a context from server facts, stamping uptime now.
    ///
    /// Granted scopes default to the CLI interactive set plus the explicit
    /// `BITTY_CTL_ELEVATE` allowlist (impure: reads one env var; tests that
    /// need hermetic scopes use the `test-support` constructor
    /// `ServeContext::with_granted`). The context
    /// owns a standalone [`crate::ctl::ControlAuthority`] session, so it is
    /// authority-bound like a served connection; the accept path uses
    /// [`ServeContext::with_connection_grant`] with the listener's shared
    /// authority instead.
    #[must_use]
    pub fn new(server: &ServerInfo) -> Self {
        let granted =
            crate::ctl::elevation_from_env(std::env::var("BITTY_CTL_ELEVATE").ok().as_deref());
        let authority = crate::ctl::ControlAuthority::new();
        let capabilities = crate::ctl::TerminalCapabilities::from_scopes(&granted);
        let grant = authority
            .open_connection(granted.clone(), capabilities.clone())
            .ok();
        Self {
            server: server.clone(),
            uptime_ms: server.uptime_ms(),
            session_id: grant
                .as_ref()
                .map(|grant| grant.session_id().to_string())
                .unwrap_or_else(|| String::from("local")),
            granted,
            local_attested: false,
            peer: None,
            #[cfg(test)]
            test_dispatch: false,
            terminal_capabilities: capabilities,
            connection_grant: grant,
            authority_required: true,
        }
    }

    #[cfg(unix)]
    pub fn bind_connected_stream(
        &mut self,
        stream: &std::os::unix::net::UnixStream,
        expected_uid: u32,
    ) -> Result<ConnectedPeerProof, IpcError> {
        self.bind_connected_stream_with(stream, move |stream| {
            crate::peer::verify_unix_stream(stream, expected_uid)
        })
    }

    #[cfg(unix)]
    pub fn bind_connected_stream_current(
        &mut self,
        stream: &std::os::unix::net::UnixStream,
    ) -> Result<ConnectedPeerProof, IpcError> {
        let expected_uid = crate::peer::current_unix_uid()?;
        self.bind_connected_stream(stream, expected_uid)
    }

    #[cfg(unix)]
    fn bind_connected_stream_with<F>(
        &mut self,
        stream: &std::os::unix::net::UnixStream,
        verifier: F,
    ) -> Result<ConnectedPeerProof, IpcError>
    where
        F: Fn(&std::os::unix::net::UnixStream) -> Result<VerifiedPeer, IpcError>
            + Send
            + Sync
            + 'static,
    {
        let stream_identity = crate::peer::stream_identity(stream)?;
        let identity = verifier(stream)?;
        if crate::peer::stream_identity(stream)? != stream_identity {
            return Err(IpcError::Unauthenticated {
                reason: "connected stream identity changed during binding".into(),
            });
        }
        let probe = stream.try_clone().map_err(|err| IpcError::Unavailable {
            reason: format!("cannot retain connected peer descriptor: {err}"),
        })?;
        let verifier = Arc::new(verifier);
        let proof = ConnectedPeerProof {
            identity,
            stream_identity,
            recheck: Arc::new(move || verifier(&probe)),
        };
        self.peer = Some(proof.clone());
        #[cfg(test)]
        {
            self.test_dispatch = false;
        }
        Ok(proof)
    }

    #[cfg(all(test, unix))]
    pub(crate) fn bind_connected_stream_for_test<F>(
        &mut self,
        stream: &std::os::unix::net::UnixStream,
        verifier: F,
    ) -> Result<ConnectedPeerProof, IpcError>
    where
        F: Fn(&std::os::unix::net::UnixStream) -> Result<VerifiedPeer, IpcError>
            + Send
            + Sync
            + 'static,
    {
        self.bind_connected_stream_with(stream, verifier)
    }

    #[cfg(unix)]
    pub(crate) fn recheck_before_read(&self, proof: &ConnectedPeerProof) -> Result<(), IpcError> {
        if !self
            .peer
            .as_ref()
            .is_some_and(|bound| bound.same_binding(proof))
        {
            return Err(IpcError::Unauthenticated {
                reason: "connected peer binding does not match the served stream".into(),
            });
        }
        self.recheck_connection(Some(&proof.identity))
    }

    pub(crate) fn recheck_before_dispatch(&self) -> Result<(), IpcError> {
        self.recheck_connection(None)
    }

    fn recheck_connection(&self, supplied: Option<&VerifiedPeer>) -> Result<(), IpcError> {
        #[cfg(test)]
        if self.test_dispatch {
            return Ok(());
        }
        let Some(peer) = &self.peer else {
            return Err(IpcError::Unauthenticated {
                reason: "connected peer attestation is unavailable".into(),
            });
        };
        if supplied.is_some_and(|identity| identity != &peer.identity) {
            return Err(IpcError::Unauthenticated {
                reason: "connected peer identity changed".into(),
            });
        }
        let identity = (peer.recheck)()?;
        if identity != peer.identity {
            return Err(IpcError::Unauthenticated {
                reason: "connected peer attestation changed".into(),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn is_local_attested(&self) -> bool {
        self.local_attested
    }

    /// Mark this context as served over a verified-local transport.
    pub fn attest_local_peer(&mut self, peer: &VerifiedPeer) {
        #[cfg(test)]
        if self.test_dispatch {
            self.local_attested = true;
            return;
        }
        if self
            .peer
            .as_ref()
            .is_some_and(|bound| bound.identity == *peer)
        {
            self.local_attested = true;
        }
    }

    /// Build the production per-connection context from a server-owned
    /// [`crate::ctl::ConnectionGrant`] (CTX-0792, #1403).
    ///
    /// This is the only constructor a served connection uses. It does **not**
    /// establish peer proof: dispatch stays fail-closed until
    /// [`Self::bind_connected_stream`] succeeds, so an accepted-stream
    /// attestation is still required even though authority is already bound.
    /// Granted scopes, session id, and the per-terminal capability set are all
    /// read from the grant, so a context can never widen what the authority
    /// consented to.
    #[must_use]
    pub fn with_connection_grant(server: &ServerInfo, grant: crate::ctl::ConnectionGrant) -> Self {
        let snapshot = grant
            .snapshot()
            .unwrap_or_else(|_| grant.initial_snapshot().clone());
        Self {
            server: server.clone(),
            uptime_ms: server.uptime_ms(),
            granted: snapshot.scopes.clone(),
            session_id: snapshot.identity.session_id.clone(),
            local_attested: false,
            peer: None,
            #[cfg(test)]
            test_dispatch: false,
            terminal_capabilities: snapshot.terminal_capabilities,
            connection_grant: Some(grant),
            authority_required: true,
        }
    }

    /// Build an unbound context with explicit granted scopes.
    ///
    /// This constructor does not establish peer proof; dispatch remains
    /// fail-closed until [`Self::bind_connected_stream`] succeeds.
    ///
    /// Test support only (#1519): the context has no server-owned authority,
    /// so production builds do not compile it. Served connections use
    /// [`Self::with_connection_grant`].
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn with_granted(server: &ServerInfo, granted: crate::scope::ScopeSet) -> Self {
        Self {
            server: server.clone(),
            uptime_ms: server.uptime_ms(),
            terminal_capabilities: crate::ctl::TerminalCapabilities::from_scopes(&granted),
            granted,
            session_id: String::from("local"),
            local_attested: false,
            peer: None,
            #[cfg(test)]
            test_dispatch: false,
            connection_grant: None,
            authority_required: false,
        }
    }

    /// Build an unbound context with explicit scopes and session binding.
    ///
    /// This constructor does not establish peer proof; dispatch remains
    /// fail-closed until [`Self::bind_connected_stream`] succeeds. The terminal
    /// capability wildcard is exactly `granted`: nothing is added, so a harness
    /// that reads the grid must grant `terminal.inspect` explicitly.
    ///
    /// Test support only (#1519), like [`Self::with_granted`].
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn with_granted_session(
        server: &ServerInfo,
        granted: crate::scope::ScopeSet,
        session_id: &str,
    ) -> Self {
        let mut id = session_id.to_string();
        if id.chars().count() > 64 {
            id = id.chars().take(64).collect();
        }
        if id.is_empty() {
            id = String::from("local");
        }
        Self {
            server: server.clone(),
            uptime_ms: server.uptime_ms(),
            terminal_capabilities: crate::ctl::TerminalCapabilities::from_scopes(&granted),
            granted,
            session_id: id,
            local_attested: false,
            peer: None,
            #[cfg(test)]
            test_dispatch: false,
            connection_grant: None,
            authority_required: false,
        }
    }

    /// Hermetic authority context: a real [`crate::ctl::ConnectionGrant`] plus
    /// the `test_dispatch` seam.
    ///
    /// Mirrors [`Self::with_granted_for_tests`] for the authority path: hermetic
    /// unit tests have no accepted stream, so the per-dispatch peer recheck
    /// (CTX-0768) would fail closed and shadow the behaviour under test. The
    /// grant itself is real and `authority_required` stays `true`, so scope,
    /// consent-generation, and terminal-capability behaviour is exercised
    /// exactly as in production — only peer proof is stubbed. Production code
    /// must use [`Self::with_connection_grant`] and bind a real proof.
    #[cfg(test)]
    pub(crate) fn with_connection_grant_for_tests(
        server: &ServerInfo,
        grant: crate::ctl::ConnectionGrant,
    ) -> Self {
        let mut context = Self::with_connection_grant(server, grant);
        context.test_dispatch = true;
        context
    }

    #[cfg(test)]
    pub(crate) fn with_granted_for_tests(
        server: &ServerInfo,
        granted: crate::scope::ScopeSet,
    ) -> Self {
        let mut context = Self::with_granted(server, granted);
        context.test_dispatch = true;
        context
    }

    #[cfg(test)]
    pub(crate) fn with_granted_session_for_tests(
        server: &ServerInfo,
        granted: crate::scope::ScopeSet,
        session_id: &str,
    ) -> Self {
        let mut context = Self::with_granted_session(server, granted, session_id);
        context.test_dispatch = true;
        context
    }

    /// The server-owned connection grant, when this context has one.
    #[must_use]
    pub fn connection_grant(&self) -> Option<&crate::ctl::ConnectionGrant> {
        self.connection_grant.as_ref()
    }

    /// Session identity for bearer binding and audit attribution.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Construction-time scopes (hermetic contexts' explicit grant). Not a
    /// live authorization: decisions use [`Self::current_authorization`].
    #[must_use]
    pub fn construction_scopes(&self) -> &crate::scope::ScopeSet {
        &self.granted
    }

    /// Whether requests must be authorized by the connection authority
    /// (`true` for every production and `ServeContext::new` context; `false`
    /// only for the explicit-scope hermetic constructors).
    #[must_use]
    pub fn authority_required(&self) -> bool {
        self.authority_required
    }

    /// Fresh server-owned authorization for this request.
    ///
    /// Never cached: a live connection reads the current grant, so a scope
    /// revocation or a session-end revoke takes effect on the next request
    /// instead of at the next connection. Peer proof is orthogonal and is
    /// enforced separately by [`Self::recheck_before_dispatch`]; a context with
    /// authority but no bound peer proof still fails closed.
    pub fn current_authorization(&self) -> Result<crate::ctl::AuthorizationSnapshot, IpcError> {
        if self.authority_required {
            return self
                .connection_grant
                .as_ref()
                .ok_or_else(|| IpcError::Unauthenticated {
                    reason: "connection authority is unavailable".into(),
                })?
                .snapshot();
        }
        Ok(crate::ctl::AuthorizationSnapshot {
            identity: crate::ctl::ConnectionIdentity {
                principal_id: String::new(),
                session_id: self.session_id.clone(),
                consent_generation: 0,
            },
            scopes: self.granted.clone(),
            terminal_capabilities: self.terminal_capabilities.clone(),
        })
    }

    /// Whether the live authorization holds `scope`.
    #[must_use]
    pub fn has_scope(&self, scope: crate::scope::Scope) -> bool {
        self.current_authorization()
            .is_ok_and(|snapshot| snapshot.scopes.contains(scope))
    }

    /// Whether the live authorization holds any of `scopes`.
    #[must_use]
    pub fn has_any_scope(&self, scopes: &[crate::scope::Scope]) -> bool {
        self.current_authorization()
            .is_ok_and(|snapshot| scopes.iter().any(|scope| snapshot.scopes.contains(*scope)))
    }

    /// Terminal capability intersection under the live authorization
    /// ([`crate::ctl::AuthorizationSnapshot::allows_terminal`]).
    #[must_use]
    pub fn allows_terminal_capability(
        &self,
        terminal_id: Option<&str>,
        scope: crate::scope::Scope,
    ) -> bool {
        self.current_authorization()
            .is_ok_and(|snapshot| snapshot.allows_terminal(terminal_id, scope))
    }

    /// End this connection's session: revoke its authority and every
    /// automation bearer bound to it (idempotent; `Drop` calls it too).
    pub fn close_connection(&self) {
        if let Some(grant) = &self.connection_grant {
            grant.close();
            super::automation::revoke_automation_session(grant.session_id());
        }
    }

    /// Issue an automation bearer bound to this connection's live session,
    /// principal, and consent generation (CTX-0792, #1403).
    ///
    /// Test-only seam: the connection's scopes are the operator ceiling
    /// (`BITTY_CTL_ELEVATE` on top of the CLI default), not an explicit
    /// local-user consent, and the accepted contract forbids issuance from
    /// environment or configuration. No production path may issue a bearer
    /// until the consent flow exists.
    ///
    /// # Errors
    ///
    /// `Unauthenticated` without a live connection authority, `ScopeDenied`
    /// when the connection lacks the family's debug and terminal scopes, and
    /// the store's bound/entropy errors.
    #[cfg(test)]
    pub(crate) fn issue_automation_bearer(
        &self,
        terminal_id: &str,
        family: super::automation::AutomationFamily,
        now_ms: u64,
    ) -> Result<String, IpcError> {
        let grant = self
            .connection_grant
            .as_ref()
            .ok_or_else(|| IpcError::Unauthenticated {
                reason: "automation issuance requires a live connection authority".into(),
            })?;
        super::automation::issue_automation_bearer_for_connection(
            grant,
            terminal_id,
            family,
            now_ms,
            None,
        )
    }
}

// ── responses ───────────────────────────────────────────────────────────────

/// Encode a success response (`protocol.ts` `ResponseFrame` shape).
#[must_use]
pub fn encode_success(id_raw: &str, result_json: &str) -> Vec<u8> {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id_raw},\"result\":{result_json},\"version\":\"{DEVTOOLS_PROTOCOL_VERSION}\"}}"
    )
    .into_bytes()
}

/// Encode an error response, truncating the message to the echo bound.
#[must_use]
pub fn encode_error(id_raw: &str, category: &str, code: &str, message: &str) -> Vec<u8> {
    let bounded = truncate_chars(message, MAX_ERROR_MESSAGE_CHARS);
    let mut escaped = String::with_capacity(bounded.len());
    json_escape_into(&mut escaped, &bounded);
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id_raw},\"error\":{{\"category\":\"{category}\",\"code\":\"{code}\",\"message\":\"{escaped}\"}},\"version\":\"{DEVTOOLS_PROTOCOL_VERSION}\"}}"
    )
    .into_bytes()
}

/// Outcome of handling one envelope: response payload plus error flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleOutcome {
    /// Response payload bytes (unframed; the caller applies `encode_frame`).
    pub response: Vec<u8>,
    /// Whether the response carries `error` rather than `result`.
    pub was_error: bool,
    /// Whether the connection must close after this response.
    pub close_connection: bool,
}

/// Handle one complete request envelope: parse, dispatch, serialize.
///
/// Total: every failure mode yields a correlated error response, never a
/// panic and never an `Err`. Framing (`encode_frame`) is left to the caller
/// so both socket and in-memory harnesses share this path.
#[must_use]
pub fn handle_envelope(
    payload: &[u8],
    dispatcher: &Dispatcher,
    context: &ServeContext,
) -> HandleOutcome {
    let request = match parse_request(payload) {
        Ok(request) => request,
        Err(fault) => {
            let id = fault.id_raw.as_deref().unwrap_or("0");
            return HandleOutcome {
                response: encode_error(id, fault.category, fault.code, &fault.message),
                was_error: true,
                close_connection: false,
            };
        }
    };
    match dispatcher.dispatch(context, &request) {
        Ok(result_json) => HandleOutcome {
            response: encode_success(&request.id_raw, &result_json),
            was_error: false,
            close_connection: false,
        },
        Err(handler_err) => HandleOutcome {
            response: encode_error(
                &request.id_raw,
                handler_err.category,
                handler_err.code,
                &handler_err.message,
            ),
            was_error: true,
            close_connection: handler_err.code == "Unauthenticated",
        },
    }
}

/// Error response for failures before parsing (oversize frame, rate limit
/// with unparseable id). Always uses id `0`.
#[must_use]
pub fn id_zero_error(category: &str, code: &str, message: &str) -> Vec<u8> {
    encode_error("0", category, code, message)
}

// ── socket directory attestation (unix) ─────────────────────────────────────

/// Attested socket-directory facts established before serving.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirAttestation {
    /// Owner UID of the socket directory.
    pub dir_uid: u32,
    /// Permission bits of the socket directory (masked to `0o777`).
    pub dir_mode: u32,
}

/// Ensure the socket's parent directory exists with `0700` semantics.
///
/// Creates missing ancestors without touching their modes, and enforces
/// `0700` on the leaf directory only when this process just created it.
/// A pre-existing leaf with a wrong mode fails closed (never chmod another
/// owner's directory). Returns the leaf's owner and mode for post-bind
/// attestation.
///
/// # Errors
///
/// Returns `Unavailable` for filesystem failures and `Unauthenticated` when
/// a pre-existing leaf violates the `0700` requirement.
#[cfg(unix)]
pub fn prepare_socket_dir(socket_path: &str) -> Result<DirAttestation, IpcError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::Path;

    let path = Path::new(socket_path);
    let parent = path.parent().ok_or_else(|| IpcError::InvalidRequest {
        reason: "socket path has no parent directory".into(),
    })?;
    if parent.as_os_str().is_empty() {
        return Err(IpcError::InvalidRequest {
            reason: "socket path has no parent directory".into(),
        });
    }
    // Create missing ancestors (their modes are left alone: never touch what
    // might be /run/user/<uid> or another owner's directory).
    if let Some(grandparent) = parent.parent() {
        if !grandparent.as_os_str().is_empty() {
            std::fs::create_dir_all(grandparent).map_err(|err| IpcError::Unavailable {
                reason: format!(
                    "cannot create socket directory ancestors {}: {err}",
                    grandparent.display()
                ),
            })?;
        }
    }
    // Create the leaf exclusively: success proves this process created it, so
    // enforcing 0700 is safe. A pre-existing leaf keeps its mode and is
    // verified (never chmodded) below.
    match std::fs::DirBuilder::new()
        .recursive(false)
        .mode(DIR_MODE)
        .create(parent)
    {
        Ok(()) => {
            // umask may have narrowed the mode; set it exactly (ours).
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(DIR_MODE)).map_err(
                |err| IpcError::Unavailable {
                    reason: format!("cannot set socket directory mode: {err}"),
                },
            )?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => {
            return Err(IpcError::Unavailable {
                reason: format!("cannot create socket directory {}: {err}", parent.display()),
            });
        }
    }
    attestation_for(parent)
}

/// Read owner/mode attestation for an existing directory.
///
/// CR-IPC-01 (fail-closed): uses `symlink_metadata` and rejects symlinks
/// outright. `std::fs::metadata` follows symlinks, which would let a second
/// local user redirect the socket directory to an attacker-controlled target
/// on a multi-user machine and have its mode/owner attested as ours.
#[cfg(unix)]
fn attestation_for(parent: &std::path::Path) -> Result<DirAttestation, IpcError> {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::symlink_metadata(parent).map_err(|err| IpcError::Unavailable {
        reason: format!("cannot stat socket directory {}: {err}", parent.display()),
    })?;
    if meta.file_type().is_symlink() {
        return Err(IpcError::Unauthenticated {
            reason: format!(
                "socket directory {} is a symlink (refusing to serve)",
                parent.display()
            ),
        });
    }
    let dir_mode = meta.mode() & 0o777;
    if dir_mode != DIR_MODE {
        return Err(IpcError::Unauthenticated {
            reason: format!(
                "socket directory mode {dir_mode:o} != {:o} (must be 0700; refusing to serve)",
                DIR_MODE
            ),
        });
    }
    Ok(DirAttestation {
        dir_uid: meta.uid(),
        dir_mode,
    })
}

/// Fail-closed pre-check: reject a symlinked socket path before chmod.
///
/// `set_permissions` follows symlinks, so without this guard a symlinked
/// socket path would chmod an attacker-chosen target. Missing paths map to
/// `Unavailable` (filesystem failure); symlinks map to `Unauthenticated`.
#[cfg(unix)]
fn reject_socket_symlink(socket_path: &str) -> Result<(), IpcError> {
    let pre = std::fs::symlink_metadata(socket_path).map_err(|err| IpcError::Unavailable {
        reason: format!("cannot stat bound socket: {err}"),
    })?;
    if pre.file_type().is_symlink() {
        return Err(IpcError::Unauthenticated {
            reason: "bound socket is a symlink (refusing to serve)".into(),
        });
    }
    Ok(())
}

/// Attest a freshly bound socket: enforce `0600` and verify endpoint.
///
/// CR-IPC-01 (fail-closed): the socket path is `symlink_metadata`-checked
/// and symlink-rejected both before `set_permissions` (so a symlink can never
/// redirect the `0600` chmod onto another owner's file) and after (so a
/// swapped-in symlink is never attested as the bound socket).
///
/// The socket file owner is the serving euid (this process just created it),
/// so `runtime_uid` is established here without `getuid`. Requires the
/// directory owner to match the socket owner and both modes to be exact.
/// Directory replacement after this point cannot escalate: every connection
/// still verifies peer UID equality.
///
/// # Errors
///
/// Returns `Unavailable` for filesystem failures and `Unauthenticated` when
/// any mode/owner check fails (fail-closed: the caller must not serve).
#[cfg(unix)]
pub fn attest_bound_socket(socket_path: &str, dir: &DirAttestation) -> Result<u32, IpcError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    reject_socket_symlink(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(SOCKET_MODE)).map_err(
        |err| IpcError::Unavailable {
            reason: format!("cannot set socket mode 0600: {err}"),
        },
    )?;
    let meta = std::fs::symlink_metadata(socket_path).map_err(|err| IpcError::Unavailable {
        reason: format!("cannot stat bound socket: {err}"),
    })?;
    if meta.file_type().is_symlink() {
        return Err(IpcError::Unauthenticated {
            reason: "bound socket is a symlink (refusing to serve)".into(),
        });
    }
    let sock_mode = meta.mode() & 0o777;
    if sock_mode != SOCKET_MODE {
        return Err(IpcError::Unauthenticated {
            reason: format!(
                "socket mode {sock_mode:o} != {:o} (must be 0600)",
                SOCKET_MODE
            ),
        });
    }
    let sock_uid = meta.uid();
    if dir.dir_uid != sock_uid {
        return Err(IpcError::Unauthenticated {
            reason: format!(
                "socket directory owner {} != socket owner {sock_uid}",
                dir.dir_uid
            ),
        });
    }
    Ok(sock_uid)
}

/// Identity of an attested socket endpoint (CTX-0539).
///
/// Captured from the socket inode by [`verify_socket_endpoint_for_connect`]
/// so a client can bind a *connected* stream back to the endpoint it vetted
/// before connect. Device + inode identify the kernel object, not the path
/// string, so a simple checked-then-swapped path (unlink + rebind at the same
/// name) is observable even though the pathname is unchanged. See
/// [`verify_connected_endpoint`] for the residual double-swap race this does
/// not eliminate.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketEndpointIdentity {
    /// Device id of the socket inode.
    pub dev: u64,
    /// Inode number of the socket inode.
    pub ino: u64,
    /// Owner uid (already required to equal `runtime_uid`).
    pub uid: u32,
    /// Permission bits (already required to equal [`SOCKET_MODE`]).
    pub mode: u32,
}

/// Verify an existing socket endpoint before connect or accept (unix).
///
/// Read-only fail-closed checks for `BITTY_SOCKET` and other resolved paths:
/// the parent directory must exist with mode `0700` owned by `runtime_uid`,
/// and the socket file must exist with mode `0600` owned by `runtime_uid`;
/// symlinks at either layer are rejected outright (no follow). Missing paths
/// fail with `Unavailable` (cannot attest what cannot be stated); mode,
/// owner, or symlink violations fail with `Unauthenticated` (caller must not
/// connect or serve).
///
/// On success the endpoint's [`SocketEndpointIdentity`] is returned so the
/// caller can re-bind the connected stream to this exact inode via
/// [`verify_connected_endpoint`] (CTX-0539). The pre-connect check alone is
/// defense in depth: it cannot prove which inode a later `connect` reached,
/// so it must never be the sole gate.
///
/// Server bind uses [`prepare_socket_dir`] + [`attest_bound_socket`] instead
/// (they create and chmod); this function is for pre-connect verification
/// and independent endpoint tamper checks. The server must also bind and
/// recheck the connected stream through [`ServeContext::bind_connected_stream`].
///
/// # Errors
///
/// Returns `InvalidRequest` for empty/NUL/overlong paths, `Unavailable` for
/// filesystem failures, and `Unauthenticated` for ownership/mode/symlink
/// violations.
#[cfg(unix)]
pub fn verify_socket_endpoint_for_connect(
    socket_path: &str,
    runtime_uid: u32,
) -> Result<SocketEndpointIdentity, IpcError> {
    use std::os::unix::fs::MetadataExt;

    if socket_path.is_empty() {
        return Err(IpcError::InvalidRequest {
            reason: "socket path is empty".into(),
        });
    }
    if socket_path.contains('\0') {
        return Err(IpcError::InvalidRequest {
            reason: "socket path contains NUL".into(),
        });
    }
    if socket_path.len() > MAX_SOCKET_PATH_BYTES {
        return Err(IpcError::InvalidRequest {
            reason: format!(
                "socket path too long for AF_UNIX ({} > {MAX_SOCKET_PATH_BYTES} payload bytes)",
                socket_path.len()
            ),
        });
    }
    let path = std::path::Path::new(socket_path);
    let parent = path.parent().ok_or_else(|| IpcError::InvalidRequest {
        reason: "socket path has no parent directory".into(),
    })?;
    if parent.as_os_str().is_empty() {
        return Err(IpcError::InvalidRequest {
            reason: "socket path has no parent directory".into(),
        });
    }
    let dir_meta = std::fs::symlink_metadata(parent).map_err(|err| IpcError::Unavailable {
        reason: format!("cannot stat socket directory {}: {err}", parent.display()),
    })?;
    if dir_meta.file_type().is_symlink() {
        return Err(IpcError::Unauthenticated {
            reason: format!(
                "socket directory {} is a symlink (refusing to connect)",
                parent.display()
            ),
        });
    }
    let dir_mode = dir_meta.mode() & 0o777;
    if dir_mode != DIR_MODE {
        return Err(IpcError::Unauthenticated {
            reason: format!(
                "socket directory mode {dir_mode:o} != {:o} (must be 0700; refusing to connect)",
                DIR_MODE
            ),
        });
    }
    if dir_meta.uid() != runtime_uid {
        return Err(IpcError::Unauthenticated {
            reason: format!(
                "socket directory owner {} != runtime {runtime_uid} (refusing to connect)",
                dir_meta.uid()
            ),
        });
    }
    let sock_meta =
        std::fs::symlink_metadata(socket_path).map_err(|err| IpcError::Unavailable {
            reason: format!("cannot stat socket {socket_path}: {err}"),
        })?;
    if sock_meta.file_type().is_symlink() {
        return Err(IpcError::Unauthenticated {
            reason: "socket is a symlink (refusing to connect)".into(),
        });
    }
    let sock_mode = sock_meta.mode() & 0o777;
    if sock_mode != SOCKET_MODE {
        return Err(IpcError::Unauthenticated {
            reason: format!(
                "socket mode {sock_mode:o} != {:o} (must be 0600; refusing to connect)",
                SOCKET_MODE
            ),
        });
    }
    if sock_meta.uid() != runtime_uid {
        return Err(IpcError::Unauthenticated {
            reason: format!(
                "socket owner {} != runtime {runtime_uid} (refusing to connect)",
                sock_meta.uid()
            ),
        });
    }
    Ok(SocketEndpointIdentity {
        dev: sock_meta.dev(),
        ino: sock_meta.ino(),
        uid: sock_meta.uid(),
        mode: sock_mode,
    })
}

/// Re-binds a connected client stream to the endpoint vetted before connect
/// (CTX-0539).
///
/// The pre-connect [`verify_socket_endpoint_for_connect`] check and the
/// `connect` call are not atomic: a path can be unlinked and rebound between
/// them (checked-then-swapped). This reads the kernel-reported peer address
/// of the already-connected `stream` (`UnixStream::peer_addr`) and requires
/// its filesystem identity to equal `expected`, so a stream that reached a
/// foreign server fails closed before one request byte is written.
///
/// This is the strongest post-connect proof available on stable Rust with
/// `#![forbid(unsafe_code)]`: per-connection `SO_PEERCRED` needs the unstable
/// `peer_credentials_unix_socket` feature or a reviewed `unsafe` seam, and a
/// challenge/response needs a pre-shared secret the accepted IPC RFC still
/// records as an open question (discovery nonce).
///
/// **Residual race (honest bound).** `peer_addr` is the path string the
/// client passed to `connect`, not the connected kernel socket's inode, so
/// the post-connect `stat` re-reads whatever inode currently occupies that
/// path. An attacker able to swap the path back to the vetted inode *after*
/// the connection was accepted would make this check pass while the
/// established connection still terminates at the foreign listener. This
/// narrows the checked-then-swapped window to a double-swap race but does not
/// cryptographically close it; only `SO_PEERCRED` (or a challenge/response)
/// removes the race entirely. Peer-UID re-checking remains separate hardening.
///
/// # Errors
///
/// Returns `Unauthenticated` when the connected peer has no pathname address
/// (an abstract/unnamed socket, which the servo never binds),
/// `Unavailable` when the peer path cannot be resolved, and
/// `Unauthenticated` when the post-connect identity differs from `expected`.
#[cfg(unix)]
pub fn verify_connected_endpoint(
    stream: &std::os::unix::net::UnixStream,
    expected: SocketEndpointIdentity,
) -> Result<(), IpcError> {
    use std::os::unix::fs::MetadataExt;

    let peer = stream.peer_addr().map_err(|err| IpcError::Unavailable {
        reason: format!("cannot read connected peer address: {err}"),
    })?;
    let Some(path) = peer.as_pathname() else {
        return Err(IpcError::Unauthenticated {
            reason: "connected peer has no filesystem socket address (refusing to send)".into(),
        });
    };
    if path.as_os_str().is_empty() {
        return Err(IpcError::Unauthenticated {
            reason: "connected peer address is empty (refusing to send)".into(),
        });
    }
    let meta = std::fs::symlink_metadata(path).map_err(|err| IpcError::Unavailable {
        reason: format!("cannot stat connected peer endpoint: {err}"),
    })?;
    if meta.file_type().is_symlink() {
        return Err(IpcError::Unauthenticated {
            reason: "connected peer endpoint is a symlink (refusing to send)".into(),
        });
    }
    let actual = SocketEndpointIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
        uid: meta.uid(),
        mode: meta.mode() & 0o777,
    };
    if actual != expected {
        return Err(IpcError::Unauthenticated {
            reason: "connected peer endpoint changed after verification (refusing to send)".into(),
        });
    }
    Ok(())
}

/// Non-unix stub: `SocketEndpointIdentity` never exists off unix.
#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketEndpointIdentity {
    /// Placeholder device id (never produced on this platform).
    pub dev: u64,
    /// Placeholder inode (never produced on this platform).
    pub ino: u64,
    /// Placeholder owner uid (never produced on this platform).
    pub uid: u32,
    /// Placeholder mode (never produced on this platform).
    pub mode: u32,
}

/// Non-unix stub for [`verify_connected_endpoint`](fn.verify_connected_endpoint).
///
/// Generic over the stream type because the unix `UnixStream` does not exist
/// on this platform; no client can reach it (the non-unix `ctl_roundtrip`
/// returns unavailable first).
#[cfg(not(unix))]
pub fn verify_connected_endpoint<T>(
    _stream: &T,
    _expected: SocketEndpointIdentity,
) -> Result<(), IpcError> {
    Err(IpcError::Unavailable {
        reason: "unix socket serving requires a unix platform".into(),
    })
}

/// Non-unix stub: socket-directory serving requires a unix platform.
#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirAttestation {
    /// Placeholder owner (never produced on this platform).
    pub dir_uid: u32,
    /// Placeholder mode (never produced on this platform).
    pub dir_mode: u32,
}

/// Non-unix stub for [`prepare_socket_dir`](fn.prepare_socket_dir).
#[cfg(not(unix))]
pub fn prepare_socket_dir(_socket_path: &str) -> Result<DirAttestation, IpcError> {
    Err(IpcError::Unavailable {
        reason: "unix socket serving requires a unix platform".into(),
    })
}

/// Non-unix stub for [`attest_bound_socket`](fn.attest_bound_socket).
#[cfg(not(unix))]
pub fn attest_bound_socket(_socket_path: &str, _dir: &DirAttestation) -> Result<u32, IpcError> {
    Err(IpcError::Unavailable {
        reason: "unix socket serving requires a unix platform".into(),
    })
}

/// Non-unix stub for [`verify_socket_endpoint_for_connect`](fn.verify_socket_endpoint_for_connect).
#[cfg(not(unix))]
pub fn verify_socket_endpoint_for_connect(
    _socket_path: &str,
    _runtime_uid: u32,
) -> Result<SocketEndpointIdentity, IpcError> {
    Err(IpcError::Unavailable {
        reason: "unix socket serving requires a unix platform".into(),
    })
}

// ── connection serving ──────────────────────────────────────────────────────

/// Per-connection counters for observability and tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConnectionStats {
    /// Requests read from the peer.
    pub requests: u64,
    /// Responses written to the peer.
    pub responses: u64,
    /// Responses carrying `error` (validation, dispatch, or rate limit).
    pub denied: u64,
    /// Framing violations that closed the connection.
    pub framing_errors: u64,
}

/// Serve one bound Unix connection until EOF, idle timeout, or fatal error.
#[cfg(unix)]
pub fn serve_bound_connection(
    stream: &mut std::os::unix::net::UnixStream,
    proof: &ConnectedPeerProof,
    dispatcher: &Dispatcher,
    context: &ServeContext,
    limiter: &mut RateLimiter,
    clock_ms: &dyn Fn() -> u64,
) -> Result<ConnectionStats, IpcError> {
    serve_bound_connection_with_identity(
        stream,
        proof,
        dispatcher,
        context,
        limiter,
        clock_ms,
        crate::peer::stream_identity,
    )
}

#[cfg(unix)]
fn serve_bound_connection_with_identity<F>(
    stream: &mut std::os::unix::net::UnixStream,
    proof: &ConnectedPeerProof,
    dispatcher: &Dispatcher,
    context: &ServeContext,
    limiter: &mut RateLimiter,
    clock_ms: &dyn Fn() -> u64,
    stream_identity: F,
) -> Result<ConnectionStats, IpcError>
where
    F: FnOnce(&std::os::unix::net::UnixStream) -> Result<StreamIdentity, IpcError>,
{
    if !proof.matches_stream_with(stream, stream_identity)? {
        return Err(IpcError::Unauthenticated {
            reason: "connected peer proof does not match the accepted stream".into(),
        });
    }
    context.recheck_before_read(proof)?;
    serve_connection_with_limiter(stream, dispatcher, context, limiter, clock_ms)
}

#[cfg(all(test, unix))]
pub(crate) fn serve_bound_connection_with_test_identity<F>(
    stream: &mut std::os::unix::net::UnixStream,
    proof: &ConnectedPeerProof,
    dispatcher: &Dispatcher,
    context: &ServeContext,
    limiter: &mut RateLimiter,
    clock_ms: &dyn Fn() -> u64,
    stream_identity: F,
) -> Result<ConnectionStats, IpcError>
where
    F: FnOnce(&std::os::unix::net::UnixStream) -> Result<StreamIdentity, IpcError>,
{
    serve_bound_connection_with_identity(
        stream,
        proof,
        dispatcher,
        context,
        limiter,
        clock_ms,
        stream_identity,
    )
}

/// Serve a generic test stream with an already checked context.
///
/// Production callers use [`serve_bound_connection`], which additionally
/// proves that the stream is the descriptor captured by the verifier.
#[cfg(all(test, unix))]
pub(crate) fn serve_connection<S>(
    stream: &mut S,
    peer: VerifiedPeer,
    dispatcher: &Dispatcher,
    context: &ServeContext,
    limiter: &mut RateLimiter,
    clock_ms: &dyn Fn() -> u64,
) -> Result<ConnectionStats, IpcError>
where
    S: ServeStream,
{
    context.recheck_connection(Some(&peer))?;
    serve_connection_with_limiter(stream, dispatcher, context, limiter, clock_ms)
}

/// Serve a generic stream under a single caller-supplied per-connection budget.
///
/// Thin adapter over [`serve_connection_inner`]: keeps CTX-0768's
/// `&mut RateLimiter` entry point intact for the callers that already own a
/// per-connection limiter, without duplicating the request loop.
#[cfg(unix)]
fn serve_connection_with_limiter<S>(
    stream: &mut S,
    dispatcher: &Dispatcher,
    context: &ServeContext,
    limiter: &mut RateLimiter,
    clock_ms: &dyn Fn() -> u64,
) -> Result<ConnectionStats, IpcError>
where
    S: ServeStream,
{
    serve_connection_inner(stream, dispatcher, context, clock_ms, |now| {
        limiter.check(now)
    })
}

/// Endpoint-wide RC-9 admission shared by every connection (CTX-0792, #1404).
///
/// One token bucket per listener at the accepted RC-9 figures (100 req/s
/// sustained, 200 burst), so the aggregate request rate is bounded no matter
/// how many connections a peer opens, while a single conforming client still
/// gets the full documented budget.
///
/// A poisoned endpoint lock is recovered with `PoisonError::into_inner` — the
/// pattern used by every other shared lock in this crate — instead of denying
/// IPC traffic for the rest of the process. Recovery is bounded: the inner
/// value is a token bucket whose timestamp window is evicted per check
/// ([`crate::limits::RateLimiter`]), so a recovered limiter cannot grow and
/// keeps enforcing the remaining budget.
#[cfg(unix)]
fn endpoint_admit(
    endpoint: &Arc<Mutex<RateLimiter>>,
) -> impl FnMut(u64) -> Result<(), IpcError> + '_ {
    move |now| {
        endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .check(now)
    }
}

/// Serve one bound Unix connection under the shared endpoint budget, with
/// peer proof.
///
/// This is the **production** accept-path entry point (CTX-0768 peer proof +
/// CTX-0792 endpoint budget, #1404). It keeps the whole CTX-0768 preamble
/// before a single byte is served:
///
/// 1. the [`ConnectedPeerProof`] must match the accepted stream's
///    dev/ino identity, so a proof captured from one descriptor cannot be
///    replayed onto another;
/// 2. [`ServeContext::recheck_before_read`] re-verifies the live peer against
///    the bound identity, so a peer that changed after accept is refused.
///
/// Only then does it admit requests through [`endpoint_admit`]. Peer proof
/// and rate admission are independent controls: neither substitutes for the
/// other, and this function refuses before either is consulted if the proof
/// does not hold.
#[cfg(unix)]
pub fn serve_bound_connection_with_endpoint_budget(
    stream: &mut std::os::unix::net::UnixStream,
    proof: &ConnectedPeerProof,
    dispatcher: &Dispatcher,
    context: &ServeContext,
    endpoint_limiter: &Arc<Mutex<RateLimiter>>,
    clock_ms: &dyn Fn() -> u64,
) -> Result<ConnectionStats, IpcError> {
    if !proof.matches_stream_with(stream, crate::peer::stream_identity)? {
        return Err(IpcError::Unauthenticated {
            reason: "connected peer proof does not match the accepted stream".into(),
        });
    }
    context.recheck_before_read(proof)?;
    serve_connection_inner(
        stream,
        dispatcher,
        context,
        clock_ms,
        endpoint_admit(endpoint_limiter),
    )
}

/// Hermetic generic-stream variant of
/// [`serve_bound_connection_with_endpoint_budget`] (tests only).
///
/// It has no accepted stream to match a proof against, so it rechecks the
/// supplied [`VerifiedPeer`] against the context instead, exactly like the
/// test-only generic `serve_connection`.
#[cfg(all(test, unix))]
pub(crate) fn serve_connection_with_shared_limiter<S>(
    stream: &mut S,
    peer: VerifiedPeer,
    dispatcher: &Dispatcher,
    context: &ServeContext,
    endpoint_limiter: &Arc<Mutex<RateLimiter>>,
    clock_ms: &dyn Fn() -> u64,
) -> Result<ConnectionStats, IpcError>
where
    S: ServeStream,
{
    context.recheck_connection(Some(&peer))?;
    serve_connection_inner(
        stream,
        dispatcher,
        context,
        clock_ms,
        endpoint_admit(endpoint_limiter),
    )
}

#[cfg(all(test, unix))]
impl Dispatcher {
    pub(crate) fn serve_connection_with_shared_limiter<S>(
        &self,
        stream: &mut S,
        peer: VerifiedPeer,
        context: &ServeContext,
        limiter: &Arc<Mutex<RateLimiter>>,
        clock_ms: &dyn Fn() -> u64,
    ) -> Result<ConnectionStats, IpcError>
    where
        S: ServeStream,
    {
        serve_connection_with_shared_limiter(stream, peer, self, context, limiter, clock_ms)
    }
}

#[cfg(unix)]
fn serve_connection_inner<S, F>(
    stream: &mut S,
    dispatcher: &Dispatcher,
    context: &ServeContext,
    clock_ms: &dyn Fn() -> u64,
    mut admit: F,
) -> Result<ConnectionStats, IpcError>
where
    S: ServeStream,
    F: FnMut(u64) -> Result<(), IpcError>,
{
    let mut stats = ConnectionStats::default();
    // Amendment A4 (#1482): at most one open continuation reassembly per
    // connection. Fragments are buffered here and never parsed, admitted, or
    // dispatched until the logical request is complete; every violation
    // replies once with `id` 0 and closes, so a partial request has no side
    // effect. EOF mid-reassembly closes silently, and a stalled stream is
    // reported as `ContinuationTimeout` when the read times out. While a
    // reassembly is open every read is bounded by the remaining 5 s
    // deadline (not just the 60 s idle timeout), so a peer dripping a
    // fragment byte by byte cannot hold the connection slot past it.
    let mut reassembler = Reassembler::new();
    let mut arming = ReadArming::new(stream);
    loop {
        let mut first = [0u8; 1];
        let read = arming
            .arm(stream, &reassembler, clock_ms)
            .and_then(|()| stream.read(&mut first));
        match read {
            Ok(0) => return Ok(stats),
            Ok(_) => {}
            Err(err)
                if err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock =>
            {
                if report_stalled_continuation(stream, &mut reassembler, clock_ms) {
                    stats.framing_errors += 1;
                }
                return Ok(stats);
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => {
                return Err(IpcError::Transport {
                    reason: format!("connection header read failed: {err}"),
                });
            }
        }
        let mut rest = [0u8; 3];
        if let Err(err) = read_exact_armed(stream, &mut rest, &mut arming, &reassembler, clock_ms) {
            stats.framing_errors += 1;
            if is_read_timeout(&err) {
                report_stalled_continuation(stream, &mut reassembler, clock_ms);
            }
            return Ok(stats);
        }
        let len = u32::from_be_bytes([first[0], rest[0], rest[1], rest[2]]) as usize;
        if len > MAX_FRAME_BYTES {
            stats.framing_errors += 1;
            let response = id_zero_error(
                "transport",
                "FrameTooLarge",
                &format!("frame {len} exceeds limit {MAX_FRAME_BYTES}"),
            );
            if write_framed(stream, &response).is_err() {
                return Ok(stats);
            }
            return Ok(stats);
        }
        let mut payload = vec![0u8; len];
        match read_exact_armed(stream, &mut payload, &mut arming, &reassembler, clock_ms) {
            Ok(()) => {}
            Err(err)
                if err.kind() == std::io::ErrorKind::UnexpectedEof || is_read_timeout(&err) =>
            {
                stats.framing_errors += 1;
                if is_read_timeout(&err) {
                    report_stalled_continuation(stream, &mut reassembler, clock_ms);
                }
                return Ok(stats);
            }
            Err(err) => {
                return Err(IpcError::Transport {
                    reason: format!("connection payload read failed: {err}"),
                });
            }
        }
        let payload = match reassembler.accept(payload, clock_ms()) {
            Ok(Accepted::Request(request)) => request,
            Ok(Accepted::Pending) => continue,
            Err(err) => {
                stats.framing_errors += 1;
                let response = id_zero_error("transport", err.code(), &err.message());
                let _ = write_framed(stream, &response);
                return Ok(stats);
            }
        };
        stats.requests += 1;
        if admit(clock_ms()).is_err() {
            stats.denied += 1;
            let id = match parse_request(&payload) {
                Ok(request) => request.id_raw,
                Err(_) => "0".to_string(),
            };
            let response = encode_error(
                &id,
                "budget",
                "RateLimited",
                "rate limited: RC-9 burst exceeded",
            );
            if write_framed(stream, &response).is_err() {
                return Err(IpcError::Transport {
                    reason: "connection response write failed".into(),
                });
            }
            stats.responses += 1;
            continue;
        }
        let outcome = handle_envelope(&payload, dispatcher, context);
        if outcome.was_error {
            stats.denied += 1;
        }
        if write_framed(stream, &outcome.response).is_err() {
            return Err(IpcError::Transport {
                reason: "connection response write failed".into(),
            });
        }
        stats.responses += 1;
        if outcome.close_connection {
            return Err(IpcError::Unauthenticated {
                reason: "connected peer recheck failed".into(),
            });
        }
    }
}

/// A served stream whose read timeout the loop can set per read.
///
/// Amendment A4 (#1482): while a continuation reassembly is open, each read
/// waits at most the time left before the continuation deadline.
#[cfg(unix)]
pub(crate) trait ServeStream: Read + Write {
    /// The read timeout configured by the accept path (the idle timeout).
    fn current_read_timeout(&self) -> std::io::Result<Option<std::time::Duration>>;
    /// Replace the read timeout for the next read.
    fn set_next_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()>;
}

#[cfg(unix)]
impl ServeStream for std::os::unix::net::UnixStream {
    fn current_read_timeout(&self) -> std::io::Result<Option<std::time::Duration>> {
        self.read_timeout()
    }

    fn set_next_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        self.set_read_timeout(timeout)
    }
}

/// Per-read timeout state of one served connection.
///
/// With no reassembly open, reads use the idle timeout the accept path
/// configured. While one is open, each read waits at most the time left
/// before the continuation deadline (never longer than the idle timeout),
/// and a read that would start after the deadline fails as `TimedOut`. The
/// socket option is only rewritten when the wanted value changes.
#[cfg(unix)]
struct ReadArming {
    idle: Option<std::time::Duration>,
    armed: Option<std::time::Duration>,
}

#[cfg(unix)]
impl ReadArming {
    fn new<S: ServeStream>(stream: &S) -> Self {
        let idle = stream.current_read_timeout().ok().flatten();
        Self { idle, armed: idle }
    }

    fn arm<S: ServeStream>(
        &mut self,
        stream: &S,
        reassembler: &Reassembler,
        clock_ms: &dyn Fn() -> u64,
    ) -> std::io::Result<()> {
        let want = match reassembler.deadline_ms() {
            None => self.idle,
            Some(deadline) => {
                let now = clock_ms();
                if now > deadline {
                    return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
                }
                // `set_read_timeout` rejects a zero duration; the deadline
                // itself is still honored by the `now > deadline` check.
                let left = std::time::Duration::from_millis((deadline - now).max(1));
                Some(self.idle.map_or(left, |idle| idle.min(left)))
            }
        };
        if want != self.armed {
            stream.set_next_read_timeout(want)?;
            self.armed = want;
        }
        Ok(())
    }
}

/// `read_exact` that re-arms the read timeout before every underlying read.
///
/// A plain `read_exact` would let each partial read wait the full timeout
/// again, so a slow drip could stretch one frame far past the deadline.
#[cfg(unix)]
fn read_exact_armed<S: ServeStream>(
    stream: &mut S,
    buf: &mut [u8],
    arming: &mut ReadArming,
    reassembler: &Reassembler,
    clock_ms: &dyn Fn() -> u64,
) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        arming.arm(stream, reassembler, clock_ms)?;
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => filled += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Whether a read failed because the stream stalled (socket read timeout).
#[cfg(unix)]
fn is_read_timeout(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

/// Discard a stalled continuation reassembly and report it once.
///
/// Returns `true` when a reassembly was open: its buffer is dropped without
/// dispatch and the peer receives one `ContinuationTimeout` error with `id` 0
/// (best effort; the connection closes either way). Returns `false` for an
/// ordinary idle timeout with nothing buffered.
#[cfg(unix)]
fn report_stalled_continuation<S>(
    stream: &mut S,
    reassembler: &mut Reassembler,
    clock_ms: &dyn Fn() -> u64,
) -> bool
where
    S: Read + Write,
{
    let Some(err) = reassembler.stalled(clock_ms()) else {
        return false;
    };
    let response = id_zero_error("transport", err.code(), &err.message());
    let _ = write_framed(stream, &response);
    true
}

/// Frame and write one response payload.
#[cfg(unix)]
fn write_framed<S>(stream: &mut S, response: &[u8]) -> std::io::Result<()>
where
    S: Read + Write,
{
    let wire = encode_frame(response).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "response exceeds frame bound",
        )
    })?;
    stream.write_all(&wire)?;
    stream.flush()
}

/// Test-only endpoint precondition fixture.
///
/// This checks filesystem owner, mode, and symlink state only; it is not
/// accepted-stream peer proof and is not compiled into production builds.
/// Live serving requires [`ServeContext::bind_connected_stream`] and fails
/// closed when no platform verifier is available.
#[cfg(all(test, unix))]
pub(crate) fn transport_attested_peer(
    socket_path: &str,
    runtime_uid: u32,
) -> Result<VerifiedPeer, IpcError> {
    verify_socket_endpoint_for_connect(socket_path, runtime_uid)?;
    let sock_uid = {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(socket_path)
            .map(|m| m.uid())
            .map_err(|err| IpcError::Unavailable {
                reason: format!("cannot stat socket {socket_path}: {err}"),
            })?
    };
    let sock_gid = {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(socket_path)
            .map(|m| m.gid())
            .map_err(|err| IpcError::Unavailable {
                reason: format!("cannot stat socket {socket_path}: {err}"),
            })?
    };
    verify_peer_uid(PeerCredentials::new(sock_uid, sock_gid, 0), runtime_uid)?;
    VerifiedPeer::attested(PeerCredentials::new(sock_uid, sock_gid, 0), runtime_uid)
}

/// Maximum concurrent connections served (`RC-9`, shed newest).
#[must_use]
pub const fn max_connections() -> usize {
    RC9_MAX_CONNECTIONS
}
