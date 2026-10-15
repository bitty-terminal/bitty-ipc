//! IPC scopes and per-request authorization (RFC OQ-018).
//!
//! Scopes are evaluated **server-side on every request from the authenticated
//! identity**; clients never assert scopes. Possession of a socket or pipe
//! handle grants no authority beyond the ability to present a request for
//! evaluation. Each method declares a required scope; if the caller lacks it,
//! the request is denied with `Denied/ScopeViolation` and no partial state is
//! created (FS-IP1).
//!
//! Families per the accepted RFC:
//! - `terminal`: `terminal.inspect` < `terminal.input` < `terminal.manage`
//! - `view`: `view.inspect` < `view.manage`
//! - `config`: `config.inspect` < `config.modify`
//! - `plugin`: `plugin.inspect` < `plugin.manage`
//! - `process`: `process.spawn` (always separate)
//! - `debug`: `debug.inspect` < `debug.trace` < `debug.control`
//! - `ai`: `ai.inspect` < `ai.invoke` (batch 2, wiring items 1+7; S2 envelope
//!   ops ride `params`/`result` under one `ai.` method namespace)
//!
//! Notes from RFC:
//! - `terminal.inspect` never implies `terminal.input`; `terminal.input` never
//!   implies `terminal.manage` (independent, no ambient escalation).
//! - `debug` scopes are fully distinct from IPC scopes until explicit elevation.
//! - All scopes are independent — a higher scope does not automatically grant a
//!   lower one; elevation is **per-client, per-scope, and ledgered**.
//! - MCP/Agent clients start read-only; `terminal.input/manage`,
//!   `config.modify`, `plugin.manage`, `process.spawn`, `debug.trace/control`
//!   each require separate consent (no bundled admin).
//!
//! This module is pure data, bounded, headless, and `forbid(unsafe)`.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use crate::error::IpcError;

// ── Scope definition ────────────────────────────────────────────────────────

/// Accepted v1 scope families (15 scopes). Exact names are versioned with the
/// wire as accepted per the IPC RFC; changing a name requires an RFC revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// `terminal.inspect` — read-only terminal inspection (list, text).
    TerminalInspect,
    /// `terminal.input` — send input to a terminal.
    TerminalInput,
    /// `terminal.manage` — close, spawn, manage terminals.
    TerminalManage,
    /// `view.inspect` — list views.
    ViewInspect,
    /// `view.manage` — split, focus, manage views.
    ViewManage,
    /// `config.inspect` — show config.
    ConfigInspect,
    /// `config.modify` — reload/modify config.
    ConfigModify,
    /// `plugin.inspect` — list plugins.
    PluginInspect,
    /// `plugin.manage` — install/disable plugins.
    PluginManage,
    /// `process.spawn` — spawn with executable allowlist (always separate).
    ProcessSpawn,
    /// `debug.inspect` — snapshot, read-only debug.
    DebugInspect,
    /// `debug.trace` — start trace.
    DebugTrace,
    /// `debug.control` — breakpoint, control.
    DebugControl,
    /// `ai.inspect` — read-only AI ops: model catalog listing, routing-only
    /// model selection, agent-context reads, extension manifest declaration
    /// echoes, activation queries, cache presence hints, MCP pin checks,
    /// MCP snapshot (digest) queries.
    ///
    /// // POLICY (CTX-0006): new scope, not a reuse. No existing scope
    /// expresses AI-op semantics: the six RFC families each govern a
    /// distinct authority domain (terminal text, views, config, plugins,
    /// process spawning, debug transport), and forcing AI ops into any of
    /// them would silently extend that scope's grant to a new domain
    /// (consent downgrade). The inspect/invoke split mirrors the existing
    /// inspect/manage family pattern without bending the hierarchy.
    AiInspect,
    /// `ai.invoke` — effectful AI ops: provider completion (inference
    /// execution against a model reference, spending budget) and tool
    /// dispatch (executing a tool with filesystem/network authority).
    ///
    /// // POLICY (CTX-0006): new scope, not a reuse. `process.spawn` (always
    /// separate, executable-allowlist spawning) does not express model
    /// invocation or tool-bus dispatch; mapping either op there would
    /// silently grant it to every `process.spawn` holder. Kept separate so
    /// read-only AI inspection never implies execution.
    AiInvoke,
}

impl Scope {
    /// Canonical string representation (wire-stable).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TerminalInspect => "terminal.inspect",
            Self::TerminalInput => "terminal.input",
            Self::TerminalManage => "terminal.manage",
            Self::ViewInspect => "view.inspect",
            Self::ViewManage => "view.manage",
            Self::ConfigInspect => "config.inspect",
            Self::ConfigModify => "config.modify",
            Self::PluginInspect => "plugin.inspect",
            Self::PluginManage => "plugin.manage",
            Self::ProcessSpawn => "process.spawn",
            Self::DebugInspect => "debug.inspect",
            Self::DebugTrace => "debug.trace",
            Self::DebugControl => "debug.control",
            Self::AiInspect => "ai.inspect",
            Self::AiInvoke => "ai.invoke",
        }
    }

    /// Family prefix (e.g. `terminal`, `view`).
    #[must_use]
    pub fn family(self) -> &'static str {
        match self {
            Self::TerminalInspect | Self::TerminalInput | Self::TerminalManage => "terminal",
            Self::ViewInspect | Self::ViewManage => "view",
            Self::ConfigInspect | Self::ConfigModify => "config",
            Self::PluginInspect | Self::PluginManage => "plugin",
            Self::ProcessSpawn => "process",
            Self::DebugInspect | Self::DebugTrace | Self::DebugControl => "debug",
            Self::AiInspect | Self::AiInvoke => "ai",
        }
    }

    /// All 15 scopes in a deterministic order.
    #[must_use]
    pub fn all() -> &'static [Scope] {
        &[
            Self::TerminalInspect,
            Self::TerminalInput,
            Self::TerminalManage,
            Self::ViewInspect,
            Self::ViewManage,
            Self::ConfigInspect,
            Self::ConfigModify,
            Self::PluginInspect,
            Self::PluginManage,
            Self::ProcessSpawn,
            Self::DebugInspect,
            Self::DebugTrace,
            Self::DebugControl,
            Self::AiInspect,
            Self::AiInvoke,
        ]
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Scope {
    type Err = IpcError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "terminal.inspect" => Ok(Self::TerminalInspect),
            "terminal.input" => Ok(Self::TerminalInput),
            "terminal.manage" => Ok(Self::TerminalManage),
            "view.inspect" => Ok(Self::ViewInspect),
            "view.manage" => Ok(Self::ViewManage),
            "config.inspect" => Ok(Self::ConfigInspect),
            "config.modify" => Ok(Self::ConfigModify),
            "plugin.inspect" => Ok(Self::PluginInspect),
            "plugin.manage" => Ok(Self::PluginManage),
            "process.spawn" => Ok(Self::ProcessSpawn),
            "debug.inspect" => Ok(Self::DebugInspect),
            "debug.trace" => Ok(Self::DebugTrace),
            "debug.control" => Ok(Self::DebugControl),
            "ai.inspect" => Ok(Self::AiInspect),
            "ai.invoke" => Ok(Self::AiInvoke),
            _ => Err(IpcError::InvalidRequest {
                reason: format!("unknown scope '{s}'"),
            }),
        }
    }
}

// ── ScopeSet ────────────────────────────────────────────────────────────────

/// Bounded set of granted scopes for one authenticated client.
///
/// The set is owned, bounded (at most 15 entries), and headlessly testable.
/// It never grows beyond the defined families. Cloning is cheap (small BTreeSet).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeSet {
    inner: BTreeSet<Scope>,
}

impl ScopeSet {
    /// Empty set (no authority).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: BTreeSet::new(),
        }
    }

    /// Set with exactly `scope`.
    #[must_use]
    pub fn single(scope: Scope) -> Self {
        let mut s = Self::new();
        s.insert(scope);
        s
    }

    /// Insert a scope (idempotent).
    pub fn insert(&mut self, scope: Scope) {
        self.inner.insert(scope);
    }

    /// Remove a scope; returns true if it was present.
    pub fn remove(&mut self, scope: Scope) -> bool {
        self.inner.remove(&scope)
    }

    /// Whether this set contains `scope`.
    #[must_use]
    pub fn contains(&self, scope: Scope) -> bool {
        self.inner.contains(&scope)
    }

    /// Whether all scopes in `other` are present.
    #[must_use]
    pub fn contains_all(&self, other: &Self) -> bool {
        other.inner.iter().all(|s| self.inner.contains(s))
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Number of granted scopes (0..=15).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Iterate scopes in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = &Scope> {
        self.inner.iter()
    }

    /// All scopes as a sorted vec.
    #[must_use]
    pub fn to_vec(&self) -> Vec<Scope> {
        self.inner.iter().copied().collect()
    }

    /// CLI interactive user default (union per RFC):
    /// `terminal.inspect`, `terminal.input`, `view.inspect`, `view.manage`,
    /// `config.inspect`, `plugin.inspect` (6). `terminal.manage`,
    /// `config.modify`, `plugin.manage`, `process.spawn`, all `debug`, and
    /// all `ai` require explicit elevation.
    ///
    /// // POLICY (CTX-0006): `ai.inspect`/`ai.invoke` are excluded from the
    /// CLI default (deny-by-default survives for every AI op). CLI callers
    /// reach AI methods only through an explicit ledgered elevation grant,
    /// never ambiently.
    #[must_use]
    pub fn cli_default() -> Self {
        let mut s = Self::new();
        s.insert(Scope::TerminalInspect);
        s.insert(Scope::TerminalInput);
        s.insert(Scope::ViewInspect);
        s.insert(Scope::ViewManage);
        s.insert(Scope::ConfigInspect);
        s.insert(Scope::PluginInspect);
        s
    }

    /// MCP/Agent read-only default (4 + optional `debug.inspect`):
    /// `terminal.inspect`, `view.inspect`, `config.inspect`, `plugin.inspect`
    /// plus `debug.inspect` only if explicitly presented. This method returns
    /// the base 4; callers add `debug.inspect` if client presented it.
    ///
    /// // POLICY (CTX-0006): `ai.inspect`/`ai.invoke` are excluded from the
    /// MCP default as well (deny-by-default survives for every AI op, on
    /// both profiles). A fresh `(UID, AgentId)` reads snapshots and lists
    /// resources through the existing read scopes only; every `ai.*` method
    /// needs a separate per-client consent grant (RFC consent items 1-2).
    #[must_use]
    pub fn mcp_default() -> Self {
        let mut s = Self::new();
        s.insert(Scope::TerminalInspect);
        s.insert(Scope::ViewInspect);
        s.insert(Scope::ConfigInspect);
        s.insert(Scope::PluginInspect);
        s
    }

    /// MCP read-only plus `debug.inspect` (when client explicitly requests it).
    #[must_use]
    pub fn mcp_default_with_debug_inspect() -> Self {
        let mut s = Self::mcp_default();
        s.insert(Scope::DebugInspect);
        s
    }

    /// All scopes (admin, for tests — never granted silently per RFC).
    #[must_use]
    pub fn all() -> Self {
        let mut s = Self::new();
        for &scope in Scope::all() {
            s.insert(scope);
        }
        s
    }

    /// Whether `scope` requires explicit elevation beyond CLI default.
    #[must_use]
    pub fn requires_elevation(scope: Scope) -> bool {
        !Self::cli_default().contains(scope)
    }

    /// Whether `scope` requires explicit elevation beyond MCP read-only default.
    #[must_use]
    pub fn requires_mcp_elevation(scope: Scope) -> bool {
        !Self::mcp_default().contains(scope)
    }
}

impl fmt::Display for ScopeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let list: Vec<&str> = self.inner.iter().map(|s| s.as_str()).collect();
        write!(f, "[{}]", list.join(", "))
    }
}

// ── Method validation (RFC wire) ────────────────────────────────────────────

/// Validate a method name per RFC wire envelope.
///
/// Rules (accepted):
/// - `v` must be 1 (checked elsewhere), but method validation here is
///   independent.
/// - `method` non-empty, `<= 128` bytes, no control bytes (`0x00..0x1F`, `0x7F`),
///   no interior whitespace, segments match `^[a-z][a-z0-9_]*$` separated by `.`;
///   e.g. `terminal.text` is valid, `terminal..text` is not.
/// - Untrusted method strings never reach dispatch without this check.
pub fn validate_method_name(method: &str) -> Result<(), IpcError> {
    if method.is_empty() {
        return Err(IpcError::InvalidMethod {
            method: method.to_string(),
            reason: "method must be non-empty".into(),
        });
    }
    if method.len() > crate::channel::MAX_METHOD_BYTES {
        return Err(IpcError::LimitExceeded {
            field: "method".into(),
            limit: crate::channel::MAX_METHOD_BYTES,
            actual: method.len(),
        });
    }
    if method.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(IpcError::InvalidMethod {
            method: method.to_string(),
            reason: "method must not contain control bytes".into(),
        });
    }
    if method
        .bytes()
        .any(|b| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r')
    {
        return Err(IpcError::InvalidMethod {
            method: method.to_string(),
            reason: "method must not contain whitespace".into(),
        });
    }
    // RFC segment grammar: ^[a-z][a-z0-9_]*$ per dot-separated segment.
    if method.starts_with('.') || method.ends_with('.') || method.contains("..") {
        return Err(IpcError::InvalidMethod {
            method: method.to_string(),
            reason: "method must not have empty segment (no leading/trailing/double dot)".into(),
        });
    }
    for seg in method.split('.') {
        if seg.is_empty() {
            return Err(IpcError::InvalidMethod {
                method: method.to_string(),
                reason: "method segment must be non-empty".into(),
            });
        }
        let mut chars = seg.bytes();
        let first = chars.next().unwrap();
        if !first.is_ascii_lowercase() {
            return Err(IpcError::InvalidMethod {
                method: method.to_string(),
                reason: "method segment must start with [a-z]".into(),
            });
        }
        for b in chars {
            let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_';
            if !ok {
                return Err(IpcError::InvalidMethod {
                    method: method.to_string(),
                    reason: "method segment must match ^[a-z][a-z0-9_]*$".into(),
                });
            }
        }
    }
    Ok(())
}

// ── Method -> required scope ────────────────────────────────────────────────

/// Map an IPC method to its required scope.
///
/// Returns `None` when the method is not in the known registry (unknown method
/// -> NotFound, not ambient authority). Callers must deny such methods with
/// `NotFound` without side effects (FS-IP1 transactional denial).
#[must_use]
pub fn required_scope_for_method(method: &str) -> Option<Scope> {
    match method {
        // terminal
        "terminal.list" | "terminal.text" | "terminal.get_text" | "terminal.snapshot" => {
            Some(Scope::TerminalInspect)
        }
        "terminal.send" | "terminal.input" | "terminal.write" => Some(Scope::TerminalInput),
        "terminal.close" | "terminal.spawn" | "terminal.kill" | "terminal.manage" => {
            Some(Scope::TerminalManage)
        }
        // view
        "view.list" => Some(Scope::ViewInspect),
        "view.split" | "view.focus" | "view.close" | "view.create" | "view.manage" => {
            Some(Scope::ViewManage)
        }
        // config
        "config.show" | "config.get" | "config.inspect" => Some(Scope::ConfigInspect),
        "config.reload" | "config.set" | "config.modify" => Some(Scope::ConfigModify),
        // plugin
        "plugin.list" | "plugin.get" => Some(Scope::PluginInspect),
        "plugin.install" | "plugin.disable" | "plugin.enable" | "plugin.remove" => {
            Some(Scope::PluginManage)
        }
        // process
        "process.spawn" => Some(Scope::ProcessSpawn),
        // debug
        "debug.snapshot" | "debug.inspect" | "debug.get" => Some(Scope::DebugInspect),
        "debug.start_trace" | "debug.trace" => Some(Scope::DebugTrace),
        "debug.break" | "debug.control" | "debug.pause" => Some(Scope::DebugControl),
        // ai — one method per S2 envelope request type (batch 2, items 1+7).
        // Read-only ops take `ai.inspect`; effectful ops take `ai.invoke`.
        // Neither scope is in any default set, so every arm below denies
        // until an explicit ledgered grant exists (deny-by-default).
        //
        // // POLICY (CTX-0006): per-method assignment rationale.
        // `ai.inspect` (read-only, no effects, no budget spend, no authority
        // exercised): provider catalog listing (`ListModelsRequest` carries
        // no filters; the reserved scoped variant is denied S2-side per
        // MP-4), routing-only model selection (detached snapshot chain, no
        // inference), pure fallback classification and pure cost arithmetic
        // over echoed inputs (total, no I/O either side could not do locally,
        // but routed here so every crossing envelope has a scoped method and
        // server-side attribution), scoped agent-context reads (untrusted
        // observation: must never auto-combine with dispatch, RFC consent
        // item 3), manifest/per-point declaration echoes (grant nothing),
        // the activation check-named query (question only, always denies
        // today under the S3 deny-all posture), cache presence-hint queries
        // (a hit never authorizes reuse; keys only, no values cross), and
        // the MCP pin/snapshot digest queries (data compare only).
        // `ai.invoke` (effectful): provider completion (inference execution
        // against a model reference: spends budget pre-I/O, consumes the
        // caller deadline, produces untrusted model output) and tool
        // dispatch (executes with filesystem/network authority via the host
        // bus; args cross digest-only; per-tool consent stays a host-side
        // execution gate on top of this method grant).
        "ai.provider_list"
        | "ai.model_select"
        | "ai.model_fallback"
        | "ai.model_cost"
        | "ai.context_read"
        | "ai.extension_manifest"
        | "ai.extension_contribute"
        | "ai.extension_activate"
        | "ai.cache_hint"
        | "ai.mcp_pin"
        | "ai.mcp_snapshot" => Some(Scope::AiInspect),
        "ai.provider_complete" | "ai.tool_dispatch" => Some(Scope::AiInvoke),
        _ => None,
    }
}

/// All methods in the generic IPC registry (51, wire-stable).
///
/// This is the single countable list backing [`required_scope_for_method`]:
/// every entry maps to `Some`, and every `Some` mapping has its method here.
/// Tests assert the two stay in sync so the scope×action matrix cannot
/// silently drift from the registry (R-011 closure).
///
/// // POLICY (CTX-0006): exactly one canonical name per S2 envelope request
/// type under the single `ai.` namespace — no aliases, no per-variant
/// fan-out (e.g. one `ai.extension_contribute` for all eight
/// `ContributionEnvelope` points; the point rides `params`). A future S-1
/// snapshot correlator lands as an optional `params`-JSON field, not a new
/// method, so this list does not change for it.
#[must_use]
pub fn all_known_methods() -> &'static [&'static str] {
    &[
        // terminal (11)
        "terminal.list",
        "terminal.text",
        "terminal.get_text",
        "terminal.snapshot",
        "terminal.send",
        "terminal.input",
        "terminal.write",
        "terminal.close",
        "terminal.spawn",
        "terminal.kill",
        "terminal.manage",
        // view (6)
        "view.list",
        "view.split",
        "view.focus",
        "view.close",
        "view.create",
        "view.manage",
        // config (6)
        "config.show",
        "config.get",
        "config.inspect",
        "config.reload",
        "config.set",
        "config.modify",
        // plugin (6)
        "plugin.list",
        "plugin.get",
        "plugin.install",
        "plugin.disable",
        "plugin.enable",
        "plugin.remove",
        // process (1)
        "process.spawn",
        // debug (8)
        "debug.snapshot",
        "debug.inspect",
        "debug.get",
        "debug.start_trace",
        "debug.trace",
        "debug.break",
        "debug.control",
        "debug.pause",
        // ai (13): one per S2 envelope request type (batch 2, items 1+7)
        "ai.provider_list",
        "ai.provider_complete",
        "ai.model_select",
        "ai.model_fallback",
        "ai.model_cost",
        "ai.tool_dispatch",
        "ai.context_read",
        "ai.extension_manifest",
        "ai.extension_contribute",
        "ai.extension_activate",
        "ai.cache_hint",
        "ai.mcp_pin",
        "ai.mcp_snapshot",
    ]
}

/// Check authorization server-side.
///
/// Denies with `ScopeDenied` (class `scope`) when the caller lacks the required
/// scope for `method`. Unknown methods are denied as `NotFound` (no partial
/// state, fail-closed). Clients cannot assert scopes — `granted` is the
/// server-evaluated set from the authenticated identity.
///
/// # Errors
///
/// - `ScopeDenied` when `method` is known but `granted` lacks the required scope.
/// - `NotFound` when `method` is not in the registry (or fails validation).
/// - `InvalidMethod` when `method` violates the wire grammar.
pub fn authorize_method(method: &str, granted: &ScopeSet) -> Result<Scope, IpcError> {
    validate_method_name(method)?;
    let required = required_scope_for_method(method).ok_or_else(|| IpcError::NotFound {
        reason: format!("unknown method '{method}'"),
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

// ── Consent ledger (per-client, per-scope, bounded) ────────────────────────

/// A single consent grant: per-client, per-scope, ledgered.
///
/// The runtime records which client identity, which scope, when, and for how
/// long, and surfaces it via `bitty ctl inspect consent`. Grants never
/// silently expand at update time; permission diff blocks silently-added
/// capabilities (R-016 parity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentGrant {
    /// Authenticated client identity (e.g. UID string or `owner.name` pair).
    pub client_id: String,
    /// Scope that was granted.
    pub scope: Scope,
    /// When the grant was made (deterministic `now_ms`).
    pub granted_at_ms: u64,
    /// Expiry (absolute `now_ms`); `u64::MAX` for no expiry (rare, tests).
    pub expires_at_ms: u64,
    /// Who granted it (user identity or `self` for auto-read-only).
    pub granted_by: String,
}

impl ConsentGrant {
    /// Whether `now_ms` is at or past expiry.
    #[must_use]
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }
}

/// Bounded per-client consent ledger.
///
/// Capacity `MAX_CONSENT_GRANTS = 64` (matches `MAX_PENDING_REQUESTS` scale).
/// Oldest entries are not auto-evicted — ledger is explicit: `grant` fails
/// when at capacity (fail-closed), `revoke` frees space. This keeps the
/// security posture deterministic and countable (FS-IP4 attribution).
///
/// Per-op AI consent gating (batch 2, item 7) flows through this ledger with
/// no new mechanism: `ai.inspect`/`ai.invoke` are in no default set, so the
/// first lawful use of any `ai.*` method is a `grant` for exactly one of
/// those scopes, and revocation/expiry returns the client to deny. The
/// per-method consent defaults (CLI vs MCP/Agent) are tabulated in
/// `docs/s2-wiring-batch2.md`; the ledger records `who, scope, granted_at,
/// expires_at, granted_by` per grant (RFC consent item 4).
#[derive(Debug, Default)]
pub struct ConsentLedger {
    grants: BTreeSet<(String, Scope)>,
    records: std::collections::BTreeMap<(String, Scope), ConsentGrant>,
}

impl ConsentLedger {
    /// Maximum number of distinct `(client_id, scope)` grants tracked.
    pub const MAX_GRANTS: usize = 64;

    /// Create an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of active grants.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Whether no grants are active.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Whether `(client_id, scope)` is currently granted and not expired at `now_ms`.
    #[must_use]
    pub fn is_granted(&self, client_id: &str, scope: Scope, now_ms: u64) -> bool {
        let key = (client_id.to_string(), scope);
        if let Some(rec) = self.records.get(&key) {
            !rec.is_expired(now_ms)
        } else {
            false
        }
    }

    /// Grant `scope` to `client_id` for `ttl_ms` (from `now_ms`). Ledgered.
    ///
    /// If the same `(client, scope)` already exists, it is refreshed (expiry
    /// extended, `granted_at` updated). If the ledger is at capacity for a new
    /// key, fails closed with `LimitExceeded` (no silent eviction).
    pub fn grant(
        &mut self,
        client_id: String,
        scope: Scope,
        now_ms: u64,
        ttl_ms: u64,
        granted_by: String,
    ) -> Result<(), IpcError> {
        let key = (client_id.clone(), scope);
        let is_new = !self.records.contains_key(&key);
        if is_new && self.grants.len() >= Self::MAX_GRANTS {
            return Err(IpcError::LimitExceeded {
                field: "consent_ledger".into(),
                limit: Self::MAX_GRANTS,
                actual: self.grants.len() + 1,
            });
        }
        let expires_at = now_ms.saturating_add(ttl_ms);
        let rec = ConsentGrant {
            client_id: client_id.clone(),
            scope,
            granted_at_ms: now_ms,
            expires_at_ms: expires_at,
            granted_by,
        };
        self.grants.insert(key.clone());
        self.records.insert(key, rec);
        Ok(())
    }

    /// Revoke `scope` from `client_id` immediately (survives restart in real
    /// runtime; here it is headless). Returns true if a grant was present.
    pub fn revoke(&mut self, client_id: &str, scope: Scope) -> bool {
        let key = (client_id.to_string(), scope);
        let existed = self.grants.remove(&key);
        self.records.remove(&key);
        existed
    }

    /// Drain grants whose expiry is at or past `now_ms`, returning the expired keys.
    pub fn drain_expired(&mut self, now_ms: u64) -> Vec<(String, Scope)> {
        let expired: Vec<(String, Scope)> = self
            .records
            .iter()
            .filter_map(|(k, rec)| {
                if rec.is_expired(now_ms) {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        for k in &expired {
            self.grants.remove(k);
            self.records.remove(k);
        }
        expired
    }

    /// Snapshot of active grants at `now_ms`.
    #[must_use]
    pub fn active_grants(&self, now_ms: u64) -> Vec<ConsentGrant> {
        self.records
            .values()
            .filter(|r| !r.is_expired(now_ms))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_parse_roundtrip() {
        for &s in Scope::all() {
            let parsed: Scope = s.as_str().parse().unwrap();
            assert_eq!(parsed, s);
        }
        assert!("unknown.scope".parse::<Scope>().is_err());
    }

    #[test]
    fn scope_set_defaults() {
        let cli = ScopeSet::cli_default();
        assert_eq!(cli.len(), 6);
        assert!(cli.contains(Scope::TerminalInspect));
        assert!(cli.contains(Scope::TerminalInput));
        assert!(!cli.contains(Scope::TerminalManage));
        assert!(!cli.contains(Scope::DebugControl));

        let mcp = ScopeSet::mcp_default();
        assert_eq!(mcp.len(), 4);
        assert!(mcp.contains(Scope::TerminalInspect));
        assert!(!mcp.contains(Scope::TerminalInput));
        assert!(!mcp.contains(Scope::DebugTrace));
    }

    #[test]
    fn method_validation_rfc() {
        assert!(validate_method_name("terminal.text").is_ok());
        assert!(validate_method_name("view.list").is_ok());
        assert!(validate_method_name("config.show").is_ok());
        assert!(validate_method_name("").is_err());
        assert!(validate_method_name("terminal..text").is_err());
        assert!(validate_method_name(".terminal").is_err());
        assert!(validate_method_name("terminal.").is_err());
        assert!(validate_method_name("Terminal.text").is_err());
        assert!(validate_method_name("terminal.123").is_err());
        assert!(validate_method_name("terminal .text").is_err());
        assert!(validate_method_name("terminal\ttext").is_err());
        assert!(validate_method_name("bad\x01method").is_err());
        let long = "a.".repeat(70);
        assert!(validate_method_name(&long).is_err());
    }

    #[test]
    fn required_scope_mapping() {
        assert_eq!(
            required_scope_for_method("terminal.text"),
            Some(Scope::TerminalInspect)
        );
        assert_eq!(
            required_scope_for_method("terminal.send"),
            Some(Scope::TerminalInput)
        );
        assert_eq!(
            required_scope_for_method("terminal.close"),
            Some(Scope::TerminalManage)
        );
        assert_eq!(
            required_scope_for_method("view.list"),
            Some(Scope::ViewInspect)
        );
        assert_eq!(
            required_scope_for_method("config.reload"),
            Some(Scope::ConfigModify)
        );
        assert_eq!(
            required_scope_for_method("process.spawn"),
            Some(Scope::ProcessSpawn)
        );
        assert_eq!(required_scope_for_method("unknown.method"), None);
    }

    #[test]
    fn authorize_allows_and_denies() {
        let cli = ScopeSet::cli_default();
        // Allowed: terminal.text needs inspect (granted)
        assert!(authorize_method("terminal.text", &cli).is_ok());
        // Denied: terminal.close needs manage (not granted to CLI default)
        let err = authorize_method("terminal.close", &cli).unwrap_err();
        assert!(matches!(err, IpcError::ScopeDenied { .. }));
        // Unknown method -> NotFound
        let err2 = authorize_method("unknown.method", &cli).unwrap_err();
        assert!(matches!(err2, IpcError::NotFound { .. }));
        // Invalid grammar -> InvalidMethod
        let err3 = authorize_method("bad..method", &cli).unwrap_err();
        assert!(matches!(err3, IpcError::InvalidMethod { .. }));
    }

    #[test]
    fn terminal_inspect_does_not_imply_input_or_manage() {
        let mut set = ScopeSet::new();
        set.insert(Scope::TerminalInspect);
        // Inspect alone must not grant input or manage
        assert!(authorize_method("terminal.text", &set).is_ok());
        assert!(authorize_method("terminal.send", &set).is_err());
        assert!(authorize_method("terminal.close", &set).is_err());

        let mut set2 = ScopeSet::new();
        set2.insert(Scope::TerminalInput);
        assert!(authorize_method("terminal.send", &set2).is_ok());
        assert!(authorize_method("terminal.text", &set2).is_err());
        assert!(authorize_method("terminal.close", &set2).is_err());
    }

    #[test]
    fn mcp_readonly_cannot_produce_effect() {
        let mcp = ScopeSet::mcp_default();
        // Read-only can inspect but not send input
        assert!(authorize_method("terminal.text", &mcp).is_ok());
        assert!(authorize_method("terminal.send", &mcp).is_err());
        assert!(authorize_method("config.reload", &mcp).is_err());
        assert!(authorize_method("plugin.install", &mcp).is_err());
        assert!(authorize_method("process.spawn", &mcp).is_err());
        assert!(authorize_method("debug.break", &mcp).is_err());
    }

    #[test]
    fn consent_ledger_grant_revoke_expiry() {
        let mut ledger = ConsentLedger::new();
        ledger
            .grant(
                "client1".into(),
                Scope::TerminalInput,
                0,
                1000,
                "user".into(),
            )
            .unwrap();
        assert!(ledger.is_granted("client1", Scope::TerminalInput, 500));
        assert!(!ledger.is_granted("client1", Scope::TerminalInput, 1000));
        assert!(!ledger.is_granted("client1", Scope::TerminalManage, 500));

        // Revoke before expiry
        ledger
            .grant(
                "client1".into(),
                Scope::TerminalManage,
                0,
                5000,
                "user".into(),
            )
            .unwrap();
        assert!(ledger.revoke("client1", Scope::TerminalManage));
        assert!(!ledger.is_granted("client1", Scope::TerminalManage, 100));

        // Drain expired
        ledger
            .grant("c2".into(), Scope::ViewManage, 0, 100, "user".into())
            .unwrap();
        let expired = ledger.drain_expired(100);
        assert_eq!(expired.len(), 1);
        assert!(!ledger.is_granted("c2", Scope::ViewManage, 100));
    }

    #[test]
    fn consent_ledger_cap_is_fail_closed() {
        let mut ledger = ConsentLedger::new();
        for i in 0..ConsentLedger::MAX_GRANTS {
            ledger
                .grant(
                    format!("client{i}"),
                    Scope::TerminalInspect,
                    0,
                    10000,
                    "user".into(),
                )
                .unwrap();
        }
        let err = ledger
            .grant(
                "overflow".into(),
                Scope::TerminalInspect,
                0,
                1000,
                "user".into(),
            )
            .unwrap_err();
        assert!(matches!(err, IpcError::LimitExceeded { .. }));
    }

    #[test]
    fn no_bundled_admin_scope() {
        // A single grant must not grant multiple scopes.
        let mut ledger = ConsentLedger::new();
        ledger
            .grant(
                "agent".into(),
                Scope::TerminalInput,
                0,
                10000,
                "user".into(),
            )
            .unwrap();
        // Other scopes still not granted
        assert!(!ledger.is_granted("agent", Scope::ConfigModify, 0));
        assert!(!ledger.is_granted("agent", Scope::PluginManage, 0));
        assert!(!ledger.is_granted("agent", Scope::ProcessSpawn, 0));
        assert!(!ledger.is_granted("agent", Scope::DebugControl, 0));
    }

    // ── Batch 2 (CTX-0006): ai.* registry, denial, consent, echo ──────────

    const AI_INSPECT_METHODS: &[&str] = &[
        "ai.provider_list",
        "ai.model_select",
        "ai.model_fallback",
        "ai.model_cost",
        "ai.context_read",
        "ai.extension_manifest",
        "ai.extension_contribute",
        "ai.extension_activate",
        "ai.cache_hint",
        "ai.mcp_pin",
        "ai.mcp_snapshot",
    ];

    const AI_INVOKE_METHODS: &[&str] = &["ai.provider_complete", "ai.tool_dispatch"];

    #[test]
    fn ai_registry_completeness() {
        // Single countable list: 38 wire-stable methods plus 13 ai methods.
        assert_eq!(all_known_methods().len(), 51);
        // No duplicates.
        let mut seen = std::collections::BTreeSet::new();
        for m in all_known_methods() {
            assert!(seen.insert(*m), "duplicate method '{m}'");
        }
        // Every listed method resolves (forward sync: list -> Some).
        for m in all_known_methods() {
            assert!(
                required_scope_for_method(m).is_some(),
                "listed method '{m}' has no required scope"
            );
        }
        // Every ai method resolves to its assigned scope.
        for m in AI_INSPECT_METHODS {
            assert_eq!(
                required_scope_for_method(m),
                Some(Scope::AiInspect),
                "method '{m}'"
            );
        }
        for m in AI_INVOKE_METHODS {
            assert_eq!(
                required_scope_for_method(m),
                Some(Scope::AiInvoke),
                "method '{m}'"
            );
        }
        // Every new name passes the wire grammar.
        for m in all_known_methods() {
            if m.starts_with("ai.") {
                assert!(validate_method_name(m).is_ok(), "method '{m}'");
            }
        }
    }

    #[test]
    fn ai_scope_denial_by_default() {
        // // POLICY (CTX-0006): deny-by-default survives on every profile —
        // no default set contains either ai scope, so every ai method denies
        // with ScopeDenied (known method, missing grant), never NotFound.
        let profiles = [
            ScopeSet::new(),
            ScopeSet::cli_default(),
            ScopeSet::mcp_default(),
            ScopeSet::mcp_default_with_debug_inspect(),
        ];
        assert_eq!(ScopeSet::cli_default().len(), 6);
        assert_eq!(ScopeSet::mcp_default().len(), 4);
        for granted in &profiles {
            assert!(!granted.contains(Scope::AiInspect));
            assert!(!granted.contains(Scope::AiInvoke));
            for m in AI_INSPECT_METHODS.iter().chain(AI_INVOKE_METHODS.iter()) {
                let err = authorize_method(m, granted).unwrap_err();
                assert!(
                    matches!(err, IpcError::ScopeDenied { .. }),
                    "method '{m}' denied wrongly: {err:?}"
                );
            }
        }
        // Elevation is required on both profiles for both ai scopes.
        assert!(ScopeSet::requires_elevation(Scope::AiInspect));
        assert!(ScopeSet::requires_elevation(Scope::AiInvoke));
        assert!(ScopeSet::requires_mcp_elevation(Scope::AiInspect));
        assert!(ScopeSet::requires_mcp_elevation(Scope::AiInvoke));
    }

    #[test]
    fn ai_inspect_does_not_imply_invoke() {
        // // POLICY (CTX-0006): the `ai.inspect` < `ai.invoke` ordering is
        // authority order only, like every existing family — no implication
        // in either direction (exact-match authorize, no ambient escalation).
        let inspect_only = ScopeSet::single(Scope::AiInspect);
        for m in AI_INSPECT_METHODS {
            assert!(authorize_method(m, &inspect_only).is_ok(), "method '{m}'");
        }
        for m in AI_INVOKE_METHODS {
            assert!(authorize_method(m, &inspect_only).is_err());
        }
        let invoke_only = ScopeSet::single(Scope::AiInvoke);
        for m in AI_INVOKE_METHODS {
            assert!(authorize_method(m, &invoke_only).is_ok(), "method '{m}'");
        }
        for m in AI_INSPECT_METHODS {
            assert!(authorize_method(m, &invoke_only).is_err());
        }
    }

    #[test]
    fn ai_unregistered_name_denies_notfound() {
        // Unknown methods deny NotFound even with every scope granted: no
        // ambient authority, no ai-namespace wildcard (FS-IP1).
        let all = ScopeSet::all();
        for m in ["ai.evil", "ai.admin", "ai.invoke_all", "ai"] {
            let err = authorize_method(m, &all).unwrap_err();
            assert!(
                matches!(err, IpcError::NotFound { .. }),
                "method '{m}' denied wrongly: {err:?}"
            );
        }
    }

    #[test]
    fn ai_method_grammar_rejection() {
        for m in [
            "ai.",
            "ai..list",
            ".ai.list",
            "ai.list.",
            "ai.List",
            "ai.9lives",
            "ai.has space",
            "AI.list",
            "ai.list!",
            "ai.model-select",
        ] {
            assert!(
                validate_method_name(m).is_err(),
                "bad ai name '{m}' accepted"
            );
        }
    }

    #[test]
    fn forged_level_echo_cannot_escalate() {
        use crate::json::validate_params_json;
        // // POLICY (CTX-0006): AuthBase.level / CallerScopeEcho cross as
        // params data only. Authorization reads solely the server-derived
        // grant set — a forged tier echo in params changes nothing.
        let forged = br#"{"level":"All","agent_instance_id":1,"session_id":2}"#;
        assert!(validate_params_json(forged).is_ok()); // opaque data, ignored
        assert!(authorize_method("ai.tool_dispatch", &ScopeSet::new()).is_err());
        // Wrapped as authority, the same echo is refused at the JSON layer.
        assert!(validate_params_json(br#"{"auth":{"level":"All"}}"#).is_err());
        assert!(validate_params_json(br#"{"scope":"ai.invoke"}"#).is_err());
        assert!(validate_params_json(br#"{"role":"admin"}"#).is_err());
        // A grant for an unrelated scope does not escalate into ai.invoke.
        let mut other = ScopeSet::new();
        other.insert(Scope::ProcessSpawn);
        other.insert(Scope::TerminalManage);
        let err = authorize_method("ai.tool_dispatch", &other).unwrap_err();
        assert!(matches!(err, IpcError::ScopeDenied { .. }));
        let err2 = authorize_method("ai.provider_complete", &other).unwrap_err();
        assert!(matches!(err2, IpcError::ScopeDenied { .. }));
    }

    #[test]
    fn ai_consent_ledger_path() {
        // // POLICY (CTX-0006): per-op consent gating for ai methods flows
        // through the generic ledger — one scope per grant, no bundling,
        // revocation/expiry returns the client to deny (RFC consent items
        // 1-2, 4).
        let mut ledger = ConsentLedger::new();
        let client = "agent-7";
        // Grant ai.inspect: inspect methods allowed, invoke still denied.
        ledger
            .grant(client.into(), Scope::AiInspect, 0, 10_000, "user".into())
            .unwrap();
        let mut granted = ScopeSet::new();
        if ledger.is_granted(client, Scope::AiInspect, 100) {
            granted.insert(Scope::AiInspect);
        }
        if ledger.is_granted(client, Scope::AiInvoke, 100) {
            granted.insert(Scope::AiInvoke);
        }
        assert!(authorize_method("ai.model_select", &granted).is_ok());
        assert!(authorize_method("ai.tool_dispatch", &granted).is_err());
        // Separate grant for ai.invoke: no bundling, each scope independent.
        ledger
            .grant(client.into(), Scope::AiInvoke, 100, 10_000, "user".into())
            .unwrap();
        let mut granted2 = ScopeSet::new();
        if ledger.is_granted(client, Scope::AiInspect, 200) {
            granted2.insert(Scope::AiInspect);
        }
        if ledger.is_granted(client, Scope::AiInvoke, 200) {
            granted2.insert(Scope::AiInvoke);
        }
        assert!(authorize_method("ai.tool_dispatch", &granted2).is_ok());
        // Revocation returns to deny immediately.
        assert!(ledger.revoke(client, Scope::AiInvoke));
        assert!(!ledger.is_granted(client, Scope::AiInvoke, 200));
        // Expiry returns to deny without revocation.
        assert!(ledger.is_granted(client, Scope::AiInspect, 9_999));
        assert!(!ledger.is_granted(client, Scope::AiInspect, 10_000));
    }
}
