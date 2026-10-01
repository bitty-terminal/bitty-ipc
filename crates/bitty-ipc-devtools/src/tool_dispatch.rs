//! Host-registered tool dispatch with per-tool consent (CTX-0421, G-3).
//!
//! The Core-internal registry (`bitty-agent/src/tool.rs`) validates calls
//! syntactically but never executes them; there is no IPC tool-dispatch
//! method with per-tool consent (TB-4). This module closes that gap with a
//! generic host-registered dispatch honoring the accepted
//! capability/consent model, read-only by default.
//!
//! Reference evidence (read-only, never modified here): `bitty-ai` PR #7
//! tool bus (`bitty-ai-runtime/src/tool.rs`: bounded `ToolRegistry`,
//! validation before dispatch, per-tool `ToolAuthorizer` seam denying by
//! default, per-turn call cap, bounded arguments/results; `harness.rs`
//! `AllowReadOnly` plus inspect-tier read-only gate; unknown tool fails
//! closed before dispatch, write tool denied by default).
//!
//! # Dispatch formula (DIR-018 step 2)
//!
//! Each dispatch composes exactly seven steps; any refusal leaves no
//! partial state (FS-IP1 transactional denial):
//!
//! 1. **Routing**: look up the tool in the host table; unknown tools fail
//!    closed as `NotFound` before any authorization, budget, or provider
//!    contact.
//! 2. **Authorization**: check the server-evaluated [`ScopeSet`] for the
//!    tool's declared [`Scope`]; missing scope fails as `ScopeDenied`.
//!    Clients never assert scopes.
//! 3. **Consent**: check the per-client [`ConsentLedger`] for
//!    `(client_id, scope)` at `now_ms`; missing or expired grants fail as
//!    `Denied[ConsentRequired]`. Consent granularity is per
//!    `(client_id, scope)` inherited from the accepted ledger — two tools
//!    sharing one scope share consent. Per-tool identity enters via
//!    routing (step 1), attribution (step 6), and the explicit per-call
//!    effect opt-in below; per-tool-name ledger entries are sequel work.
//!    Effect tools additionally require an
//!    explicit per-call opt-in (see below); there is no bundled admin.
//! 4. **Captured target**: validate the optional target shape up front
//!    (host `t:<digits>` grammar via [`crate::ctl::parse_terminal_id`]),
//!    capture it at dispatch, hand it to the provider, and verify the
//!    provider echoes the same target. A mismatch fails as
//!    `InvalidRequest` (confused-deputy guard). This composes with the
//!    snapshot service's captured target (CTX-0420) without depending on
//!    unmerged code: both validate the same host grammar, but neither
//!    imports the other.
//! 5. **Budget**: enforce argument/result/summary bounds; over-bound
//!    inputs or provider outputs fail as `LimitExceeded`, never silently
//!    clamped or truncated.
//! 6. **Attribution**: bind `client_id` + `tool` + `execution_id` into the
//!    outcome; denials carry typed scope/action or code/reason for
//!    FS-IP4 attribution.
//! 7. **Outcome**: return a bounded [`ToolExecution`] labeled
//!    `is_untrusted_surface` (always `true`; T-10 / R-013). Failures are
//!    typed [`IpcError`]s, never partial executions. `Unknown`
//!    reconciliation (effect may have happened without ack) belongs to the
//!    ExecutionContext sequel (DIR-018 step 3), not here.
//!
//! # Read-only by default (TB-4)
//!
//! Tools declare `read_only`. Read-only tools serve with scope +
//! consent. Effect tools (`read_only == false`) additionally require
//! `allow_effects == true` on the request; without it dispatch denies as
//! `Denied[EffectRequiresExplicitConsent]` even when scope and consent
//! are present. There is no ambient authority: a missing authorizing
//! scope, a missing consent grant, or a missing explicit effect opt-in
//! each refuses independently.
//!
//! Effect tools must not launder through read-only scopes: registration
//! rejects an effect tool whose `required_scope` is a pure-inspect scope
//! (`terminal.inspect`, `view.inspect`, `config.inspect`,
//! `plugin.inspect`, `debug.inspect`).
//!
//! # Budgets (accepted contracts, verified first-hand)
//!
//! Every number below reuses an accepted bound; no value is invented:
//!
//! - Tool name `<= 64` bytes, `^[a-z][a-z0-9_]*$` (single segment):
//!   IPC-Agent RFC tool vocabulary plus `bitty-ai-runtime` TB-2. The
//!   Core-internal `bitty-agent` grammar additionally allows `.`/`-`;
//!   dot/dash mapping is sequel work, so dispatch stays on the stricter
//!   single-segment shape and rejects dots/dashes fail-closed.
//! - Description `<= 512` bytes (RFC tool vocabulary).
//! - Schema `<= 16 KiB` opaque bytes (RFC tool vocabulary).
//! - Arguments `<= 16 KiB` (RFC; `bitty-agent` `MAX_TOOL_ARGS_BYTES`).
//! - Result data `<= 16 KiB` (RFC; `bitty-agent` `MAX_TOOL_RESULT_BYTES`).
//! - Registry `<= 32` tools (RFC; `bitty-agent` `MAX_TOOLS_PER_AGENT`).
//! - Summary `<= 512` bytes (`devtools::MAX_ERROR_MESSAGE_CHARS`,
//!   bounded human-message precedent).
//! - Target and client identity `<= 64` bytes each
//!   (`auth::MAX_SCOPED_ID_BYTES`, scoped-id precedent); targets must
//!   additionally satisfy the host `t:<digits>` grammar.
//!
//! The module is pure data, bounded, headless, and `forbid(unsafe)`: it
//! owns no socket, spawns no thread, performs no I/O, and depends on no
//! workspace crate beyond `bitty-ipc` itself. No network, no new external
//! crates.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use bitty_ipc_api::error::IpcError;
use bitty_ipc_api::scope::{ConsentLedger, Scope, ScopeSet};

// ── bounds (accepted-contract sources inline) ───────────────────────────────

/// Maximum tool name bytes (RFC tool vocabulary, TB-2).
pub const MAX_TOOL_NAME_LEN: usize = 64;

/// Maximum tool description bytes (RFC tool vocabulary).
pub const MAX_TOOL_DESCRIPTION_LEN: usize = 512;

/// Maximum tool JSON Schema bytes, opaque (RFC tool vocabulary).
pub const MAX_TOOL_SCHEMA_BYTES: usize = 16 * 1024;

/// Maximum tool argument bytes (RFC; `bitty-agent` args cap).
pub const MAX_TOOL_ARGS_BYTES: usize = 16 * 1024;

/// Maximum tool result data bytes (RFC; `bitty-agent` result cap).
pub const MAX_TOOL_RESULT_BYTES: usize = 16 * 1024;

/// Maximum tools per host dispatcher (RFC; `bitty-agent` per-agent cap).
pub const MAX_TOOLS_PER_HOST: usize = 32;

/// Maximum outcome summary bytes (`devtools::MAX_ERROR_MESSAGE_CHARS`).
pub const MAX_TOOL_SUMMARY_BYTES: usize = crate::devtools::MAX_ERROR_MESSAGE_CHARS;

/// Maximum target/client-identity bytes (`auth::MAX_SCOPED_ID_BYTES`).
pub const MAX_TOOL_TARGET_BYTES: usize = bitty_ipc_auth::auth::MAX_SCOPED_ID_BYTES;

/// Maximum client identity bytes (`auth::MAX_SCOPED_ID_BYTES`).
pub const MAX_TOOL_CLIENT_ID_BYTES: usize = bitty_ipc_auth::auth::MAX_SCOPED_ID_BYTES;

// ── tool name grammar ───────────────────────────────────────────────────────

/// Validate a tool name (`^[a-z][a-z0-9_]*$`, single segment, `<= 64`).
///
/// Dots and dashes are rejected: dots would collide with IPC method
/// hierarchy routing, and dashes collide with CLI-flag parsing. Mapping
/// the looser Core-internal vocabulary is sequel work.
///
/// # Errors
///
/// Returns `InvalidRequest` when the name is empty, over-bound, or
/// violates the grammar.
pub fn validate_tool_name(name: &str) -> Result<(), IpcError> {
    if name.is_empty() {
        return Err(IpcError::InvalidRequest {
            reason: "tool name must not be empty".into(),
        });
    }
    if name.len() > MAX_TOOL_NAME_LEN {
        return Err(IpcError::LimitExceeded {
            field: "tool name".into(),
            limit: MAX_TOOL_NAME_LEN,
            actual: name.len(),
        });
    }
    if name.contains('\0') {
        return Err(IpcError::InvalidRequest {
            reason: "tool name must not contain NUL".into(),
        });
    }
    let mut bytes = name.bytes();
    let first = bytes.next().unwrap_or(b'0');
    if !first.is_ascii_lowercase() {
        return Err(IpcError::InvalidRequest {
            reason: "tool name must start with [a-z]".into(),
        });
    }
    for byte in name.bytes() {
        let ok = byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_';
        if !ok {
            return Err(IpcError::InvalidRequest {
                reason: "tool name must match ^[a-z][a-z0-9_]*$".into(),
            });
        }
    }
    Ok(())
}

/// Whether `scope` is a pure-inspect (read-only) scope.
#[must_use]
pub fn is_read_only_scope(scope: Scope) -> bool {
    matches!(
        scope,
        Scope::TerminalInspect
            | Scope::ViewInspect
            | Scope::ConfigInspect
            | Scope::PluginInspect
            | Scope::DebugInspect
    )
}

// ── declaration ─────────────────────────────────────────────────────────────

/// A bounded host tool declaration (TB-2 shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSpec {
    /// Registered tool name (`^[a-z][a-z0-9_]*$`).
    pub name: String,
    /// Human-readable description (`<= 512` bytes).
    pub description: String,
    /// JSON Schema for arguments, opaque bounded bytes (`<= 16 KiB`).
    pub schema_json: Vec<u8>,
    /// Capability scope the tool requires (one of the 13 accepted scopes).
    pub required_scope: Scope,
    /// Whether the tool is side-effect free. Effect tools need an
    /// explicit per-call opt-in plus scope and consent.
    pub read_only: bool,
}

impl ToolSpec {
    /// Construct and validate a declaration.
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when the name violates the grammar, contains
    ///   NUL, carries NUL in description, or when an effect tool declares
    ///   a pure-inspect scope (authority laundering).
    /// - `LimitExceeded` when description or schema exceeds budget.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        schema_json: Vec<u8>,
        required_scope: Scope,
        read_only: bool,
    ) -> Result<Self, IpcError> {
        let name = name.into();
        let description = description.into();
        validate_tool_name(&name)?;
        if description.len() > MAX_TOOL_DESCRIPTION_LEN {
            return Err(IpcError::LimitExceeded {
                field: "tool description".into(),
                limit: MAX_TOOL_DESCRIPTION_LEN,
                actual: description.len(),
            });
        }
        if schema_json.len() > MAX_TOOL_SCHEMA_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "tool schema".into(),
                limit: MAX_TOOL_SCHEMA_BYTES,
                actual: schema_json.len(),
            });
        }
        if description.contains('\0') {
            return Err(IpcError::InvalidRequest {
                reason: "tool description must not contain NUL".into(),
            });
        }
        if !read_only && is_read_only_scope(required_scope) {
            return Err(IpcError::InvalidRequest {
                reason: format!(
                    "effect tool '{name}' must not require read-only scope '{}'",
                    required_scope.as_str()
                ),
            });
        }
        Ok(Self {
            name,
            description,
            schema_json,
            required_scope,
            read_only,
        })
    }
}

// ── request ─────────────────────────────────────────────────────────────────

/// Bounded tool invocation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRequest {
    /// Registered tool name.
    pub tool: String,
    /// Opaque bounded JSON arguments (`<= 16 KiB`).
    pub arguments: Vec<u8>,
    /// Optional captured target (host `t:<digits>` when present).
    pub target: Option<String>,
    /// Explicit effect opt-in; required for effect tools, ignored for
    /// read-only tools. Defaults to `false` (read-only by default).
    pub allow_effects: bool,
}

impl ToolRequest {
    /// Build a read-only-by-default request for `tool` with `arguments`.
    #[must_use]
    pub fn new(tool: impl Into<String>, arguments: Vec<u8>) -> Self {
        Self {
            tool: tool.into(),
            arguments,
            target: None,
            allow_effects: false,
        }
    }

    /// Capture a host target (`t:<digits>`).
    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Opt into effect execution for effect tools (explicit consent path).
    #[must_use]
    pub fn with_allow_effects(mut self, allow: bool) -> Self {
        self.allow_effects = allow;
        self
    }

    /// Validate the request shape (fail-closed, no side effects).
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when the tool name violates the grammar or the
    ///   target violates the host `t:<digits>` grammar.
    /// - `LimitExceeded` when arguments or target exceed budget.
    pub fn validate(&self) -> Result<(), IpcError> {
        validate_tool_name(&self.tool)?;
        if self.arguments.len() > MAX_TOOL_ARGS_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "tool arguments".into(),
                limit: MAX_TOOL_ARGS_BYTES,
                actual: self.arguments.len(),
            });
        }
        if let Some(target) = &self.target {
            if target.len() > MAX_TOOL_TARGET_BYTES {
                return Err(IpcError::LimitExceeded {
                    field: "tool target".into(),
                    limit: MAX_TOOL_TARGET_BYTES,
                    actual: target.len(),
                });
            }
            crate::ctl::parse_terminal_id(target).map(|_| ())?;
        }
        Ok(())
    }
}

// ── provider output ─────────────────────────────────────────────────────────

/// Raw provider output before bounding and attribution.
///
/// Providers never set the trust label themselves; the service always
/// labels the outcome `is_untrusted_surface`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    /// Target the data corresponds to (must match the request target).
    pub target_id: Option<String>,
    /// Bounded result bytes (`<= 16 KiB`).
    pub data: Vec<u8>,
    /// Bounded human summary (`<= 512` bytes).
    pub summary: String,
}

impl ToolOutput {
    /// Validate the output shape (fail-closed before it enters an outcome).
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when the summary contains NUL.
    /// - `LimitExceeded` when data or summary exceeds budget.
    pub fn validate(&self) -> Result<(), IpcError> {
        if self.data.len() > MAX_TOOL_RESULT_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "tool result".into(),
                limit: MAX_TOOL_RESULT_BYTES,
                actual: self.data.len(),
            });
        }
        if self.summary.len() > MAX_TOOL_SUMMARY_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "tool summary".into(),
                limit: MAX_TOOL_SUMMARY_BYTES,
                actual: self.summary.len(),
            });
        }
        if self.summary.contains('\0') {
            return Err(IpcError::InvalidRequest {
                reason: "tool summary must not contain NUL".into(),
            });
        }
        Ok(())
    }
}

// ── outcome ─────────────────────────────────────────────────────────────────

/// Bounded, attributed tool outcome (DIR-018 outcome step).
///
/// Exactly the dispatched tool's result with host attribution; tool bytes
/// are untrusted observation data, never instructions (T-10 / R-013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecution {
    /// Attribution handle for this dispatch (caller-supplied, monotonic).
    pub execution_id: u64,
    /// Authenticated client identity the dispatch is attributed to.
    pub client_id: String,
    /// Tool that ran.
    pub tool: String,
    /// Captured target the result corresponds to.
    pub target: Option<String>,
    /// Bounded human summary.
    pub summary: String,
    /// Bounded result bytes.
    pub data: Vec<u8>,
    /// Always `true`: tool results are untrusted observations.
    pub is_untrusted_surface: bool,
}

impl ToolExecution {
    /// Whether this outcome is an untrusted observation surface.
    ///
    /// Always `true`; provided so call sites read intent, not a field.
    #[must_use]
    pub fn is_untrusted_surface(&self) -> bool {
        self.is_untrusted_surface
    }

    /// Validate the outcome against its budgets (fail-closed).
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when the tool name violates the grammar, the
    ///   client identity is empty, or the trust label is not set.
    /// - `LimitExceeded` when client identity, data, summary, or target
    ///   exceeds budget.
    pub fn validate(&self) -> Result<(), IpcError> {
        validate_tool_name(&self.tool)?;
        if self.client_id.is_empty() {
            return Err(IpcError::InvalidRequest {
                reason: "tool client_id must not be empty".into(),
            });
        }
        if self.client_id.len() > MAX_TOOL_CLIENT_ID_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "tool client_id".into(),
                limit: MAX_TOOL_CLIENT_ID_BYTES,
                actual: self.client_id.len(),
            });
        }
        if !self.is_untrusted_surface {
            return Err(IpcError::InvalidRequest {
                reason: "tool outcomes must be labeled is_untrusted_surface".into(),
            });
        }
        if self.data.len() > MAX_TOOL_RESULT_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "tool result".into(),
                limit: MAX_TOOL_RESULT_BYTES,
                actual: self.data.len(),
            });
        }
        if self.summary.len() > MAX_TOOL_SUMMARY_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "tool summary".into(),
                limit: MAX_TOOL_SUMMARY_BYTES,
                actual: self.summary.len(),
            });
        }
        if let Some(target) = &self.target {
            if target.len() > MAX_TOOL_TARGET_BYTES {
                return Err(IpcError::LimitExceeded {
                    field: "tool target".into(),
                    limit: MAX_TOOL_TARGET_BYTES,
                    actual: target.len(),
                });
            }
            crate::ctl::parse_terminal_id(target).map(|_| ())?;
        }
        Ok(())
    }
}

// ── host dispatcher ─────────────────────────────────────────────────────────

/// Host-side provider for one registered tool.
///
/// Receives the validated request (with captured target) and returns raw
/// output; the service enforces budgets, target match, and trust labeling.
/// Providers are pure `fn` pointers so the table stays dependency-free,
/// mirroring the snapshot dispatcher.
pub type ToolProvider = fn(&ToolRequest) -> Result<ToolOutput, IpcError>;

/// Host-registered tool dispatch service.
///
/// The table maps tool names to `(spec, provider)` pairs. Dispatch
/// implements the DIR-018 formula on every request; unknown tools,
/// missing scopes, missing consent, missing explicit effect opt-in, and
/// missing handlers all fail closed with no partial state (FS-IP1).
#[derive(Debug, Default)]
pub struct ToolDispatchService {
    /// Tool name to (spec, provider).
    handlers: BTreeMap<String, (ToolSpec, ToolProvider)>,
}

impl ToolDispatchService {
    /// Empty service: every dispatch fails closed until a tool registers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: BTreeMap::new(),
        }
    }

    /// Register a tool with its host provider.
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when the spec is invalid or the tool name is
    ///   already registered (no silent overwrite).
    /// - `LimitExceeded` when the registry is at capacity (`32`).
    pub fn register(&mut self, spec: ToolSpec, provider: ToolProvider) -> Result<(), IpcError> {
        if self.handlers.contains_key(&spec.name) {
            return Err(IpcError::InvalidRequest {
                reason: format!("duplicate tool '{}'", spec.name),
            });
        }
        if self.handlers.len() >= MAX_TOOLS_PER_HOST {
            return Err(IpcError::LimitExceeded {
                field: "tool registry".into(),
                limit: MAX_TOOLS_PER_HOST,
                actual: self.handlers.len() + 1,
            });
        }
        self.handlers.insert(spec.name.clone(), (spec, provider));
        Ok(())
    }

    /// Whether `tool` has a registered provider.
    #[must_use]
    pub fn contains(&self, tool: &str) -> bool {
        self.handlers.contains_key(tool)
    }

    /// Number of registered tools.
    #[must_use]
    pub fn tool_count(&self) -> usize {
        self.handlers.len()
    }

    /// Registered tool names in sorted order.
    #[must_use]
    pub fn tool_names(&self) -> Vec<String> {
        self.handlers.keys().cloned().collect()
    }

    /// Serve one bounded tool dispatch (fail-closed, no partial state).
    ///
    /// Implements routing + authorization + consent + captured target +
    /// budget + attribution + outcome per call.
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when the request shape is malformed or the
    ///   provider returns data for a different target than captured.
    /// - `NotFound` when the tool is unknown or has no host provider.
    /// - `ScopeDenied` when `granted` lacks the tool's required scope.
    /// - `Denied[EffectRequiresExplicitConsent]` when an effect tool is
    ///   called without `allow_effects`.
    /// - `Denied[ConsentRequired]` when the consent ledger lacks an
    ///   active `(client_id, scope)` grant at `now_ms`.
    /// - `LimitExceeded` when arguments or bounded outputs violate budget.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch(
        &self,
        request: &ToolRequest,
        granted: &ScopeSet,
        consent: &ConsentLedger,
        client_id: &str,
        now_ms: u64,
        execution_id: u64,
    ) -> Result<ToolExecution, IpcError> {
        request.validate()?;
        if client_id.is_empty() {
            return Err(IpcError::InvalidRequest {
                reason: "tool client_id must not be empty".into(),
            });
        }
        if client_id.len() > MAX_TOOL_CLIENT_ID_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "tool client_id".into(),
                limit: MAX_TOOL_CLIENT_ID_BYTES,
                actual: client_id.len(),
            });
        }
        let (spec, provider) =
            self.handlers
                .get(&request.tool)
                .ok_or_else(|| IpcError::NotFound {
                    reason: format!("unknown tool '{}'", request.tool),
                })?;
        if !granted.contains(spec.required_scope) {
            return Err(IpcError::ScopeDenied {
                scope: spec.required_scope.as_str().into(),
                action: request.tool.clone(),
            });
        }
        if !spec.read_only && !request.allow_effects {
            return Err(IpcError::Denied {
                code: "EffectRequiresExplicitConsent".into(),
                reason: format!(
                    "effect tool '{}' requires explicit allow_effects",
                    request.tool
                ),
            });
        }
        if !consent.is_granted(client_id, spec.required_scope, now_ms) {
            return Err(IpcError::Denied {
                code: "ConsentRequired".into(),
                reason: format!(
                    "missing consent for '{}' on scope '{}'",
                    request.tool,
                    spec.required_scope.as_str()
                ),
            });
        }
        let output = provider(request)?;
        if output.target_id != request.target {
            return Err(IpcError::InvalidRequest {
                reason: format!(
                    "tool provider returned target '{}', want '{}'",
                    output.target_id.as_deref().unwrap_or("<none>"),
                    request.target.as_deref().unwrap_or("<none>")
                ),
            });
        }
        output.validate()?;
        let execution = ToolExecution {
            execution_id,
            client_id: client_id.to_owned(),
            tool: request.tool.clone(),
            target: request.target.clone(),
            summary: output.summary,
            data: output.data,
            is_untrusted_surface: true,
        };
        execution.validate()?;
        Ok(execution)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_only_spec() -> ToolSpec {
        ToolSpec::new(
            "terminal_read_zone",
            "Read a bounded terminal semantic zone",
            br#"{"type":"object"}"#.to_vec(),
            Scope::TerminalInspect,
            true,
        )
        .expect("valid spec")
    }

    fn effect_spec() -> ToolSpec {
        ToolSpec::new(
            "terminal_send",
            "Send input to a terminal",
            br#"{"type":"object"}"#.to_vec(),
            Scope::TerminalInput,
            false,
        )
        .expect("valid spec")
    }

    fn canned(request: &ToolRequest) -> Result<ToolOutput, IpcError> {
        Ok(ToolOutput {
            target_id: request.target.clone(),
            data: b"hello".to_vec(),
            summary: "ok".to_owned(),
        })
    }

    fn granted(scopes: &[Scope]) -> ScopeSet {
        let mut set = ScopeSet::new();
        for scope in scopes {
            set.insert(*scope);
        }
        set
    }

    fn consented(client: &str, scope: Scope, now_ms: u64) -> ConsentLedger {
        let mut ledger = ConsentLedger::new();
        ledger
            .grant(client.to_owned(), scope, now_ms, 60_000, "test".to_owned())
            .expect("grant");
        ledger
    }

    #[test]
    fn effect_tool_requires_explicit_opt_in() {
        let mut service = ToolDispatchService::new();
        service
            .register(effect_spec(), canned)
            .expect("register effect tool");
        let request = ToolRequest::new("terminal_send", b"{}".to_vec()).with_target("t:2");
        let denied = service
            .dispatch(
                &request,
                &granted(&[Scope::TerminalInput]),
                &consented("agent-1", Scope::TerminalInput, 1_000),
                "agent-1",
                1_000,
                1,
            )
            .expect_err("effect without opt-in must deny");
        assert!(matches!(denied, IpcError::Denied { .. }), "got {denied:?}");
        let allowed = ToolRequest::new("terminal_send", b"{}".to_vec())
            .with_target("t:2")
            .with_allow_effects(true);
        let outcome = service
            .dispatch(
                &allowed,
                &granted(&[Scope::TerminalInput]),
                &consented("agent-1", Scope::TerminalInput, 1_000),
                "agent-1",
                1_000,
                2,
            )
            .expect("explicit effect path serves");
        assert_eq!(outcome.tool, "terminal_send");
        assert!(outcome.is_untrusted_surface);
    }

    #[test]
    fn tool_name_grammar_is_single_segment() {
        assert!(validate_tool_name("terminal_read_zone").is_ok());
        assert!(validate_tool_name("").is_err());
        assert!(validate_tool_name("Terminal").is_err());
        assert!(validate_tool_name("1tool").is_err());
        assert!(validate_tool_name("terminal.read").is_err());
        assert!(validate_tool_name("terminal-read").is_err());
        assert!(validate_tool_name(&"a".repeat(MAX_TOOL_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn effect_tool_with_read_only_scope_is_rejected() {
        let spec = ToolSpec::new(
            "terminal_send",
            "effect with read-only scope",
            Vec::new(),
            Scope::TerminalInspect,
            false,
        );
        assert!(
            matches!(spec, Err(IpcError::InvalidRequest { .. })),
            "got {spec:?}"
        );
    }

    #[test]
    fn duplicate_registration_is_rejected() {
        let mut service = ToolDispatchService::new();
        service
            .register(read_only_spec(), canned)
            .expect("first register");
        let error = service
            .register(read_only_spec(), canned)
            .expect_err("duplicate must fail");
        assert!(
            matches!(error, IpcError::InvalidRequest { .. }),
            "got {error:?}"
        );
    }

    #[test]
    fn registry_cap_is_fail_closed() {
        let mut service = ToolDispatchService::new();
        for index in 0..MAX_TOOLS_PER_HOST {
            let spec = ToolSpec::new(
                format!("tool_{index}"),
                "test tool",
                Vec::new(),
                Scope::TerminalInspect,
                true,
            )
            .expect("valid spec");
            service.register(spec, canned).expect("capacity");
        }
        let overflow = ToolSpec::new(
            "one_more",
            "overflow",
            Vec::new(),
            Scope::TerminalInspect,
            true,
        )
        .expect("valid spec");
        let error = service
            .register(overflow, canned)
            .expect_err("overflow must fail");
        assert!(
            matches!(error, IpcError::LimitExceeded { .. }),
            "got {error:?}"
        );
    }

    #[test]
    fn read_only_dispatch_serves_with_attribution() {
        let mut service = ToolDispatchService::new();
        service
            .register(read_only_spec(), canned)
            .expect("register");
        let request = ToolRequest::new("terminal_read_zone", b"{}".to_vec()).with_target("t:3");
        let outcome = service
            .dispatch(
                &request,
                &granted(&[Scope::TerminalInspect]),
                &consented("agent-1", Scope::TerminalInspect, 1_000),
                "agent-1",
                1_000,
                42,
            )
            .expect("dispatch serves");
        assert_eq!(outcome.execution_id, 42);
        assert_eq!(outcome.client_id, "agent-1");
        assert_eq!(outcome.target.as_deref(), Some("t:3"));
        assert!(outcome.is_untrusted_surface);
        assert!(outcome.is_untrusted_surface());
    }

    #[test]
    fn untrusted_label_cannot_be_cleared() {
        let mut outcome = ToolExecution {
            execution_id: 1,
            client_id: "agent-1".to_owned(),
            tool: "terminal_read_zone".to_owned(),
            target: None,
            summary: "ok".to_owned(),
            data: b"hi".to_vec(),
            is_untrusted_surface: true,
        };
        assert!(outcome.validate().is_ok());
        outcome.is_untrusted_surface = false;
        assert!(outcome.validate().is_err());
    }

    #[test]
    fn invalid_target_grammar_is_rejected() {
        let mut service = ToolDispatchService::new();
        service
            .register(read_only_spec(), canned)
            .expect("register");
        let request = ToolRequest::new("terminal_read_zone", b"{}".to_vec()).with_target("panel-1");
        let error = service
            .dispatch(
                &request,
                &granted(&[Scope::TerminalInspect]),
                &consented("agent-1", Scope::TerminalInspect, 1_000),
                "agent-1",
                1_000,
                1,
            )
            .expect_err("bad target must fail");
        assert!(
            matches!(
                error,
                IpcError::InvalidRequest { .. } | IpcError::LimitExceeded { .. }
            ),
            "got {error:?}"
        );
    }

    #[test]
    fn expired_consent_fails_closed() {
        let mut service = ToolDispatchService::new();
        service
            .register(read_only_spec(), canned)
            .expect("register");
        let mut ledger = ConsentLedger::new();
        ledger
            .grant(
                "agent-1".to_owned(),
                Scope::TerminalInspect,
                0,
                100,
                "test".to_owned(),
            )
            .expect("grant");
        let request = ToolRequest::new("terminal_read_zone", b"{}".to_vec());
        let error = service
            .dispatch(
                &request,
                &granted(&[Scope::TerminalInspect]),
                &ledger,
                "agent-1",
                200,
                1,
            )
            .expect_err("expired consent must fail");
        assert!(matches!(error, IpcError::Denied { .. }), "got {error:?}");
    }
}
