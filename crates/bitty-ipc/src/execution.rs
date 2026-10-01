//! Generic supervised-execution backend with structured outcome (CTX-0442, step 3).
//!
//! DIR-018 step 3 (031 §4-§5, exec hard blocker): Bitty owns PTY and process
//! lifecycle, but a future `exec` tool cannot run `cargo test`, `git diff`,
//! or `pytest` under host supervision without a generic primitive that turns
//! an [`ExecutionRequest`] (executable/args/cwd/env_policy/target/timeout/
//! output_budget) into a bounded [`ExecutionResult`] (status/exit/stdout-
//! stderr-summaries/truncated/evidence_refs/effect_state). This module is
//! that generic ExecutionContext backend: pure data, bounded, headless, and
//! generic (no `ai.*` naming per the CTX-0423 demotion direction).
//!
//! Reference patterns (read-only, never modified here): the CTX-0420
//! snapshot service (bounded DTO, fail-closed dispatcher, provider-echo
//! match, `is_untrusted_surface` labeling) and the CTX-0421 tool dispatch
//! (routing + authorization + consent + captured target + budget +
//! attribution + outcome, effect tools need an explicit opt-in, per-client
//! consent granularity, duplicate-before-capacity registration).
//!
//! # Unknown reconciles, never blind-retries
//!
//! When the host loses the acknowledgement path (for example the IPC peer
//! disconnects after the child was spawned), the outcome is
//! [`EffectState::Unknown`]: the effect may or may not have happened. The
//! service stores the `Unknown` result under its `execution_id` and exposes
//! it through [`ExecutionService::reconcile`]. Callers must reconcile first
//! and then close the entry with [`ExecutionService::resolve`]; re-dispatch
//! under a tracked id is rejected as `InvalidRequest`, and there is
//! deliberately no `retry` primitive. Same-id re-dispatch is rejected;
//! a new id is an explicit, separately-attributed re-execution, so
//! callers must reconcile `Unknown` before choosing to re-execute —
//! a blind retry could run a
//! non-idempotent command twice (031 §5: `git checkout foo` must not be
//! assumed failed just because the response never arrived).
//!
//! # Budgets (accepted contracts, verified first-hand)
//!
//! Every number below reuses an accepted bound; no value is invented:
//!
//! - Executable `1..=4096` bytes, no NUL (`ctl::MAX_CTL_CWD_LEN`, path
//!   bound). Host executable-allowlist enforcement is sequel host wiring,
//!   not this pure-data slice: shape and bounds only.
//! - Arguments: at most `64` entries (`devtools::MAX_INPUT_RING`,
//!   bounded-list cap), each `<= 4096` bytes (`ctl::MAX_CTL_PARAMS_BYTES`,
//!   params bound) with no NUL, total `<= 16 KiB`
//!   (`tool_dispatch::MAX_TOOL_ARGS_BYTES`, RFC tool-args cap).
//! - `cwd`: optional, `1..=4096` bytes with no NUL via
//!   `ctl::validate_ctl_cwd` (`ctl::MAX_CTL_CWD_LEN`). `None` means the host
//!   default; this slice invents no default path (no hardcoded host paths).
//! - Environment: closed [`EnvPolicy`] (`Isolated` or `Explicit`); ambient
//!   inheritance cannot be expressed. Names `1..=64` bytes
//!   (`auth::MAX_SCOPED_ID_BYTES`, scoped-id precedent) matching
//!   `^[A-Za-z_][A-Za-z0-9_]*$`, values `<= 4096` bytes
//!   (`ctl::MAX_CTL_CWD_LEN`), at most `64` entries
//!   (`devtools::MAX_INPUT_RING`).
//! - Target: optional host `t:<digits>` grammar via
//!   `ctl::parse_terminal_id`, `<= 64` bytes
//!   (`auth::MAX_SCOPED_ID_BYTES`, same as tool-dispatch targets).
//! - Timeout: `1..=30_000` ms (`channel::MAX_REQUEST_TIMEOUT_MS`, hard
//!   per-request deadline ceiling), default `5_000` ms
//!   (`channel::DEFAULT_REQUEST_TIMEOUT_MS`). Zero is rejected, never
//!   silently clamped.
//! - Output budget: optional caller ceiling `1..=256 KiB`
//!   (`limits::RC10_MAX_SNAPSHOT_BYTES`, same as the snapshot `max_bytes`
//!   ceiling). The effective per-stream budget is
//!   `min(MAX_EXEC_STREAM_BYTES, output_budget)`; each of stdout/stderr is
//!   truncated to it at a char boundary with `truncated = true`, mirroring
//!   the snapshot effective-budget rule.
//! - Per-stream summary: `<= 16 KiB`
//!   (`tool_dispatch::MAX_TOOL_RESULT_BYTES`, RFC tool-result cap).
//!   Absolute per-stream ceiling.
//! - Evidence refs: at most `8` entries (`bitty-agent`
//!   `MAX_TOOL_CALLS_PER_TURN`, per-turn call cap), each non-empty and
//!   `<= 512` bytes (`tool_dispatch::MAX_TOOL_SUMMARY_BYTES`, bounded
//!   human-message precedent), no NUL. Refs are discrete attributions, so
//!   over-bound refs fail closed (`LimitExceeded`); only byte streams
//!   truncate.
//! - Client identity `<= 64` bytes (`auth::MAX_SCOPED_ID_BYTES`).
//! - Tracked executions: at most `64` stored outcomes
//!   (`channel::MAX_PENDING_REQUESTS`, pending-table precedent);
//!   overflow fails closed (`LimitExceeded`), never silently evicts.
//!
//! Token-first profiling (OQ-066) stays open: these levels select byte
//! ceilings only, never a token contract.
//!
//! The module is pure data, bounded, headless, and `forbid(unsafe)`: it
//! owns no socket, spawns no process, performs no I/O, and depends on no
//! workspace crate beyond `bitty-ipc` itself. No network, no new external
//! crates.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use bitty_ipc_api::error::IpcError;
use bitty_ipc_api::scope::{ConsentLedger, Scope, ScopeSet};

// ── bounds (accepted-contract sources inline) ───────────────────────────────

/// Maximum executable path bytes (`ctl::MAX_CTL_CWD_LEN`, 4096).
pub const MAX_EXECUTABLE_BYTES: usize = crate::ctl::MAX_CTL_CWD_LEN;

/// Maximum argument count (`devtools::MAX_INPUT_RING`, bounded-list cap 64).
pub const MAX_EXEC_ARGS: usize = crate::devtools::MAX_INPUT_RING;

/// Maximum bytes per argument (`ctl::MAX_CTL_PARAMS_BYTES`, 4096).
pub const MAX_EXEC_ARG_BYTES: usize = crate::ctl::MAX_CTL_PARAMS_BYTES;

/// Maximum total argument bytes (`tool_dispatch::MAX_TOOL_ARGS_BYTES`, 16 KiB).
pub const MAX_EXEC_ARGS_TOTAL_BYTES: usize = crate::tool_dispatch::MAX_TOOL_ARGS_BYTES;

/// Maximum `cwd` bytes (`ctl::MAX_CTL_CWD_LEN`, 4096).
pub const MAX_EXEC_CWD_BYTES: usize = crate::ctl::MAX_CTL_CWD_LEN;

/// Maximum explicit environment entries (`devtools::MAX_INPUT_RING`, 64).
pub const MAX_EXEC_ENV_VARS: usize = crate::devtools::MAX_INPUT_RING;

/// Maximum environment-variable name bytes (`auth::MAX_SCOPED_ID_BYTES`, 64).
pub const MAX_EXEC_ENV_NAME_BYTES: usize = bitty_ipc_auth::auth::MAX_SCOPED_ID_BYTES;

/// Maximum environment-variable value bytes (`ctl::MAX_CTL_CWD_LEN`, 4096).
pub const MAX_EXEC_ENV_VALUE_BYTES: usize = crate::ctl::MAX_CTL_CWD_LEN;

/// Default execution timeout in ms (`channel::DEFAULT_REQUEST_TIMEOUT_MS`).
pub const DEFAULT_EXEC_TIMEOUT_MS: u64 = bitty_ipc_api::channel::DEFAULT_REQUEST_TIMEOUT_MS;

/// Maximum execution timeout in ms (`channel::MAX_REQUEST_TIMEOUT_MS`).
pub const MAX_EXEC_TIMEOUT_MS: u64 = bitty_ipc_api::channel::MAX_REQUEST_TIMEOUT_MS;

/// Maximum caller output-budget bytes (`limits::RC10_MAX_SNAPSHOT_BYTES`, 256 KiB).
pub const MAX_EXEC_OUTPUT_BUDGET_BYTES: usize = bitty_ipc_core::limits::RC10_MAX_SNAPSHOT_BYTES;

/// Maximum retained bytes per stdout/stderr summary
/// (`tool_dispatch::MAX_TOOL_RESULT_BYTES`, 16 KiB). Absolute per-stream ceiling.
pub const MAX_EXEC_STREAM_BYTES: usize = crate::tool_dispatch::MAX_TOOL_RESULT_BYTES;

/// Maximum evidence refs per outcome (`bitty-agent` `MAX_TOOL_CALLS_PER_TURN`, 8).
pub const MAX_EXEC_EVIDENCE_REFS: usize = 8;

/// Maximum bytes per evidence ref
/// (`tool_dispatch::MAX_TOOL_SUMMARY_BYTES`, bounded human-message precedent).
pub const MAX_EXEC_EVIDENCE_REF_BYTES: usize = crate::tool_dispatch::MAX_TOOL_SUMMARY_BYTES;

/// Maximum target bytes (`auth::MAX_SCOPED_ID_BYTES`, 64).
pub const MAX_EXEC_TARGET_BYTES: usize = bitty_ipc_auth::auth::MAX_SCOPED_ID_BYTES;

/// Maximum client-identity bytes (`auth::MAX_SCOPED_ID_BYTES`, 64).
pub const MAX_EXEC_CLIENT_ID_BYTES: usize = bitty_ipc_auth::auth::MAX_SCOPED_ID_BYTES;

/// Maximum stored outcomes per service (`channel::MAX_PENDING_REQUESTS`, 64).
pub const MAX_TRACKED_EXECUTIONS: usize = bitty_ipc_api::channel::MAX_PENDING_REQUESTS;

/// Scope guarding supervised execution (always separate; requires elevation).
pub const EXECUTION_SCOPE: Scope = Scope::ProcessSpawn;

// ── closed outcome vocabulary ───────────────────────────────────────────────

/// Process-completion view of an execution (closed set).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionStatus {
    /// The process ran to completion (see `exit_code` for success/failure).
    Completed,
    /// The process ran and failed (non-zero exit or host-reported failure).
    Failed,
    /// The execution was canceled before producing an outcome.
    Canceled,
    /// Completion is not known (acknowledgement path lost); reconcile first.
    Unknown,
}

impl ExecutionStatus {
    /// Stable wire label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
            Self::Unknown => "unknown",
        }
    }

    /// Whether this status carries no completion knowledge.
    #[must_use]
    pub fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }
}

impl fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ExecutionStatus {
    type Err = IpcError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "canceled" => Ok(Self::Canceled),
            "unknown" => Ok(Self::Unknown),
            _ => Err(IpcError::InvalidRequest {
                reason: format!(
                    "unknown execution status '{s}' (want completed|failed|canceled|unknown)"
                ),
            }),
        }
    }
}

/// Effect-certainty view of an execution (closed set, 031 §5).
///
/// `Unknown` means the effect may or may not have happened: the caller must
/// reconcile through [`ExecutionService::reconcile`] and close with
/// [`ExecutionService::resolve`], never blind-retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EffectState {
    /// The effect completed.
    Completed,
    /// The effect failed.
    Failed,
    /// The execution was canceled before the effect landed.
    Canceled,
    /// Effect certainty is not known; reconcile first, never blind-retry.
    Unknown,
}

impl EffectState {
    /// Stable wire label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
            Self::Unknown => "unknown",
        }
    }

    /// Whether effect certainty is missing (reconciliation required).
    #[must_use]
    pub fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }
}

impl fmt::Display for EffectState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EffectState {
    type Err = IpcError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "canceled" => Ok(Self::Canceled),
            "unknown" => Ok(Self::Unknown),
            _ => Err(IpcError::InvalidRequest {
                reason: format!(
                    "unknown effect state '{s}' (want completed|failed|canceled|unknown)"
                ),
            }),
        }
    }
}

// ── closed environment policy ───────────────────────────────────────────────

/// One explicit environment entry (name plus value, no inheritance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVar {
    /// Variable name (`^[A-Za-z_][A-Za-z0-9_]*$`, `1..=64` bytes).
    pub name: String,
    /// Variable value (`<= 4096` bytes, may be empty).
    pub value: String,
}

impl EnvVar {
    /// Build and validate one entry.
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when the name is empty, violates the grammar, or
    ///   either field contains NUL.
    /// - `LimitExceeded` when the name or value exceeds budget.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Result<Self, IpcError> {
        let var = Self {
            name: name.into(),
            value: value.into(),
        };
        var.validate()?;
        Ok(var)
    }

    /// Validate the entry shape (fail-closed, no side effects).
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when the name is empty, violates the grammar, or
    ///   either field contains NUL.
    /// - `LimitExceeded` when the name or value exceeds budget.
    pub fn validate(&self) -> Result<(), IpcError> {
        if self.name.is_empty() {
            return Err(IpcError::InvalidRequest {
                reason: "env var name must not be empty".into(),
            });
        }
        if self.name.len() > MAX_EXEC_ENV_NAME_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "env var name".into(),
                limit: MAX_EXEC_ENV_NAME_BYTES,
                actual: self.name.len(),
            });
        }
        if self.value.len() > MAX_EXEC_ENV_VALUE_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "env var value".into(),
                limit: MAX_EXEC_ENV_VALUE_BYTES,
                actual: self.value.len(),
            });
        }
        if self.name.contains('\0') || self.value.contains('\0') {
            return Err(IpcError::InvalidRequest {
                reason: "env var must not contain NUL".into(),
            });
        }
        let mut bytes = self.name.bytes();
        let first = bytes.next().unwrap_or(b'0');
        if !(first.is_ascii_alphabetic() || first == b'_') {
            return Err(IpcError::InvalidRequest {
                reason: "env var name must start with [A-Za-z_]".into(),
            });
        }
        for byte in self.name.bytes() {
            let ok = byte.is_ascii_alphanumeric() || byte == b'_';
            if !ok {
                return Err(IpcError::InvalidRequest {
                    reason: "env var name must match ^[A-Za-z_][A-Za-z0-9_]*$".into(),
                });
            }
        }
        Ok(())
    }
}

/// Closed environment policy: no ambient passthrough by construction.
///
/// There is no `Inherit` variant: a supervised child either starts from an
/// empty environment ([`EnvPolicy::Isolated`]) or from an explicitly listed
/// bounded set ([`EnvPolicy::Explicit`]). Ambient process environment can
/// never flow across the boundary because no value of this type expresses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvPolicy {
    /// Empty environment (no inherited variables).
    Isolated,
    /// Bounded explicit environment (no inherited variables).
    Explicit {
        /// Explicit entries (`<= 64`).
        vars: Vec<EnvVar>,
    },
}

impl EnvPolicy {
    /// Build a bounded explicit policy from `(name, value)` pairs.
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when any entry violates the name grammar or
    ///   contains NUL.
    /// - `LimitExceeded` when the entry count or any field exceeds budget.
    pub fn explicit(vars: Vec<(String, String)>) -> Result<Self, IpcError> {
        if vars.len() > MAX_EXEC_ENV_VARS {
            return Err(IpcError::LimitExceeded {
                field: "env vars".into(),
                limit: MAX_EXEC_ENV_VARS,
                actual: vars.len(),
            });
        }
        let mut entries = Vec::with_capacity(vars.len());
        for (name, value) in vars {
            entries.push(EnvVar::new(name, value)?);
        }
        Ok(Self::Explicit { vars: entries })
    }

    /// Whether this policy starts from an empty environment.
    #[must_use]
    pub fn is_isolated(&self) -> bool {
        matches!(self, Self::Isolated)
    }

    /// Number of explicit entries (zero for [`EnvPolicy::Isolated`]).
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Isolated => 0,
            Self::Explicit { vars } => vars.len(),
        }
    }

    /// Whether there are no explicit entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Validate the policy shape (fail-closed, no side effects).
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when any entry violates the name grammar or
    ///   contains NUL.
    /// - `LimitExceeded` when the entry count or any field exceeds budget.
    pub fn validate(&self) -> Result<(), IpcError> {
        match self {
            Self::Isolated => Ok(()),
            Self::Explicit { vars } => {
                if vars.len() > MAX_EXEC_ENV_VARS {
                    return Err(IpcError::LimitExceeded {
                        field: "env vars".into(),
                        limit: MAX_EXEC_ENV_VARS,
                        actual: vars.len(),
                    });
                }
                for var in vars {
                    var.validate()?;
                }
                Ok(())
            }
        }
    }
}

// ── request ─────────────────────────────────────────────────────────────────

/// Bounded supervised-execution request (DIR-018 field list plus effect gate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionRequest {
    /// Executable path or name (`1..=4096` bytes, no NUL).
    pub executable: String,
    /// Argument list (bounded count, per-arg, and total budgets, no NUL).
    pub args: Vec<String>,
    /// Working directory (`None` means the host default; `Some` is
    /// `1..=4096` bytes with no NUL via `ctl::validate_ctl_cwd`).
    pub cwd: Option<String>,
    /// Closed environment policy (never ambient inheritance).
    pub env_policy: EnvPolicy,
    /// Optional captured target (host `t:<digits>` when present).
    pub target: Option<String>,
    /// Supervision timeout in ms (`1..=30_000`).
    pub timeout_ms: u64,
    /// Optional caller output ceiling (`1..=256 KiB`; `None` selects the
    /// per-stream default).
    pub output_budget: Option<usize>,
    /// Explicit effect opt-in; execution is always effectful, so dispatch
    /// denies without it. Defaults to `false` (deny by default).
    pub allow_effects: bool,
}

impl ExecutionRequest {
    /// Build an isolated request with default timeout and stream budget.
    #[must_use]
    pub fn new(executable: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            executable: executable.into(),
            args,
            cwd: None,
            env_policy: EnvPolicy::Isolated,
            target: None,
            timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
            output_budget: None,
            allow_effects: false,
        }
    }

    /// Set the working directory (`None` keeps the host default).
    #[must_use]
    pub fn with_cwd(mut self, cwd: Option<String>) -> Self {
        self.cwd = cwd;
        self
    }

    /// Set the closed environment policy.
    #[must_use]
    pub fn with_env_policy(mut self, policy: EnvPolicy) -> Self {
        self.env_policy = policy;
        self
    }

    /// Capture a host target (`t:<digits>`).
    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Set the supervision timeout in ms.
    #[must_use]
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Set the caller output ceiling in bytes.
    #[must_use]
    pub fn with_output_budget(mut self, budget: usize) -> Self {
        self.output_budget = Some(budget);
        self
    }

    /// Opt into effect execution (explicit consent path).
    #[must_use]
    pub fn with_allow_effects(mut self, allow: bool) -> Self {
        self.allow_effects = allow;
        self
    }

    /// Effective per-stream budget: `min(MAX_EXEC_STREAM_BYTES, output_budget)`.
    #[must_use]
    pub fn effective_stream_budget(&self) -> usize {
        match self.output_budget {
            Some(budget) => MAX_EXEC_STREAM_BYTES.min(budget),
            None => MAX_EXEC_STREAM_BYTES,
        }
    }

    /// Total argument bytes (for budget accounting).
    #[must_use]
    pub fn args_total_bytes(&self) -> usize {
        self.args.iter().map(String::len).sum()
    }

    /// Validate the request shape (fail-closed, no side effects).
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when the executable is empty, any field contains
    ///   NUL, an argument or the target violates its grammar, or the
    ///   timeout/output budget is zero.
    /// - `LimitExceeded` when any field exceeds its accepted budget.
    pub fn validate(&self) -> Result<(), IpcError> {
        if self.executable.is_empty() {
            return Err(IpcError::InvalidRequest {
                reason: "executable must not be empty".into(),
            });
        }
        if self.executable.len() > MAX_EXECUTABLE_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "executable".into(),
                limit: MAX_EXECUTABLE_BYTES,
                actual: self.executable.len(),
            });
        }
        if self.executable.contains('\0') {
            return Err(IpcError::InvalidRequest {
                reason: "executable must not contain NUL".into(),
            });
        }
        if self.args.len() > MAX_EXEC_ARGS {
            return Err(IpcError::LimitExceeded {
                field: "args".into(),
                limit: MAX_EXEC_ARGS,
                actual: self.args.len(),
            });
        }
        for arg in &self.args {
            if arg.len() > MAX_EXEC_ARG_BYTES {
                return Err(IpcError::LimitExceeded {
                    field: "arg".into(),
                    limit: MAX_EXEC_ARG_BYTES,
                    actual: arg.len(),
                });
            }
            if arg.contains('\0') {
                return Err(IpcError::InvalidRequest {
                    reason: "arg must not contain NUL".into(),
                });
            }
        }
        if self.args_total_bytes() > MAX_EXEC_ARGS_TOTAL_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "args total".into(),
                limit: MAX_EXEC_ARGS_TOTAL_BYTES,
                actual: self.args_total_bytes(),
            });
        }
        if let Some(cwd) = &self.cwd {
            if cwd.len() > MAX_EXEC_CWD_BYTES {
                return Err(IpcError::LimitExceeded {
                    field: "cwd".into(),
                    limit: MAX_EXEC_CWD_BYTES,
                    actual: cwd.len(),
                });
            }
            crate::ctl::validate_ctl_cwd(cwd)?;
        }
        self.env_policy.validate()?;
        if let Some(target) = &self.target {
            if target.len() > MAX_EXEC_TARGET_BYTES {
                return Err(IpcError::LimitExceeded {
                    field: "execution target".into(),
                    limit: MAX_EXEC_TARGET_BYTES,
                    actual: target.len(),
                });
            }
            crate::ctl::parse_terminal_id(target).map(|_| ())?;
        }
        if self.timeout_ms == 0 {
            return Err(IpcError::InvalidRequest {
                reason: "timeout_ms must be non-zero".into(),
            });
        }
        if self.timeout_ms > MAX_EXEC_TIMEOUT_MS {
            return Err(IpcError::LimitExceeded {
                field: "timeout_ms".into(),
                limit: MAX_EXEC_TIMEOUT_MS as usize,
                actual: self.timeout_ms as usize,
            });
        }
        if let Some(budget) = self.output_budget {
            if budget == 0 {
                return Err(IpcError::InvalidRequest {
                    reason: "output_budget must be non-zero".into(),
                });
            }
            if budget > MAX_EXEC_OUTPUT_BUDGET_BYTES {
                return Err(IpcError::LimitExceeded {
                    field: "output_budget".into(),
                    limit: MAX_EXEC_OUTPUT_BUDGET_BYTES,
                    actual: budget,
                });
            }
        }
        Ok(())
    }
}

// ── provider output ─────────────────────────────────────────────────────────

/// Raw host-provider output before bounding and attribution.
///
/// Providers never set the trust label themselves; the service always
/// labels the outcome `is_untrusted_surface`. Stream bytes are truncated by
/// the service to the request's effective budget before validation (snapshot
/// precedent); evidence refs are discrete attributions and fail closed when
/// over-bound (tool-dispatch precedent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawExecutionOutput {
    /// Target the data corresponds to (must match the request target).
    pub target_id: Option<String>,
    /// Process-completion view.
    pub status: ExecutionStatus,
    /// Process exit code (`None` when unknown, and conventionally when canceled).
    pub exit_code: Option<i32>,
    /// Raw stdout bytes (truncated to the effective budget by the service).
    pub stdout: String,
    /// Raw stderr bytes (truncated to the effective budget by the service).
    pub stderr: String,
    /// Bounded evidence refs (fail-closed, never truncated).
    pub evidence_refs: Vec<String>,
    /// Effect-certainty view (`Unknown` must pair with `Unknown` status).
    pub effect_state: EffectState,
}

impl RawExecutionOutput {
    /// Validate the output shape (fail-closed before it enters a result).
    ///
    /// Stream lengths are checked here against the absolute per-stream
    /// ceiling: the service truncates to the effective budget *before*
    /// calling this, so direct validation of over-ceiling streams still
    /// fails closed.
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when a stream or ref contains NUL, a ref is
    ///   empty, the target violates the host grammar, the `Unknown`
    ///   agreement is broken, or an `Unknown` outcome carries an exit code.
    /// - `LimitExceeded` when a stream or the ref list exceeds budget.
    pub fn validate(&self) -> Result<(), IpcError> {
        if self.stdout.len() > MAX_EXEC_STREAM_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "stdout".into(),
                limit: MAX_EXEC_STREAM_BYTES,
                actual: self.stdout.len(),
            });
        }
        if self.stderr.len() > MAX_EXEC_STREAM_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "stderr".into(),
                limit: MAX_EXEC_STREAM_BYTES,
                actual: self.stderr.len(),
            });
        }
        if self.stdout.contains('\0') || self.stderr.contains('\0') {
            return Err(IpcError::InvalidRequest {
                reason: "execution output must not contain NUL".into(),
            });
        }
        validate_evidence_refs(&self.evidence_refs)?;
        if let Some(target) = &self.target_id {
            if target.len() > MAX_EXEC_TARGET_BYTES {
                return Err(IpcError::LimitExceeded {
                    field: "execution target".into(),
                    limit: MAX_EXEC_TARGET_BYTES,
                    actual: target.len(),
                });
            }
            crate::ctl::parse_terminal_id(target).map(|_| ())?;
        }
        validate_unknown_agreement(self.status, self.effect_state, self.exit_code.is_some())?;
        Ok(())
    }
}

/// Validate evidence refs (shared by provider output and result DTOs).
fn validate_evidence_refs(refs: &[String]) -> Result<(), IpcError> {
    if refs.len() > MAX_EXEC_EVIDENCE_REFS {
        return Err(IpcError::LimitExceeded {
            field: "evidence_refs".into(),
            limit: MAX_EXEC_EVIDENCE_REFS,
            actual: refs.len(),
        });
    }
    for reference in refs {
        if reference.is_empty() {
            return Err(IpcError::InvalidRequest {
                reason: "evidence ref must not be empty".into(),
            });
        }
        if reference.len() > MAX_EXEC_EVIDENCE_REF_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "evidence ref".into(),
                limit: MAX_EXEC_EVIDENCE_REF_BYTES,
                actual: reference.len(),
            });
        }
        if reference.contains('\0') {
            return Err(IpcError::InvalidRequest {
                reason: "evidence ref must not contain NUL".into(),
            });
        }
    }
    Ok(())
}

/// Enforce the `Unknown` agreement: unknown travels together, and an
/// `Unknown` outcome carries no exit code to quote.
fn validate_unknown_agreement(
    status: ExecutionStatus,
    effect_state: EffectState,
    has_exit_code: bool,
) -> Result<(), IpcError> {
    if status.is_unknown() != effect_state.is_unknown() {
        return Err(IpcError::InvalidRequest {
            reason: format!(
                "status '{status}' and effect state '{effect_state}' must agree on Unknown"
            ),
        });
    }
    if status.is_unknown() && has_exit_code {
        return Err(IpcError::InvalidRequest {
            reason: "Unknown execution must not carry an exit code".into(),
        });
    }
    Ok(())
}

// ── outcome ─────────────────────────────────────────────────────────────────

/// Bounded, attributed execution outcome (DIR-018 result field list).
///
/// Exactly the supervised run's evidence with host attribution: process
/// bytes are untrusted observation data, never instructions (T-10 / R-013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    /// Attribution handle for this dispatch (caller-supplied, monotonic).
    pub execution_id: u64,
    /// Authenticated client identity the dispatch is attributed to.
    pub client_id: String,
    /// Captured target the result corresponds to.
    pub target: Option<String>,
    /// Process-completion view.
    pub status: ExecutionStatus,
    /// Process exit code (`None` when unknown, and conventionally when canceled).
    pub exit_code: Option<i32>,
    /// Bounded stdout summary (char-boundary truncated).
    pub stdout_summary: String,
    /// Bounded stderr summary (char-boundary truncated).
    pub stderr_summary: String,
    /// True when any summary was truncated to fit its budget.
    pub truncated: bool,
    /// Bounded evidence refs.
    pub evidence_refs: Vec<String>,
    /// Effect-certainty view (`Unknown` reconciles, never blind-retries).
    pub effect_state: EffectState,
    /// Always `true`: process bytes are untrusted observations.
    pub is_untrusted_surface: bool,
}

impl ExecutionResult {
    /// Build and validate an outcome; the trust label is always set here.
    ///
    /// # Errors
    ///
    /// Returns the [`ExecutionResult::validate`] failure when the outcome
    /// violates a budget or the `Unknown` agreement.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution_id: u64,
        client_id: String,
        target: Option<String>,
        status: ExecutionStatus,
        exit_code: Option<i32>,
        stdout_summary: String,
        stderr_summary: String,
        truncated: bool,
        evidence_refs: Vec<String>,
        effect_state: EffectState,
    ) -> Result<Self, IpcError> {
        let result = Self {
            execution_id,
            client_id,
            target,
            status,
            exit_code,
            stdout_summary,
            stderr_summary,
            truncated,
            evidence_refs,
            effect_state,
            is_untrusted_surface: true,
        };
        result.validate()?;
        Ok(result)
    }

    /// Whether this outcome is an untrusted observation surface.
    ///
    /// Always `true`; provided so call sites read intent, not a field.
    #[must_use]
    pub fn is_untrusted_surface(&self) -> bool {
        self.is_untrusted_surface
    }

    /// Whether this outcome needs reconciliation (`effect_state == Unknown`).
    ///
    /// A `true` result must go through [`ExecutionService::reconcile`] and
    /// [`ExecutionService::resolve`]; it must never be blind-retried.
    #[must_use]
    pub fn needs_reconciliation(&self) -> bool {
        self.effect_state.is_unknown()
    }

    /// Validate the outcome against its budgets (fail-closed).
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when the client identity is empty, a summary or
    ///   ref contains NUL, a ref is empty, the target violates the host
    ///   grammar, the trust label is not set, the `Unknown` agreement is
    ///   broken, or an `Unknown` outcome carries an exit code.
    /// - `LimitExceeded` when the client identity, a summary, the target,
    ///   or the ref list exceeds budget.
    pub fn validate(&self) -> Result<(), IpcError> {
        if self.client_id.is_empty() {
            return Err(IpcError::InvalidRequest {
                reason: "execution client_id must not be empty".into(),
            });
        }
        if self.client_id.len() > MAX_EXEC_CLIENT_ID_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "execution client_id".into(),
                limit: MAX_EXEC_CLIENT_ID_BYTES,
                actual: self.client_id.len(),
            });
        }
        if !self.is_untrusted_surface {
            return Err(IpcError::InvalidRequest {
                reason: "execution outcomes must be labeled is_untrusted_surface".into(),
            });
        }
        if self.stdout_summary.len() > MAX_EXEC_STREAM_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "stdout".into(),
                limit: MAX_EXEC_STREAM_BYTES,
                actual: self.stdout_summary.len(),
            });
        }
        if self.stderr_summary.len() > MAX_EXEC_STREAM_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "stderr".into(),
                limit: MAX_EXEC_STREAM_BYTES,
                actual: self.stderr_summary.len(),
            });
        }
        if self.stdout_summary.contains('\0') || self.stderr_summary.contains('\0') {
            return Err(IpcError::InvalidRequest {
                reason: "execution output must not contain NUL".into(),
            });
        }
        validate_evidence_refs(&self.evidence_refs)?;
        if let Some(target) = &self.target {
            if target.len() > MAX_EXEC_TARGET_BYTES {
                return Err(IpcError::LimitExceeded {
                    field: "execution target".into(),
                    limit: MAX_EXEC_TARGET_BYTES,
                    actual: target.len(),
                });
            }
            crate::ctl::parse_terminal_id(target).map(|_| ())?;
        }
        validate_unknown_agreement(self.status, self.effect_state, self.exit_code.is_some())?;
        Ok(())
    }
}

// ── bounding helpers ────────────────────────────────────────────────────────

/// Truncate `text` to `budget` bytes at a char boundary.
///
/// Returns the bounded text plus whether truncation occurred. A zero budget
/// yields empty text with `truncated` set when the input is non-empty.
fn truncate_to_budget(text: &str, budget: usize) -> (String, bool) {
    if text.len() <= budget {
        return (text.to_owned(), false);
    }
    let mut end = budget;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), true)
}

// ── host service ────────────────────────────────────────────────────────────

/// Host-side provider for supervised execution.
///
/// Receives the validated request and returns raw output; the service
/// enforces stream budgets, the `Unknown` agreement, target match, and
/// trust labeling. Providers are pure `fn` pointers so the service stays
/// dependency-free, mirroring the snapshot and tool-dispatch services.
/// Providers perform no network I/O and spawn nothing outside host
/// supervision; this slice is headless, so providers are test doubles and
/// real process wiring is sequel work.
pub type ExecutionProvider = fn(&ExecutionRequest) -> Result<RawExecutionOutput, IpcError>;

/// Default headless provider: empty successful completion.
///
/// Used by [`ExecutionService::new`] so gating, validation, and
/// reconciliation paths stay testable without a custom provider.
fn default_provider(request: &ExecutionRequest) -> Result<RawExecutionOutput, IpcError> {
    Ok(RawExecutionOutput {
        target_id: request.target.clone(),
        status: ExecutionStatus::Completed,
        exit_code: Some(0),
        stdout: String::new(),
        stderr: String::new(),
        evidence_refs: Vec::new(),
        effect_state: EffectState::Completed,
    })
}

/// Generic supervised-execution backend (the ExecutionContext host service).
///
/// Dispatch composes validation + authorization + consent + explicit effect
/// opt-in + captured target + budget + attribution + outcome on every call;
/// any refusal leaves no partial state (FS-IP1 transactional denial). Every
/// stored outcome is queryable through [`ExecutionService::reconcile`], and
/// `Unknown` entries close only through [`ExecutionService::resolve`].
/// There is no retry primitive: re-dispatch under a tracked id fails as
/// `InvalidRequest`; a new id is an explicit, separately-attributed
/// re-execution (callers must reconcile `Unknown` before re-executing).
#[derive(Debug)]
pub struct ExecutionService {
    /// Host execution provider (pure `fn`, dependency-free).
    provider: ExecutionProvider,
    /// Stored outcomes keyed by `execution_id`, bounded at
    /// [`MAX_TRACKED_EXECUTIONS`].
    results: BTreeMap<u64, ExecutionResult>,
}

impl ExecutionService {
    /// Service with the default headless provider and an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            provider: default_provider,
            results: BTreeMap::new(),
        }
    }

    /// Service with a custom host provider and an empty registry.
    #[must_use]
    pub fn with_provider(provider: ExecutionProvider) -> Self {
        Self {
            provider,
            results: BTreeMap::new(),
        }
    }

    /// Number of stored outcomes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Whether no outcome is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Whether `execution_id` has a stored outcome.
    #[must_use]
    pub fn contains(&self, execution_id: u64) -> bool {
        self.results.contains_key(&execution_id)
    }

    /// Serve one bounded supervised execution (fail-closed, no partial state).
    ///
    /// Validates the request shape, rejects re-dispatch under a tracked id
    /// and registry overflow, authorizes `process.spawn` against the
    /// server-evaluated `granted` scopes, requires the explicit effect
    /// opt-in plus an active `(client_id, process.spawn)` consent grant,
    /// then bounds provider output to the effective stream budget with
    /// `is_untrusted_surface` labeling and stores the attributed outcome.
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when the request shape is malformed, the client
    ///   identity is empty, the id is already tracked, the provider echoes
    ///   a different target than captured, or the bounded outcome violates
    ///   the `Unknown` agreement.
    /// - `LimitExceeded` when the registry is at capacity or any field
    ///   exceeds its accepted budget.
    /// - `ScopeDenied` when `granted` lacks `process.spawn`.
    /// - `Denied[EffectRequiresExplicitConsent]` when `allow_effects` is
    ///   not set (execution is always effectful).
    /// - `Denied[ConsentRequired]` when the consent ledger lacks an active
    ///   `(client_id, process.spawn)` grant at `now_ms`.
    pub fn dispatch(
        &mut self,
        request: &ExecutionRequest,
        granted: &ScopeSet,
        consent: &ConsentLedger,
        client_id: &str,
        now_ms: u64,
        execution_id: u64,
    ) -> Result<ExecutionResult, IpcError> {
        request.validate()?;
        if client_id.is_empty() {
            return Err(IpcError::InvalidRequest {
                reason: "execution client_id must not be empty".into(),
            });
        }
        if client_id.len() > MAX_EXEC_CLIENT_ID_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "execution client_id".into(),
                limit: MAX_EXEC_CLIENT_ID_BYTES,
                actual: client_id.len(),
            });
        }
        if self.results.contains_key(&execution_id) {
            return Err(IpcError::InvalidRequest {
                reason: format!(
                    "execution id {execution_id} is already tracked (reconcile, never blind-retry)"
                ),
            });
        }
        if self.results.len() >= MAX_TRACKED_EXECUTIONS {
            return Err(IpcError::LimitExceeded {
                field: "tracked executions".into(),
                limit: MAX_TRACKED_EXECUTIONS,
                actual: self.results.len() + 1,
            });
        }
        if !granted.contains(EXECUTION_SCOPE) {
            return Err(IpcError::ScopeDenied {
                scope: EXECUTION_SCOPE.as_str().into(),
                action: "exec".into(),
            });
        }
        if !request.allow_effects {
            return Err(IpcError::Denied {
                code: "EffectRequiresExplicitConsent".into(),
                reason: "supervised execution requires explicit allow_effects".into(),
            });
        }
        if !consent.is_granted(client_id, EXECUTION_SCOPE, now_ms) {
            return Err(IpcError::Denied {
                code: "ConsentRequired".into(),
                reason: format!(
                    "missing consent for exec on scope '{}'",
                    EXECUTION_SCOPE.as_str()
                ),
            });
        }
        let output = (self.provider)(request)?;
        if output.target_id != request.target {
            return Err(IpcError::InvalidRequest {
                reason: format!(
                    "execution provider returned target '{}', want '{}'",
                    output.target_id.as_deref().unwrap_or("<none>"),
                    request.target.as_deref().unwrap_or("<none>")
                ),
            });
        }
        let budget = request.effective_stream_budget();
        let (stdout_summary, stdout_truncated) = truncate_to_budget(&output.stdout, budget);
        let (stderr_summary, stderr_truncated) = truncate_to_budget(&output.stderr, budget);
        let bounded = RawExecutionOutput {
            stdout: stdout_summary,
            stderr: stderr_summary,
            ..output
        };
        bounded.validate()?;
        let result = ExecutionResult {
            execution_id,
            client_id: client_id.to_owned(),
            target: request.target.clone(),
            status: bounded.status,
            exit_code: bounded.exit_code,
            stdout_summary: bounded.stdout,
            stderr_summary: bounded.stderr,
            truncated: stdout_truncated || stderr_truncated,
            evidence_refs: bounded.evidence_refs,
            effect_state: bounded.effect_state,
            is_untrusted_surface: true,
        };
        result.validate()?;
        self.results.insert(execution_id, result.clone());
        Ok(result)
    }

    /// Reconcile one tracked execution: return its latest stored outcome.
    ///
    /// This is the only query path for `Unknown` outcomes. It never
    /// re-executes and never mutates state.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` when `execution_id` has no stored outcome.
    pub fn reconcile(&self, execution_id: u64) -> Result<ExecutionResult, IpcError> {
        self.results
            .get(&execution_id)
            .cloned()
            .ok_or_else(|| IpcError::NotFound {
                reason: format!("unknown execution id {execution_id}"),
            })
    }

    /// Resolve an `Unknown` entry into a terminal outcome.
    ///
    /// # Errors
    ///
    /// - `NotFound` when `execution_id` has no stored outcome.
    /// - `InvalidRequest` when the stored outcome is already terminal
    ///   (no silent overwrite), when `result` carries a different
    ///   `execution_id`, when `result` rewrites the stored `client_id` or
    ///   `target` attribution, or when `result` is itself `Unknown`
    ///   (resolution must terminate; further evidence arrives as another
    ///   `resolve`).
    pub fn resolve(&mut self, execution_id: u64, result: ExecutionResult) -> Result<(), IpcError> {
        let stored = self
            .results
            .get(&execution_id)
            .ok_or_else(|| IpcError::NotFound {
                reason: format!("unknown execution id {execution_id}"),
            })?;
        if !stored.needs_reconciliation() {
            return Err(IpcError::InvalidRequest {
                reason: format!("execution id {execution_id} is already terminal"),
            });
        }
        if result.execution_id != execution_id {
            return Err(IpcError::InvalidRequest {
                reason: format!(
                    "resolution carries id {}, want {execution_id}",
                    result.execution_id
                ),
            });
        }
        if result.client_id != stored.client_id || result.target != stored.target {
            return Err(IpcError::InvalidRequest {
                reason: "resolution must preserve client_id and target".into(),
            });
        }
        if result.needs_reconciliation() {
            return Err(IpcError::InvalidRequest {
                reason: "resolution must be terminal, not Unknown".into(),
            });
        }
        result.validate()?;
        self.results.insert(execution_id, result);
        Ok(())
    }
}

impl Default for ExecutionService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn granted_spawn() -> ScopeSet {
        let mut set = ScopeSet::new();
        set.insert(Scope::ProcessSpawn);
        set
    }

    fn consented(now_ms: u64) -> ConsentLedger {
        let mut ledger = ConsentLedger::new();
        ledger
            .grant(
                "agent-0442".to_owned(),
                Scope::ProcessSpawn,
                now_ms,
                60_000,
                "test".to_owned(),
            )
            .expect("grant");
        ledger
    }

    fn allowed_request() -> ExecutionRequest {
        ExecutionRequest::new("git", vec!["diff".to_owned()]).with_allow_effects(true)
    }

    fn dispatch_now(
        service: &mut ExecutionService,
        request: &ExecutionRequest,
        id: u64,
    ) -> Result<ExecutionResult, IpcError> {
        service.dispatch(
            request,
            &granted_spawn(),
            &consented(1_000),
            "agent-0442",
            1_000,
            id,
        )
    }

    #[test]
    fn budgets_match_accepted_bounds() {
        assert_eq!(MAX_EXECUTABLE_BYTES, crate::ctl::MAX_CTL_CWD_LEN);
        assert_eq!(MAX_EXEC_ARGS, crate::devtools::MAX_INPUT_RING);
        assert_eq!(MAX_EXEC_ARG_BYTES, crate::ctl::MAX_CTL_PARAMS_BYTES);
        assert_eq!(
            MAX_EXEC_ARGS_TOTAL_BYTES,
            crate::tool_dispatch::MAX_TOOL_ARGS_BYTES
        );
        assert_eq!(MAX_EXEC_CWD_BYTES, crate::ctl::MAX_CTL_CWD_LEN);
        assert_eq!(MAX_EXEC_ENV_VARS, crate::devtools::MAX_INPUT_RING);
        assert_eq!(MAX_EXEC_ENV_NAME_BYTES, bitty_ipc_auth::auth::MAX_SCOPED_ID_BYTES);
        assert_eq!(MAX_EXEC_ENV_VALUE_BYTES, crate::ctl::MAX_CTL_CWD_LEN);
        assert_eq!(
            DEFAULT_EXEC_TIMEOUT_MS,
            bitty_ipc_api::channel::DEFAULT_REQUEST_TIMEOUT_MS
        );
        assert_eq!(MAX_EXEC_TIMEOUT_MS, bitty_ipc_api::channel::MAX_REQUEST_TIMEOUT_MS);
        assert_eq!(
            MAX_EXEC_OUTPUT_BUDGET_BYTES,
            bitty_ipc_core::limits::RC10_MAX_SNAPSHOT_BYTES
        );
        assert_eq!(
            MAX_EXEC_STREAM_BYTES,
            crate::tool_dispatch::MAX_TOOL_RESULT_BYTES
        );
        assert_eq!(
            MAX_EXEC_EVIDENCE_REF_BYTES,
            crate::tool_dispatch::MAX_TOOL_SUMMARY_BYTES
        );
        assert_eq!(MAX_EXEC_TARGET_BYTES, bitty_ipc_auth::auth::MAX_SCOPED_ID_BYTES);
        assert_eq!(MAX_EXEC_CLIENT_ID_BYTES, bitty_ipc_auth::auth::MAX_SCOPED_ID_BYTES);
        assert_eq!(MAX_TRACKED_EXECUTIONS, bitty_ipc_api::channel::MAX_PENDING_REQUESTS);
        assert_eq!(EXECUTION_SCOPE, Scope::ProcessSpawn);
    }

    #[test]
    fn status_and_effect_vocabulary_is_closed() {
        assert!("completed".parse::<ExecutionStatus>() == Ok(ExecutionStatus::Completed));
        assert!("failed".parse::<ExecutionStatus>() == Ok(ExecutionStatus::Failed));
        assert!("canceled".parse::<ExecutionStatus>() == Ok(ExecutionStatus::Canceled));
        assert!("unknown".parse::<ExecutionStatus>() == Ok(ExecutionStatus::Unknown));
        assert!("running".parse::<ExecutionStatus>().is_err());
        assert!("completed".parse::<EffectState>() == Ok(EffectState::Completed));
        assert!("unknown".parse::<EffectState>() == Ok(EffectState::Unknown));
        assert!("pending".parse::<EffectState>().is_err());
        assert_eq!(ExecutionStatus::Unknown.as_str(), "unknown");
        assert_eq!(EffectState::Failed.as_str(), "failed");
        assert!(EffectState::Unknown.is_unknown());
        assert!(!EffectState::Completed.is_unknown());
    }

    #[test]
    fn env_policy_is_closed_and_bounded() {
        assert!(EnvPolicy::Isolated.is_isolated());
        assert!(EnvPolicy::Isolated.is_empty());
        let policy =
            EnvPolicy::explicit(vec![("GIT_PAGER".to_owned(), "cat".to_owned())]).expect("valid");
        assert!(!policy.is_isolated());
        assert_eq!(policy.len(), 1);
        assert!(policy.validate().is_ok());
        let too_many: Vec<(String, String)> = (0..(MAX_EXEC_ENV_VARS + 1))
            .map(|i| (format!("VAR_{i}"), "x".to_owned()))
            .collect();
        assert!(matches!(
            EnvPolicy::explicit(too_many),
            Err(IpcError::LimitExceeded { .. })
        ));
        assert!(EnvVar::new("1BAD", "x").is_err());
        assert!(EnvVar::new("GOOD_NAME_1", "x").is_ok());
        assert!(EnvVar::new("", "x").is_err());
        assert!(EnvVar::new("BAD-NAME", "x").is_err());
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let text = "é".repeat(100);
        let (bounded, truncated) = truncate_to_budget(&text, MAX_EXEC_STREAM_BYTES);
        assert!(bounded.len() <= MAX_EXEC_STREAM_BYTES);
        assert!(!truncated);
        let (cut, truncated) = truncate_to_budget(&text, 7);
        assert!(truncated);
        assert!(cut.len() <= 7);
        assert!(text.starts_with(cut.as_str()));
    }

    #[test]
    fn effective_budget_is_min_of_stream_ceiling_and_caller_budget() {
        let request = ExecutionRequest::new("git", Vec::new()).with_output_budget(64);
        assert_eq!(request.effective_stream_budget(), 64);
        let request = ExecutionRequest::new("git", Vec::new());
        assert_eq!(request.effective_stream_budget(), MAX_EXEC_STREAM_BYTES);
        let request = ExecutionRequest::new("git", Vec::new()).with_output_budget(512 * 1024);
        assert_eq!(request.effective_stream_budget(), MAX_EXEC_STREAM_BYTES);
    }

    #[test]
    fn zero_or_over_ceiling_output_budget_is_rejected() {
        let request = ExecutionRequest::new("git", Vec::new()).with_output_budget(0);
        assert!(matches!(
            request.validate(),
            Err(IpcError::InvalidRequest { .. })
        ));
        let request = ExecutionRequest::new("git", Vec::new())
            .with_output_budget(MAX_EXEC_OUTPUT_BUDGET_BYTES + 1);
        assert!(matches!(
            request.validate(),
            Err(IpcError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn timeout_bounds_reject_zero_and_over_ceiling() {
        let request = ExecutionRequest::new("git", Vec::new()).with_timeout_ms(0);
        assert!(matches!(
            request.validate(),
            Err(IpcError::InvalidRequest { .. })
        ));
        let request = ExecutionRequest::new("git", Vec::new()).with_timeout_ms(u64::MAX);
        assert!(matches!(
            request.validate(),
            Err(IpcError::LimitExceeded { .. })
        ));
        let request = ExecutionRequest::new("git", Vec::new()).with_timeout_ms(MAX_EXEC_TIMEOUT_MS);
        assert!(request.validate().is_ok());
    }

    #[test]
    fn executable_and_arg_shapes_are_rejected() {
        let request = ExecutionRequest::new("", Vec::new());
        assert!(request.validate().is_err());
        let request = ExecutionRequest::new("x".repeat(MAX_EXECUTABLE_BYTES + 1), Vec::new());
        assert!(matches!(
            request.validate(),
            Err(IpcError::LimitExceeded { .. })
        ));
        let request = ExecutionRequest::new("git", vec!["a".repeat(MAX_EXEC_ARG_BYTES + 1)]);
        assert!(matches!(
            request.validate(),
            Err(IpcError::LimitExceeded { .. })
        ));
        let many = vec!["x".to_owned(); MAX_EXEC_ARGS + 1];
        let request = ExecutionRequest::new("git", many);
        assert!(matches!(
            request.validate(),
            Err(IpcError::LimitExceeded { .. })
        ));
        let request = ExecutionRequest::new("gi\0t", Vec::new());
        assert!(matches!(
            request.validate(),
            Err(IpcError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn unknown_agreement_is_enforced() {
        let mismatched = ExecutionResult::new(
            1,
            "agent-0442".to_owned(),
            None,
            ExecutionStatus::Completed,
            Some(0),
            String::new(),
            String::new(),
            false,
            Vec::new(),
            EffectState::Unknown,
        );
        assert!(
            matches!(mismatched, Err(IpcError::InvalidRequest { .. })),
            "got {mismatched:?}"
        );
        let exit_with_unknown = ExecutionResult::new(
            1,
            "agent-0442".to_owned(),
            None,
            ExecutionStatus::Unknown,
            Some(1),
            String::new(),
            String::new(),
            false,
            Vec::new(),
            EffectState::Unknown,
        );
        assert!(
            matches!(exit_with_unknown, Err(IpcError::InvalidRequest { .. })),
            "got {exit_with_unknown:?}"
        );
        let unknown = ExecutionResult::new(
            1,
            "agent-0442".to_owned(),
            None,
            ExecutionStatus::Unknown,
            None,
            String::new(),
            String::new(),
            false,
            Vec::new(),
            EffectState::Unknown,
        )
        .expect("Unknown pair validates");
        assert!(unknown.needs_reconciliation());
    }

    #[test]
    fn untrusted_label_cannot_be_cleared() {
        let mut result = dispatch_now(&mut ExecutionService::new(), &allowed_request(), 11)
            .expect("default provider serves");
        assert!(result.is_untrusted_surface);
        result.is_untrusted_surface = false;
        assert!(result.validate().is_err());
    }

    #[test]
    fn duplicate_execution_id_is_rejected_before_capacity() {
        let mut service = ExecutionService::new();
        dispatch_now(&mut service, &allowed_request(), 21).expect("first serves");
        let error =
            dispatch_now(&mut service, &allowed_request(), 21).expect_err("duplicate id must fail");
        assert!(
            matches!(error, IpcError::InvalidRequest { .. }),
            "got {error:?}"
        );
    }

    #[test]
    fn registry_overflow_fails_closed() {
        let mut service = ExecutionService::new();
        for id in 0..(MAX_TRACKED_EXECUTIONS as u64) {
            dispatch_now(&mut service, &allowed_request(), id).expect("capacity");
        }
        let error = dispatch_now(
            &mut service,
            &allowed_request(),
            MAX_TRACKED_EXECUTIONS as u64,
        )
        .expect_err("overflow must fail");
        assert!(
            matches!(error, IpcError::LimitExceeded { .. }),
            "got {error:?}"
        );
    }

    #[test]
    fn resolve_rejects_terminal_and_unknown_targets() {
        let mut service = ExecutionService::new();
        assert!(matches!(
            service.resolve(
                99,
                ExecutionResult::new(
                    99,
                    "agent-0442".to_owned(),
                    None,
                    ExecutionStatus::Completed,
                    Some(0),
                    String::new(),
                    String::new(),
                    false,
                    Vec::new(),
                    EffectState::Completed,
                )
                .expect("valid"),
            ),
            Err(IpcError::NotFound { .. })
        ));
        dispatch_now(&mut service, &allowed_request(), 31).expect("serves");
        let terminal = service.reconcile(31).expect("stored");
        assert!(!terminal.needs_reconciliation());
        assert!(matches!(
            service.resolve(31, terminal),
            Err(IpcError::InvalidRequest { .. })
        ));
        assert!(matches!(
            service.reconcile(u64::MAX),
            Err(IpcError::NotFound { .. })
        ));
    }
}
