//! Host-registered bounded `terminal.snapshot` read service (CTX-0420, G-2).
//!
//! The generic scope registry maps `terminal.snapshot` to `terminal.inspect`
//! (`crate::scope::required_scope_for_method`) but no host dispatcher
//! registers a handler, so every out-of-process context read fails closed.
//! This module closes that gap with a host-registered, zone-scoped, bounded
//! read service under the existing generic scopes. Panel-context reads ride
//! the same DTO: a panel hosts terminals, so the caller names the panel's
//! terminal (`t:<digits>`) and optionally narrows to one semantic zone.
//! A `panel.context` wire method does not exist in the generic registry, so
//! it stays fail-closed (`NotFound`), exactly as the `bitty-ai` pressure
//! test proves (read-only reference: `bitty-ai` PR #7, `IpcBridge` +
//! `collect_terminal_context` with a loopback peer).
//!
//! # DTO contract (DIR-018)
//!
//! [`TerminalSnapshot`] carries exactly the bounded DIR-018 field list:
//! `terminal_id` / `generation` / `cwd` / `semantic_zones` / `text` /
//! `truncated` / `is_untrusted_surface`. Grid internals (cells, dimensions,
//! cursor, modes) never enter the DTO: the provider hands over plain text
//! plus zone metadata, and the service truncates both to budget.
//! `is_untrusted_surface` is always `true`: terminal bytes are
//! attacker-controlled observation data, never instructions (T-10 / R-013).
//!
//! # Budgets (accepted contracts, verified first-hand)
//!
//! Every number below reuses an accepted `bitty-ipc` bound; no value is
//! invented here:
//!
//! - Caller `max_bytes` ceiling: `1..=RC10_MAX_SNAPSHOT_BYTES`
//!   (`bitty_ipc_core::limits::RC10_MAX_SNAPSHOT_BYTES`, 256 KiB, same as
//!   `crate::frame::MAX_FRAME_BYTES`). Zero or over-ceiling ceilings are
//!   rejected fail-closed, never silently clamped.
//! - Detail budgets: `Minimal` = `MAX_PROF_DRAIN_BYTES` (8 KiB,
//!   `crate::devtools`, aggregate drain bound), `Standard` =
//!   `MAX_INSPECT_TEXT_BYTES` (16 KiB, grid-text bound), `Full` =
//!   `MAX_INSPECT_JSON_BYTES` (32 KiB, rendered-introspection bound).
//!   The effective text budget is `min(detail budget, max_bytes)`.
//! - `cwd`: `MAX_CTL_CWD_LEN` (4096, `crate::ctl`).
//! - `semantic_zones`: at most `MAX_INPUT_RING` entries (64, bounded-list
//!   cap); overflow drops oldest first with `truncated = true`, matching the
//!   zone-log and input-ring `DropOldest` precedent.
//! - `terminal_id`: host shape `t:<digits>` via `crate::ctl::parse_terminal_id`
//!   (1..=10 digits, no leading zeros); existence resolves server-side.
//! - Zone vocabulary: `prompt` | `input` | `command` | `output` (CP-9 zone
//!   kinds, case-insensitive on input, lowercase on the wire).
//!
//! The module is pure data, bounded, headless, and `forbid(unsafe)`: it owns
//! no socket, spawns no thread, performs no I/O, and depends on no workspace
//! crate beyond `bitty-ipc` itself. No network, no new external crates.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use bitty_ipc_api::error::IpcError;
use bitty_ipc_api::scope::{
    ScopeSet, authorize_method, required_scope_for_method, validate_method_name,
};

// ── method + budget constants (accepted-contract sources inline) ────────────

/// Generic wire method served by this module (`scope.rs` registry).
pub const SNAPSHOT_METHOD: &str = "terminal.snapshot";

/// Text budget for [`DetailLevel::Minimal`]: 8 KiB aggregate drain bound
/// (`devtools::MAX_PROF_DRAIN_BYTES`).
pub const MAX_SNAPSHOT_MINIMAL_BYTES: usize = crate::devtools::MAX_PROF_DRAIN_BYTES;

/// Text budget for [`DetailLevel::Standard`]: 16 KiB grid-text bound
/// (`devtools::MAX_INSPECT_TEXT_BYTES`).
pub const MAX_SNAPSHOT_STANDARD_BYTES: usize = crate::devtools::MAX_INSPECT_TEXT_BYTES;

/// Text budget for [`DetailLevel::Full`]: 32 KiB rendered-introspection bound
/// (`devtools::MAX_INSPECT_JSON_BYTES`). Absolute text ceiling.
pub const MAX_SNAPSHOT_FULL_BYTES: usize = crate::devtools::MAX_INSPECT_JSON_BYTES;

/// Maximum `cwd` bytes (`ctl::MAX_CTL_CWD_LEN`, 4096).
pub const MAX_SNAPSHOT_CWD_BYTES: usize = crate::ctl::MAX_CTL_CWD_LEN;

/// Maximum retained semantic zones per snapshot (bounded-list cap 64,
/// `devtools::MAX_INPUT_RING` precedent). Overflow drops oldest first.
pub const MAX_SNAPSHOT_ZONES: usize = crate::devtools::MAX_INPUT_RING;

// ── detail level ────────────────────────────────────────────────────────────

/// Caller-declared detail level resolving to an accepted byte budget.
///
/// Token-first profiling (OQ-066) stays open: these levels select a byte
/// ceiling only, and the 32 KiB `Full` ceiling remains a candidate profile,
/// not a core token contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetailLevel {
    /// Smallest zone-scoped read (8 KiB).
    Minimal,
    /// Default bounded scrape (16 KiB).
    Standard,
    /// Largest single-response read (32 KiB).
    Full,
}

impl DetailLevel {
    /// Stable wire label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Standard => "standard",
            Self::Full => "full",
        }
    }

    /// Accepted byte budget for this level.
    #[must_use]
    pub fn budget_bytes(self) -> usize {
        match self {
            Self::Minimal => MAX_SNAPSHOT_MINIMAL_BYTES,
            Self::Standard => MAX_SNAPSHOT_STANDARD_BYTES,
            Self::Full => MAX_SNAPSHOT_FULL_BYTES,
        }
    }
}

impl fmt::Display for DetailLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DetailLevel {
    type Err = IpcError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "minimal" => Ok(Self::Minimal),
            "standard" => Ok(Self::Standard),
            "full" => Ok(Self::Full),
            _ => Err(IpcError::InvalidRequest {
                reason: format!("unknown detail level '{s}' (want minimal|standard|full)"),
            }),
        }
    }
}

// ── semantic zones ──────────────────────────────────────────────────────────

/// Terminal semantic-zone kind (CP-9 vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZoneKind {
    /// Shell prompt mark (`OSC 133 A`).
    Prompt,
    /// Command-input mark (`OSC 133 B`).
    Input,
    /// Command-start mark (`OSC 133 C`).
    Command,
    /// Command-output mark (`OSC 133 D`).
    Output,
}

impl ZoneKind {
    /// Stable lowercase wire label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prompt => "prompt",
            Self::Input => "input",
            Self::Command => "command",
            Self::Output => "output",
        }
    }
}

impl fmt::Display for ZoneKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ZoneKind {
    type Err = IpcError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("prompt") {
            Ok(Self::Prompt)
        } else if s.eq_ignore_ascii_case("input") {
            Ok(Self::Input)
        } else if s.eq_ignore_ascii_case("command") {
            Ok(Self::Command)
        } else if s.eq_ignore_ascii_case("output") {
            Ok(Self::Output)
        } else {
            Err(IpcError::InvalidRequest {
                reason: format!("unknown semantic zone '{s}' (want prompt|input|command|output)"),
            })
        }
    }
}

/// One semantic-zone record contributing to a snapshot (metadata only).
///
/// Carries no cell, glyph, or grid data: kind plus the inclusive line span
/// that produced the zone's share of `text`. Line numbers anchor zone
/// boundaries (CP-8); they are not grid internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticZone {
    /// Which zone boundary this record marks.
    pub kind: ZoneKind,
    /// First line contributing to this zone.
    pub line_start: u32,
    /// Last line contributing to this zone (`>= line_start`).
    pub line_end: u32,
}

impl SemanticZone {
    /// Validate the record shape (fail-closed before it enters a DTO).
    ///
    /// # Errors
    ///
    /// Returns `InvalidRequest` when the line span is inverted.
    pub fn validate(&self) -> Result<(), IpcError> {
        if self.line_start > self.line_end {
            return Err(IpcError::InvalidRequest {
                reason: format!(
                    "semantic zone {} has inverted lines {}..={}",
                    self.kind, self.line_start, self.line_end
                ),
            });
        }
        Ok(())
    }
}

// ── request ─────────────────────────────────────────────────────────────────

/// Bounded read request for [`SNAPSHOT_METHOD`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRequest {
    /// Host terminal id (`t:<digits>`); existence resolves server-side.
    pub terminal_id: String,
    /// Optional single-zone narrowing (`None` serves all zones).
    pub zone: Option<ZoneKind>,
    /// Detail level selecting the accepted byte budget.
    pub detail: DetailLevel,
    /// Optional caller byte ceiling (`1..=RC10_MAX_SNAPSHOT_BYTES`).
    pub max_bytes: Option<usize>,
}

impl SnapshotRequest {
    /// Build a request for one terminal at a detail level.
    #[must_use]
    pub fn new(terminal_id: impl Into<String>, detail: DetailLevel) -> Self {
        Self {
            terminal_id: terminal_id.into(),
            zone: None,
            detail,
            max_bytes: None,
        }
    }

    /// Narrow the read to one semantic zone.
    #[must_use]
    pub fn with_zone(mut self, zone: ZoneKind) -> Self {
        self.zone = Some(zone);
        self
    }

    /// Set the caller byte ceiling.
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = Some(max_bytes);
        self
    }

    /// Effective text budget: `min(detail budget, max_bytes)`.
    #[must_use]
    pub fn effective_budget(&self) -> usize {
        match self.max_bytes {
            Some(max) => self.detail.budget_bytes().min(max),
            None => self.detail.budget_bytes(),
        }
    }

    /// Validate the request shape (fail-closed, no side effects).
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when `terminal_id` violates the host `t:<digits>`
    ///   grammar or `max_bytes` is zero.
    /// - `LimitExceeded` when `max_bytes` exceeds `RC10_MAX_SNAPSHOT_BYTES`.
    pub fn validate(&self) -> Result<(), IpcError> {
        crate::ctl::parse_terminal_id(&self.terminal_id).map(|_| ())?;
        if let Some(max) = self.max_bytes {
            if max == 0 {
                return Err(IpcError::InvalidRequest {
                    reason: "max_bytes must be non-zero".into(),
                });
            }
            if max > bitty_ipc_core::limits::RC10_MAX_SNAPSHOT_BYTES {
                return Err(IpcError::LimitExceeded {
                    field: "max_bytes".into(),
                    limit: bitty_ipc_core::limits::RC10_MAX_SNAPSHOT_BYTES,
                    actual: max,
                });
            }
        }
        Ok(())
    }
}

// ── provider output (unbounded input, bounded by the service) ───────────────

/// Raw terminal data supplied by the host provider (pre-bound output).
///
/// The provider reads live terminal state; the service enforces every bound
/// and always labels the result `is_untrusted_surface`. Providers never set
/// the trust label themselves, so a compromised provider cannot launder
/// terminal bytes into instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotData {
    /// Host terminal id (must match the request).
    pub terminal_id: String,
    /// Damage generation the data corresponds to.
    pub generation: u64,
    /// Working-directory report (`OSC 7`), may be empty.
    pub cwd: String,
    /// Zone records oldest first (capped at [`MAX_SNAPSHOT_ZONES`]).
    pub semantic_zones: Vec<SemanticZone>,
    /// Zone text (truncated to the effective budget at a char boundary).
    pub text: String,
}

// ── DTO (DIR-018 bounded field list) ────────────────────────────────────────

/// Bounded terminal snapshot (DIR-018 field list, never grid internals).
///
/// Exactly seven fields: `terminal_id` / `generation` / `cwd` /
/// `semantic_zones` / `text` / `truncated` / `is_untrusted_surface`.
/// `is_untrusted_surface` is always `true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalSnapshot {
    /// Host terminal id (`t:<digits>`).
    pub terminal_id: String,
    /// Damage generation the snapshot corresponds to.
    pub generation: u64,
    /// Working-directory report, bounded at [`MAX_SNAPSHOT_CWD_BYTES`].
    pub cwd: String,
    /// Zone records, bounded at [`MAX_SNAPSHOT_ZONES`] (newest kept).
    pub semantic_zones: Vec<SemanticZone>,
    /// Bounded zone text (char-boundary truncated).
    pub text: String,
    /// True when any field was truncated to fit its budget.
    pub truncated: bool,
    /// Always `true`: terminal bytes are untrusted observation data (T-10).
    pub is_untrusted_surface: bool,
}

impl TerminalSnapshot {
    /// Whether this snapshot is an untrusted observation surface.
    ///
    /// Always `true`; provided so call sites read intent, not a field.
    #[must_use]
    pub fn is_untrusted_surface(&self) -> bool {
        self.is_untrusted_surface
    }

    /// Validate the DTO against its budgets (fail-closed).
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when `terminal_id` violates the host grammar, a
    ///   zone span is inverted, or the trust label is not set.
    /// - `LimitExceeded` when `text`, `cwd`, or the zone count exceeds budget.
    pub fn validate(&self) -> Result<(), IpcError> {
        crate::ctl::parse_terminal_id(&self.terminal_id).map(|_| ())?;
        if !self.is_untrusted_surface {
            return Err(IpcError::InvalidRequest {
                reason: "terminal snapshots must be labeled is_untrusted_surface".into(),
            });
        }
        if self.text.len() > MAX_SNAPSHOT_FULL_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "text".into(),
                limit: MAX_SNAPSHOT_FULL_BYTES,
                actual: self.text.len(),
            });
        }
        if self.cwd.len() > MAX_SNAPSHOT_CWD_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "cwd".into(),
                limit: MAX_SNAPSHOT_CWD_BYTES,
                actual: self.cwd.len(),
            });
        }
        if self.semantic_zones.len() > MAX_SNAPSHOT_ZONES {
            return Err(IpcError::LimitExceeded {
                field: "semantic_zones".into(),
                limit: MAX_SNAPSHOT_ZONES,
                actual: self.semantic_zones.len(),
            });
        }
        for zone in &self.semantic_zones {
            zone.validate()?;
        }
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

/// Apply the request budgets to raw provider data (pure, deterministic).
fn bound_snapshot(request: &SnapshotRequest, data: SnapshotData) -> TerminalSnapshot {
    let budget = request.effective_budget();
    let (text, text_truncated) = truncate_to_budget(&data.text, budget);
    let (cwd, cwd_truncated) = truncate_to_budget(&data.cwd, MAX_SNAPSHOT_CWD_BYTES);
    let zones_truncated = data.semantic_zones.len() > MAX_SNAPSHOT_ZONES;
    let semantic_zones = if zones_truncated {
        data.semantic_zones[data.semantic_zones.len() - MAX_SNAPSHOT_ZONES..].to_vec()
    } else {
        data.semantic_zones
    };
    // Zone narrowing serves only the requested zone's metadata; text stays
    // the provider-scoped bytes (the provider owns zone filtering of bytes).
    let semantic_zones = match request.zone {
        Some(kind) => semantic_zones
            .into_iter()
            .filter(|zone| zone.kind == kind)
            .collect(),
        None => semantic_zones,
    };
    TerminalSnapshot {
        terminal_id: request.terminal_id.clone(),
        generation: data.generation,
        cwd,
        semantic_zones,
        text,
        truncated: text_truncated || cwd_truncated || zones_truncated,
        is_untrusted_surface: true,
    }
}

// ── host dispatcher ─────────────────────────────────────────────────────────

/// Host-side provider for one generic snapshot method.
///
/// Receives the validated request and returns raw terminal data; the service
/// enforces budgets and trust labeling. Providers are pure `fn` pointers so
/// the table stays dependency-free, mirroring the DevTools dispatcher.
pub type SnapshotProvider = fn(&SnapshotRequest) -> Result<SnapshotData, IpcError>;

/// Host-registered read service for generic snapshot methods.
///
/// The table maps generic wire methods (e.g. [`SNAPSHOT_METHOD`]) to host
/// providers. Dispatch authorizes via the server-evaluated [`ScopeSet`]
/// on every request; unknown methods, missing scopes, and missing handlers
/// all fail closed with no partial state (FS-IP1 transactional denial).
#[derive(Debug, Default)]
pub struct SnapshotService {
    /// Method name to provider, keyed by full generic method name.
    handlers: BTreeMap<&'static str, SnapshotProvider>,
}

impl SnapshotService {
    /// Empty service: every dispatch fails closed until a handler registers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: BTreeMap::new(),
        }
    }

    /// Service with the bounded [`SNAPSHOT_METHOD`] handler registered.
    ///
    /// Method names are statically valid, so a registration failure here is
    /// a programming error surfaced loudly rather than a silent partial
    /// table.
    #[must_use]
    pub fn with_defaults(provider: SnapshotProvider) -> Self {
        let mut service = Self::new();
        if service.register(SNAPSHOT_METHOD, provider).is_err() {
            debug_assert!(false, "statically valid snapshot method rejected");
        }
        service
    }

    /// Register a provider for a generic method.
    ///
    /// # Errors
    ///
    /// - `InvalidMethod` when `method` violates the wire grammar.
    /// - `NotFound` when `method` has no required scope in the generic
    ///   registry (e.g. `panel.context`): only methods under existing
    ///   generic scopes can register.
    pub fn register(
        &mut self,
        method: &'static str,
        provider: SnapshotProvider,
    ) -> Result<(), IpcError> {
        validate_method_name(method)?;
        if required_scope_for_method(method).is_none() {
            return Err(IpcError::NotFound {
                reason: format!("unknown snapshot method '{method}'"),
            });
        }
        self.handlers.insert(method, provider);
        Ok(())
    }

    /// Whether `method` has a registered provider.
    #[must_use]
    pub fn contains(&self, method: &str) -> bool {
        self.handlers.contains_key(method)
    }

    /// Number of registered methods.
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.handlers.len()
    }

    /// Serve one bounded snapshot request (fail-closed, no partial state).
    ///
    /// Validates the method grammar and request shape, authorizes against
    /// the server-evaluated `granted` scopes, then bounds provider data to
    /// the request budgets with `is_untrusted_surface` labeling.
    ///
    /// # Errors
    ///
    /// - `InvalidMethod` when `method` violates the wire grammar.
    /// - `NotFound` when `method` is unknown to the generic registry or has
    ///   no registered host provider.
    /// - `ScopeDenied` when `granted` lacks the required scope.
    /// - `InvalidRequest` / `LimitExceeded` when the request shape or the
    ///   bounded DTO violates a budget, or when the provider returns data
    ///   for a different terminal than requested.
    pub fn dispatch(
        &self,
        method: &str,
        request: &SnapshotRequest,
        granted: &ScopeSet,
    ) -> Result<TerminalSnapshot, IpcError> {
        validate_method_name(method)?;
        if required_scope_for_method(method).is_none() {
            return Err(IpcError::NotFound {
                reason: format!("unknown snapshot method '{method}'"),
            });
        }
        request.validate()?;
        authorize_method(method, granted)?;
        let provider = self
            .handlers
            .get(method)
            .ok_or_else(|| IpcError::NotFound {
                reason: format!("no host provider for '{method}'"),
            })?;
        let data = provider(request)?;
        if data.terminal_id != request.terminal_id {
            return Err(IpcError::InvalidRequest {
                reason: format!(
                    "snapshot provider returned '{}', want '{}'",
                    data.terminal_id, request.terminal_id
                ),
            });
        }
        let snapshot = bound_snapshot(request, data);
        snapshot.validate()?;
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitty_ipc_api::scope::Scope;

    fn canned(request: &SnapshotRequest) -> Result<SnapshotData, IpcError> {
        Ok(SnapshotData {
            terminal_id: request.terminal_id.clone(),
            generation: 3,
            cwd: "/work".to_owned(),
            semantic_zones: vec![SemanticZone {
                kind: ZoneKind::Output,
                line_start: 0,
                line_end: 2,
            }],
            text: "hello".to_owned(),
        })
    }

    fn granted() -> ScopeSet {
        ScopeSet::single(Scope::TerminalInspect)
    }

    #[test]
    fn detail_budgets_match_accepted_bounds() {
        assert_eq!(
            DetailLevel::Minimal.budget_bytes(),
            crate::devtools::MAX_PROF_DRAIN_BYTES
        );
        assert_eq!(
            DetailLevel::Standard.budget_bytes(),
            crate::devtools::MAX_INSPECT_TEXT_BYTES
        );
        assert_eq!(
            DetailLevel::Full.budget_bytes(),
            crate::devtools::MAX_INSPECT_JSON_BYTES
        );
        assert!("minimal".parse::<DetailLevel>() == Ok(DetailLevel::Minimal));
        assert!("standard".parse::<DetailLevel>() == Ok(DetailLevel::Standard));
        assert!("full".parse::<DetailLevel>() == Ok(DetailLevel::Full));
        assert!("raw".parse::<DetailLevel>().is_err());
    }

    #[test]
    fn zone_vocabulary_is_case_insensitive() {
        assert!("Output".parse::<ZoneKind>() == Ok(ZoneKind::Output));
        assert!("COMMAND".parse::<ZoneKind>() == Ok(ZoneKind::Command));
        assert!("scrollback".parse::<ZoneKind>().is_err());
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let text = "é".repeat(100);
        let (bounded, truncated) = truncate_to_budget(&text, 8 * 1024);
        assert!(bounded.len() <= 8 * 1024);
        assert!(text.starts_with(bounded.as_str()));
        assert!(!truncated, "in-budget text must not flag truncation");
        let (cut, truncated) = truncate_to_budget(&text, 7);
        assert!(truncated);
        assert!(cut.len() <= 7);
        assert!(
            text.starts_with(cut.as_str()),
            "must cut at a char boundary"
        );
    }

    #[test]
    fn effective_budget_is_min_of_detail_and_caller_ceiling() {
        let request = SnapshotRequest::new("t:1", DetailLevel::Full).with_max_bytes(1024);
        assert_eq!(request.effective_budget(), 1024);
        let request = SnapshotRequest::new("t:1", DetailLevel::Minimal);
        assert_eq!(request.effective_budget(), 8 * 1024);
    }

    #[test]
    fn zero_or_over_ceiling_max_bytes_is_rejected() {
        let request = SnapshotRequest::new("t:1", DetailLevel::Standard).with_max_bytes(0);
        assert!(matches!(
            request.validate(),
            Err(IpcError::InvalidRequest { .. })
        ));
        let request = SnapshotRequest::new("t:1", DetailLevel::Standard)
            .with_max_bytes(bitty_ipc_core::limits::RC10_MAX_SNAPSHOT_BYTES + 1);
        assert!(matches!(
            request.validate(),
            Err(IpcError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn inverted_zone_span_is_rejected() {
        let zone = SemanticZone {
            kind: ZoneKind::Input,
            line_start: 5,
            line_end: 2,
        };
        assert!(zone.validate().is_err());
    }

    #[test]
    fn zone_narrowing_filters_metadata() {
        let service = SnapshotService::with_defaults(canned);
        let request =
            SnapshotRequest::new("t:2", DetailLevel::Standard).with_zone(ZoneKind::Prompt);
        let snapshot = service
            .dispatch(SNAPSHOT_METHOD, &request, &granted())
            .expect("registered handler serves");
        assert!(snapshot.semantic_zones.is_empty());
        assert!(snapshot.is_untrusted_surface);
    }

    #[test]
    fn untrusted_label_cannot_be_cleared() {
        let mut snapshot = bound_snapshot(
            &SnapshotRequest::new("t:1", DetailLevel::Standard),
            SnapshotData {
                terminal_id: "t:1".to_owned(),
                generation: 1,
                cwd: String::new(),
                semantic_zones: Vec::new(),
                text: "hi".to_owned(),
            },
        );
        assert!(snapshot.is_untrusted_surface);
        snapshot.is_untrusted_surface = false;
        assert!(snapshot.validate().is_err());
    }
}
