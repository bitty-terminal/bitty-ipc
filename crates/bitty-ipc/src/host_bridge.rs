//! Generic host bridge layer: live providers for the Phase-A pure services
//! (CTX-0439, G-5).
//!
//! The Phase-A services ([`SnapshotService`](crate::snapshot::SnapshotService),
//! [`ToolDispatchService`](crate::tool_dispatch::ToolDispatchService),
//! [`ExecutionService`](crate::execution::ExecutionService),
//! [`FragmentIngestService`](crate::rich_fragment::FragmentIngestService))
//! run on test `fn` doubles; the Runtime owns no provider wiring. This module
//! is the `bitty-ipc` half of the bridge: a bounded live store the Runtime
//! publishes committed terminal state into, plus `fn` providers reading that
//! store through the existing dispatch paths (unchanged grammar, registry,
//! shape, authorize, budget, DTO-validate order). Providers stay pure `fn`
//! pointers so the services keep their dependency-free tables; liveness
//! arrives via publication, mirroring the `devtools` introspection live
//! store (`publish_grid_text` precedent).
//!
//! # Dispatch order (unchanged)
//!
//! Every dispatch keeps the established order:
//! grammar -> registry -> shape -> authorize -> handler -> provider ->
//! bound -> DTO-validate. Provider-echo mismatch still fails as
//! `InvalidRequest` (confused-deputy guard); the live snapshot provider
//! matches by construction (the store is keyed by terminal id) and the
//! dispatch re-verifies, so a compromised store entry cannot launder bytes
//! across terminals.
//!
//! # Budgets (accepted contracts, verified first-hand)
//!
//! Every number below reuses an accepted `bitty-ipc` bound; no value is
//! invented here:
//!
//! - Live store depth `<= 64` ([`MAX_LIVE_SNAPSHOTS`],
//!   `channel::MAX_PENDING_REQUESTS`, pending-table precedent, same as
//!   `execution::MAX_TRACKED_EXECUTIONS` and
//!   `rich_fragment::MAX_PENDING_FRAGMENTS`). Duplicate publication
//!   overwrites (freshest state wins: liveness, not ingestion dedup);
//!   a new terminal id at capacity evicts the oldest entry so dead terminals
//!   cannot permanently wedge the store, while terminals can also be
//!   explicitly retired via [`retire_live_snapshot`].
//! - Inspect tool result data `<= 16 KiB`
//!   (`tool_dispatch::MAX_TOOL_RESULT_BYTES`); over-bound live text is cut
//!   at a char boundary at insert and with the truncation flagged in the summary
//!   (snapshot/execution truncate-and-flag precedent; the flag keeps the
//!   cut honest, never silent).
//! - Inspect tool summaries `<= 512` bytes
//!   (`tool_dispatch::MAX_TOOL_SUMMARY_BYTES`, bounded human-message
//!   precedent).
//! - Client identity `1..=64` bytes (`auth::MAX_SCOPED_ID_BYTES`,
//!   scoped-id precedent).
//!
//! # Trust binding (CTX-0421 review outcome)
//!
//! Caller-supplied `client_id` / scopes / clock are untrusted until bound
//! here. The production build exposes no host-caller authority constructor;
//! [`HostCaller::bind_for_tests`] is compiled only for crate tests and cannot
//! mint `ProcessSpawn`. A future production binding must consume server-owned
//! authority rather than caller-supplied scopes or clock. UID-to-`client_id`
//! allocation remains outside this slice.
//!
//! The module is pure data plus one bounded process-global store, headless,
//! and `forbid(unsafe)`: it owns no socket, spawns no thread, performs no
//! I/O, and depends on no workspace crate beyond `bitty-ipc` itself. No
//! network, no new external crates.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::snapshot::{SnapshotData, SnapshotRequest};
use crate::tool_dispatch::{
    MAX_TOOL_RESULT_BYTES, ToolDispatchService, ToolOutput, ToolRequest, ToolSpec,
};
use bitty_ipc_api::error::IpcError;
use bitty_ipc_api::scope::Scope;
#[cfg(test)]
use bitty_ipc_api::scope::ScopeSet;
#[cfg(test)]
use bitty_ipc_auth::auth::{MAX_SCOPED_ID_BYTES, VerifiedPeer};

// ── live snapshot store ─────────────────────────────────────────────────────

/// Maximum live terminals retained (`channel::MAX_PENDING_REQUESTS`, 64).
///
/// Pending-table precedent: a malicious or buggy publisher cannot grow the
/// store without limit (T-01).
pub const MAX_LIVE_SNAPSHOTS: usize = bitty_ipc_api::channel::MAX_PENDING_REQUESTS;

/// Read-only inspect tool serving bounded live terminal text.
pub const INSPECT_TEXT_TOOL: &str = "terminal_text";

/// Read-only inspect tool serving a bounded live terminal status report.
pub const INSPECT_STATUS_TOOL: &str = "terminal_status";

/// Internal live snapshot record tracking staleness and insert truncation.
#[derive(Clone)]
struct LiveEntry {
    seq: u64,
    data: SnapshotData,
    truncated: bool,
    original_text_len: usize,
}

static NEXT_SNAPSHOT_SEQ: AtomicU64 = AtomicU64::new(0);

/// Process-global live terminal state, keyed by host terminal id.
///
/// Written by [`publish_live_snapshot`] (Runtime committed state), read by
/// [`live_snapshot_provider`] and the inspect tool providers below. Bounded
/// at [`MAX_LIVE_SNAPSHOTS`]; see the module docs for the overwrite/eviction
/// policy.
fn live_snapshot_store() -> &'static Mutex<BTreeMap<String, LiveEntry>> {
    static STORE: OnceLock<Mutex<BTreeMap<String, LiveEntry>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Retire a live snapshot when a terminal closes.
///
/// # Errors
///
/// Returns `InvalidRequest` when `terminal_id` violates the host
/// `t:<digits>` grammar, or `Internal` when the store lock is poisoned.
pub fn retire_live_snapshot(terminal_id: &str) -> Result<bool, IpcError> {
    crate::ctl::parse_terminal_id(terminal_id).map(|_| ())?;
    let mut store = live_snapshot_store()
        .lock()
        .map_err(|_| IpcError::Internal {
            reason: "live snapshot store lock is poisoned".into(),
        })?;
    Ok(store.remove(terminal_id).is_some())
}

/// Publish committed terminal state into the live store.
///
/// Overwrites any entry for the same terminal (freshest wins). If the store
/// is at capacity ([`MAX_LIVE_SNAPSHOTS`]) and a new terminal is published,
/// the oldest entry is evicted to ensure dead terminals do not permanently
/// wedge the store. Terminals can also be explicitly removed when closed via
/// [`retire_live_snapshot`].
///
/// Per-entry text is bounded to [`MAX_TOOL_RESULT_BYTES`]: if `data.text`
/// exceeds this bound, it is truncated on a UTF-8 character boundary.
///
/// # Errors
///
/// Returns `InvalidRequest` when `data.terminal_id` violates the host
/// `t:<digits>` grammar, or `Internal` when the store lock is poisoned.
pub fn publish_live_snapshot(mut data: SnapshotData) -> Result<bool, IpcError> {
    crate::ctl::parse_terminal_id(&data.terminal_id).map(|_| ())?;
    let original_text_len = data.text.len();
    let truncated = if data.text.len() > MAX_TOOL_RESULT_BYTES {
        let mut end = MAX_TOOL_RESULT_BYTES;
        while end > 0 && !data.text.is_char_boundary(end) {
            end -= 1;
        }
        data.text.truncate(end);
        true
    } else {
        false
    };

    let mut store = live_snapshot_store()
        .lock()
        .map_err(|_| IpcError::Internal {
            reason: "live snapshot store lock is poisoned".into(),
        })?;

    while !store.contains_key(&data.terminal_id) && store.len() >= MAX_LIVE_SNAPSHOTS {
        if let Some(oldest_key) = store
            .iter()
            .min_by_key(|(_, entry)| entry.seq)
            .map(|(k, _)| k.clone())
        {
            store.remove(&oldest_key);
        } else {
            break;
        }
    }

    let seq = NEXT_SNAPSHOT_SEQ.fetch_add(1, Ordering::Relaxed);
    store.insert(
        data.terminal_id.clone(),
        LiveEntry {
            seq,
            data,
            truncated,
            original_text_len,
        },
    );
    Ok(true)
}

/// Live [`SnapshotService`](crate::snapshot::SnapshotService) provider.
///
/// Serves the published entry for `request.terminal_id`; the dispatch
/// re-verifies the provider echo, so the match holds twice.
///
/// # Errors
///
/// Returns `NotFound` when no live state was published for the requested
/// terminal, or `Internal` when the store lock is poisoned.
pub fn live_snapshot_provider(request: &SnapshotRequest) -> Result<SnapshotData, IpcError> {
    let store = live_snapshot_store()
        .lock()
        .map_err(|_| IpcError::Internal {
            reason: "live snapshot store lock is poisoned".into(),
        })?;
    store
        .get(&request.terminal_id)
        .map(|entry| entry.data.clone())
        .ok_or_else(|| IpcError::NotFound {
            reason: format!("no live snapshot published for '{}'", request.terminal_id),
        })
}

/// Number of live terminals currently retained (diagnostics only).
#[must_use]
pub fn live_snapshot_count() -> usize {
    live_snapshot_store()
        .lock()
        .map(|store| store.len())
        .unwrap_or(0)
}

/// Drop every live entry (tests only; production state is never cleared
/// except by overwrite).
pub fn clear_live_snapshots_for_tests() {
    if let Ok(mut store) = live_snapshot_store().lock() {
        store.clear();
    }
    NEXT_SNAPSHOT_SEQ.store(0, Ordering::Relaxed);
}

// ── read-only inspect tools ─────────────────────────────────────────────────

/// Truncate `text` to `budget` bytes at a char boundary.
///
/// Returns the bounded text plus whether truncation occurred
/// (snapshot/execution precedent).
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

/// Declaration for [`INSPECT_TEXT_TOOL`] (read-only, `terminal.inspect`).
///
/// # Errors
///
/// Returns the [`ToolSpec::new`] failure when the statically valid
/// declaration is rejected (programming error, never caller input).
pub fn inspect_text_spec() -> Result<ToolSpec, IpcError> {
    ToolSpec::new(
        INSPECT_TEXT_TOOL,
        "bounded live terminal text for one terminal (read-only inspect)",
        b"{}".to_vec(),
        Scope::TerminalInspect,
        true,
    )
}

/// Declaration for [`INSPECT_STATUS_TOOL`] (read-only, `terminal.inspect`).
///
/// # Errors
///
/// Returns the [`ToolSpec::new`] failure when the statically valid
/// declaration is rejected (programming error, never caller input).
pub fn inspect_status_spec() -> Result<ToolSpec, IpcError> {
    ToolSpec::new(
        INSPECT_STATUS_TOOL,
        "bounded live terminal status report for one terminal (read-only inspect)",
        b"{}".to_vec(),
        Scope::TerminalInspect,
        true,
    )
}

/// Read one published entry by target (shared provider prologue).
fn live_entry_for_tool(tool: &str, request: &ToolRequest) -> Result<LiveEntry, IpcError> {
    let target = request
        .target
        .as_deref()
        .ok_or_else(|| IpcError::InvalidRequest {
            reason: format!("tool '{tool}' requires a captured target"),
        })?;
    crate::ctl::parse_terminal_id(target).map(|_| ())?;
    let store = live_snapshot_store()
        .lock()
        .map_err(|_| IpcError::Internal {
            reason: "live snapshot store lock is poisoned".into(),
        })?;
    store
        .get(target)
        .cloned()
        .ok_or_else(|| IpcError::NotFound {
            reason: format!("no live snapshot published for '{target}'"),
        })
}

/// Provider for [`INSPECT_TEXT_TOOL`]: bounded live text with echo match.
///
/// Over-bound live text is cut at a char boundary and the cut is flagged
/// in the summary (never silent).
///
/// # Errors
///
/// - `InvalidRequest` when the request carries no target or the target
///   violates the host grammar.
/// - `NotFound` when no live state was published for the target.
/// - `Internal` when the store lock is poisoned.
pub fn inspect_text_provider(request: &ToolRequest) -> Result<ToolOutput, IpcError> {
    let entry = live_entry_for_tool(INSPECT_TEXT_TOOL, request)?;
    let (data_text, tool_truncated) = truncate_to_budget(&entry.data.text, MAX_TOOL_RESULT_BYTES);
    let truncated = entry.truncated || tool_truncated;
    let summary = format!(
        "{} gen {} {}/{}B{}",
        entry.data.terminal_id,
        entry.data.generation,
        data_text.len(),
        entry.original_text_len,
        if truncated { " truncated" } else { "" }
    );
    let output = ToolOutput {
        target_id: request.target.clone(),
        data: data_text.into_bytes(),
        summary,
    };
    output.validate()?;
    Ok(output)
}

/// Provider for [`INSPECT_STATUS_TOOL`]: bounded generation/cwd/zone report.
///
/// The `cwd` display is cut to the accepted snapshot `cwd` bound
/// (`snapshot::MAX_SNAPSHOT_CWD_BYTES`); the cut keeps the DTO inside the
/// tool result budget on every path.
///
/// # Errors
///
/// - `InvalidRequest` when the request carries no target or the target
///   violates the host grammar.
/// - `NotFound` when no live state was published for the target.
/// - `Internal` when the store lock is poisoned.
pub fn inspect_status_provider(request: &ToolRequest) -> Result<ToolOutput, IpcError> {
    let entry = live_entry_for_tool(INSPECT_STATUS_TOOL, request)?;
    let (cwd, _) = truncate_to_budget(&entry.data.cwd, crate::snapshot::MAX_SNAPSHOT_CWD_BYTES);
    let data = format!(
        "generation: {}\ncwd: {}\nzones: {}\ntext_bytes: {}\n",
        entry.data.generation,
        cwd,
        entry.data.semantic_zones.len(),
        entry.data.text.len()
    );
    let summary = format!(
        "{} gen {} zones {}",
        entry.data.terminal_id,
        entry.data.generation,
        entry.data.semantic_zones.len()
    );
    let output = ToolOutput {
        target_id: request.target.clone(),
        data: data.into_bytes(),
        summary,
    };
    output.validate()?;
    Ok(output)
}

/// Register the live read-only inspect tools on `service`.
///
/// Registers exactly [`INSPECT_TEXT_TOOL`] and [`INSPECT_STATUS_TOOL`]
/// (both `read_only`, both `terminal.inspect`). Effect tools are never
/// registered here: they stay deny-by-default (`NotFound`) until their
/// own slice wires them.
///
/// # Errors
///
/// - `InvalidRequest` when a tool name is already registered (no silent
///   overwrite).
/// - `LimitExceeded` when the registry is at capacity (`32`).
pub fn register_live_inspect_tools(service: &mut ToolDispatchService) -> Result<(), IpcError> {
    service.register(inspect_text_spec()?, inspect_text_provider)?;
    service.register(inspect_status_spec()?, inspect_status_provider)?;
    Ok(())
}

// ── trust binding ───────────────────────────────────────────────────────────

/// Caller identity bound to an attested connection plus server-evaluated
/// authority (CTX-0421 review outcome).
///
/// This type is compiled only for crate tests. Its test binding requires an
/// already-attested [`VerifiedPeer`], records that peer's UID, and rejects
/// `ProcessSpawn`; it is not exported or dispatchable from production code.
/// Production host authority must be supplied by a future server-owned
/// binding rather than this fixture.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct HostCaller {
    /// Server-validated client label presented over the attested connection.
    client_id: String,
    /// Server-evaluated scope set (never caller-asserted).
    granted: ScopeSet,
    /// Server clock in ms (never caller-supplied).
    now_ms: u64,
    peer_uid: u32,
}

#[cfg(test)]
impl HostCaller {
    /// Maximum client identity bytes (`auth::MAX_SCOPED_ID_BYTES`, 64).
    pub const MAX_CLIENT_ID_BYTES: usize = MAX_SCOPED_ID_BYTES;

    /// Bind a caller label to an attested connection and server authority.
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when `client_id` is empty.
    /// - `LimitExceeded` when `client_id` exceeds 64 bytes.
    pub(crate) fn bind_for_tests(
        peer: &VerifiedPeer,
        client_id: impl Into<String>,
        granted: ScopeSet,
        now_ms: u64,
    ) -> Result<Self, IpcError> {
        let client_id = client_id.into();
        if client_id.is_empty() {
            return Err(IpcError::InvalidRequest {
                reason: "host caller client_id must not be empty".into(),
            });
        }
        if client_id.len() > Self::MAX_CLIENT_ID_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "host caller client_id".into(),
                limit: Self::MAX_CLIENT_ID_BYTES,
                actual: client_id.len(),
            });
        }
        if granted.contains(Scope::ProcessSpawn) {
            return Err(IpcError::ScopeDenied {
                scope: Scope::ProcessSpawn.as_str().into(),
                action: "host_bridge_test".into(),
            });
        }
        Ok(Self {
            client_id,
            granted,
            now_ms,
            peer_uid: peer.peer_uid(),
        })
    }

    /// Bound client label.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Server-evaluated scope set.
    #[must_use]
    pub fn granted(&self) -> &ScopeSet {
        &self.granted
    }

    /// Server clock in ms.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// UID of the verified peer used by the test-only binding.
    #[must_use]
    pub fn peer_uid(&self) -> u32 {
        self.peer_uid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{
        DetailLevel, SNAPSHOT_METHOD, SemanticZone, SnapshotRequest, SnapshotService, ZoneKind,
    };
    use bitty_ipc_api::scope::{ConsentLedger, ScopeSet};

    /// Serialize the store-touching tests in this module (the live store is
    /// process-global; parallel tests must not interleave publishes).
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn live_data(terminal_id: &str, generation: u64, text: &str) -> SnapshotData {
        SnapshotData {
            terminal_id: terminal_id.to_owned(),
            generation,
            cwd: "/work".to_owned(),
            semantic_zones: vec![SemanticZone {
                kind: ZoneKind::Output,
                line_start: 0,
                line_end: 2,
            }],
            text: text.to_owned(),
        }
    }

    fn granted_inspect() -> ScopeSet {
        ScopeSet::single(Scope::TerminalInspect)
    }

    fn consented(client: &str, now_ms: u64) -> ConsentLedger {
        let mut ledger = ConsentLedger::new();
        ledger
            .grant(
                client.to_owned(),
                Scope::TerminalInspect,
                now_ms,
                60_000,
                "test".to_owned(),
            )
            .expect("grant");
        ledger
    }

    #[test]
    fn bounds_match_accepted_contracts() {
        assert_eq!(
            MAX_LIVE_SNAPSHOTS,
            bitty_ipc_api::channel::MAX_PENDING_REQUESTS
        );
        assert_eq!(HostCaller::MAX_CLIENT_ID_BYTES, MAX_SCOPED_ID_BYTES);
        assert_eq!(MAX_TOOL_RESULT_BYTES, 16 * 1024);
        assert_eq!(
            crate::tool_dispatch::MAX_TOOL_SUMMARY_BYTES,
            crate::devtools::MAX_ERROR_MESSAGE_CHARS
        );
    }

    #[test]
    fn live_publish_serves_through_dispatch() {
        let _guard = test_lock();
        clear_live_snapshots_for_tests();
        publish_live_snapshot(live_data("t:71", 9, "hello live")).expect("publish serves");
        let service = SnapshotService::with_defaults(live_snapshot_provider);
        let snapshot = service
            .dispatch(
                SNAPSHOT_METHOD,
                &SnapshotRequest::new("t:71", DetailLevel::Standard),
                &granted_inspect(),
            )
            .expect("live provider serves");
        assert_eq!(snapshot.terminal_id, "t:71");
        assert_eq!(snapshot.generation, 9);
        assert_eq!(snapshot.cwd, "/work");
        assert_eq!(snapshot.text, "hello live");
        assert!(!snapshot.truncated);
        assert!(snapshot.is_untrusted_surface);
        assert_eq!(snapshot.semantic_zones.len(), 1);
    }

    #[test]
    fn live_provider_miss_is_not_found() {
        let _guard = test_lock();
        clear_live_snapshots_for_tests();
        let service = SnapshotService::with_defaults(live_snapshot_provider);
        let error = service
            .dispatch(
                SNAPSHOT_METHOD,
                &SnapshotRequest::new("t:72", DetailLevel::Standard),
                &granted_inspect(),
            )
            .expect_err("unpublished terminal must fail closed");
        assert!(matches!(error, IpcError::NotFound { .. }), "got {error:?}");
    }

    #[test]
    fn live_publish_rejects_bad_terminal_grammar() {
        let _guard = test_lock();
        clear_live_snapshots_for_tests();
        let error = publish_live_snapshot(live_data("nope", 1, "x"))
            .expect_err("bad terminal id must fail");
        assert!(
            matches!(error, IpcError::InvalidRequest { .. }),
            "got {error:?}"
        );
        assert_eq!(live_snapshot_count(), 0);
    }

    #[test]
    fn retire_live_snapshot_drops_count_and_removes_entry() {
        let _guard = test_lock();
        clear_live_snapshots_for_tests();
        publish_live_snapshot(live_data("t:101", 1, "first")).expect("publish 101");
        publish_live_snapshot(live_data("t:102", 2, "second")).expect("publish 102");
        assert_eq!(live_snapshot_count(), 2);

        // Retiring an existing terminal returns Ok(true) and decrements count
        assert!(retire_live_snapshot("t:101").expect("retire 101"));
        assert_eq!(live_snapshot_count(), 1);

        // Verification: t:101 is gone from the store
        let service = SnapshotService::with_defaults(live_snapshot_provider);
        let error = service
            .dispatch(
                SNAPSHOT_METHOD,
                &SnapshotRequest::new("t:101", DetailLevel::Standard),
                &granted_inspect(),
            )
            .expect_err("retired terminal must fail as not found");
        assert!(matches!(error, IpcError::NotFound { .. }));

        // t:102 is still retained and serves
        let snapshot = service
            .dispatch(
                SNAPSHOT_METHOD,
                &SnapshotRequest::new("t:102", DetailLevel::Standard),
                &granted_inspect(),
            )
            .expect("retained terminal serves");
        assert_eq!(snapshot.text, "second");

        // Retiring already-retired terminal returns Ok(false)
        assert!(!retire_live_snapshot("t:101").expect("already retired"));
        assert_eq!(live_snapshot_count(), 1);

        // Retiring with invalid terminal id grammar returns InvalidRequest
        let err = retire_live_snapshot("invalid").expect_err("bad grammar fails");
        assert!(matches!(err, IpcError::InvalidRequest { .. }));
        assert_eq!(live_snapshot_count(), 1);

        // Retire remaining terminal leaves count at 0
        assert!(retire_live_snapshot("t:102").expect("retire 102"));
        assert_eq!(live_snapshot_count(), 0);
        clear_live_snapshots_for_tests();
    }

    #[test]
    fn store_at_capacity_evicts_oldest_on_new_publish() {
        let _guard = test_lock();
        clear_live_snapshots_for_tests();
        for index in 0..(MAX_LIVE_SNAPSHOTS as u64) {
            let id = format!("t:{}", 1000 + index);
            assert!(
                publish_live_snapshot(live_data(&id, index, "x")).expect("capacity slot"),
                "slot for {id}"
            );
        }
        assert_eq!(live_snapshot_count(), MAX_LIVE_SNAPSHOTS);

        // 65th publish succeeds by evicting oldest terminal (t:1000), count stays <= MAX_LIVE_SNAPSHOTS
        assert!(
            publish_live_snapshot(live_data("t:2000", 1, "newest")).expect("65th publish succeeds"),
            "new terminal at capacity evicts oldest"
        );
        assert_eq!(live_snapshot_count(), MAX_LIVE_SNAPSHOTS);

        let service = SnapshotService::with_defaults(live_snapshot_provider);

        // t:1000 was evicted
        let err = service
            .dispatch(
                SNAPSHOT_METHOD,
                &SnapshotRequest::new("t:1000", DetailLevel::Standard),
                &granted_inspect(),
            )
            .expect_err("oldest terminal must be evicted");
        assert!(matches!(err, IpcError::NotFound { .. }));

        // t:1001 (second oldest) is still retained
        assert!(
            service
                .dispatch(
                    SNAPSHOT_METHOD,
                    &SnapshotRequest::new("t:1001", DetailLevel::Standard),
                    &granted_inspect(),
                )
                .is_ok()
        );

        // t:2000 is present and serves
        let snap = service
            .dispatch(
                SNAPSHOT_METHOD,
                &SnapshotRequest::new("t:2000", DetailLevel::Standard),
                &granted_inspect(),
            )
            .expect("newest serves");
        assert_eq!(snap.text, "newest");

        // Updating an existing terminal refreshes it and keeps count <= MAX_LIVE_SNAPSHOTS
        assert!(
            publish_live_snapshot(live_data("t:1001", 99, "fresh")).expect("overwrite serves"),
            "overwrite of a retained terminal still serves"
        );
        assert_eq!(live_snapshot_count(), MAX_LIVE_SNAPSHOTS);
        clear_live_snapshots_for_tests();
    }

    #[test]
    fn publish_truncates_over_budget_text_on_utf8_char_boundary() {
        let _guard = test_lock();
        clear_live_snapshots_for_tests();

        // 16382 ASCII bytes ('a') + 3-byte char '語' (0xE8 0xAA 0x9E) = 16385 bytes.
        // MAX_TOOL_RESULT_BYTES is 16384, which falls inside '語'.
        // Truncation must stop at byte 16382 to preserve valid UTF-8.
        let mut over_budget = "a".repeat(MAX_TOOL_RESULT_BYTES - 2);
        over_budget.push('語');
        assert_eq!(over_budget.len(), MAX_TOOL_RESULT_BYTES + 1);

        publish_live_snapshot(live_data("t:3000", 1, &over_budget)).expect("publish");

        let service = SnapshotService::with_defaults(live_snapshot_provider);
        let snapshot = service
            .dispatch(
                SNAPSHOT_METHOD,
                &SnapshotRequest::new("t:3000", DetailLevel::Standard),
                &granted_inspect(),
            )
            .expect("retrieval serves");

        assert!(snapshot.text.len() <= MAX_TOOL_RESULT_BYTES);
        assert_eq!(snapshot.text.len(), MAX_TOOL_RESULT_BYTES - 2);
        assert_eq!(snapshot.text, "a".repeat(MAX_TOOL_RESULT_BYTES - 2));

        // ASCII over-budget text truncates to exactly MAX_TOOL_RESULT_BYTES
        let ascii_over = "b".repeat(MAX_TOOL_RESULT_BYTES + 100);
        publish_live_snapshot(live_data("t:3001", 1, &ascii_over)).expect("publish ascii");
        let snapshot_ascii = service
            .dispatch(
                SNAPSHOT_METHOD,
                &SnapshotRequest::new("t:3001", DetailLevel::Standard),
                &granted_inspect(),
            )
            .expect("retrieval serves");
        assert_eq!(snapshot_ascii.text.len(), MAX_TOOL_RESULT_BYTES);

        clear_live_snapshots_for_tests();
    }

    #[test]
    fn inspect_text_serves_live_bytes_with_echo() {
        let _guard = test_lock();
        clear_live_snapshots_for_tests();
        publish_live_snapshot(live_data("t:73", 4, "typed bytes")).expect("publish");
        let mut service = ToolDispatchService::new();
        register_live_inspect_tools(&mut service).expect("register");
        let execution = service
            .dispatch(
                &ToolRequest::new(INSPECT_TEXT_TOOL, b"{}".to_vec()).with_target("t:73"),
                &granted_inspect(),
                &consented("bridge-tests", 1_000),
                "bridge-tests",
                1_000,
                41,
            )
            .expect("inspect serves");
        assert_eq!(execution.tool, INSPECT_TEXT_TOOL);
        assert_eq!(execution.target.as_deref(), Some("t:73"));
        assert_eq!(execution.data, b"typed bytes");
        assert!(execution.summary.contains("t:73"));
        assert!(execution.is_untrusted_surface);
        assert_eq!(execution.execution_id, 41);
        assert_eq!(execution.client_id, "bridge-tests");
    }

    #[test]
    fn inspect_status_serves_generation_cwd_zones() {
        let _guard = test_lock();
        clear_live_snapshots_for_tests();
        publish_live_snapshot(live_data("t:74", 6, "hello")).expect("publish");
        let mut service = ToolDispatchService::new();
        register_live_inspect_tools(&mut service).expect("register");
        let execution = service
            .dispatch(
                &ToolRequest::new(INSPECT_STATUS_TOOL, b"{}".to_vec()).with_target("t:74"),
                &granted_inspect(),
                &consented("bridge-tests", 1_000),
                "bridge-tests",
                1_000,
                42,
            )
            .expect("status serves");
        let body = String::from_utf8(execution.data).expect("status is UTF-8");
        assert!(body.contains("generation: 6"), "got {body:?}");
        assert!(body.contains("cwd: /work"), "got {body:?}");
        assert!(body.contains("zones: 1"), "got {body:?}");
        assert!(execution.is_untrusted_surface);
    }

    #[test]
    fn inspect_tools_require_captured_target() {
        let _guard = test_lock();
        clear_live_snapshots_for_tests();
        publish_live_snapshot(live_data("t:75", 1, "x")).expect("publish");
        let mut service = ToolDispatchService::new();
        register_live_inspect_tools(&mut service).expect("register");
        for tool in [INSPECT_TEXT_TOOL, INSPECT_STATUS_TOOL] {
            let error = service
                .dispatch(
                    &ToolRequest::new(tool, b"{}".to_vec()),
                    &granted_inspect(),
                    &consented("bridge-tests", 1_000),
                    "bridge-tests",
                    1_000,
                    43,
                )
                .expect_err("missing target must fail closed");
            assert!(
                matches!(error, IpcError::InvalidRequest { .. }),
                "got {error:?}"
            );
        }
    }

    #[test]
    fn inspect_text_unknown_terminal_is_not_found() {
        let _guard = test_lock();
        clear_live_snapshots_for_tests();
        let mut service = ToolDispatchService::new();
        register_live_inspect_tools(&mut service).expect("register");
        let error = service
            .dispatch(
                &ToolRequest::new(INSPECT_TEXT_TOOL, b"{}".to_vec()).with_target("t:76"),
                &granted_inspect(),
                &consented("bridge-tests", 1_000),
                "bridge-tests",
                1_000,
                44,
            )
            .expect_err("unpublished terminal must fail closed");
        assert!(matches!(error, IpcError::NotFound { .. }), "got {error:?}");
    }

    #[test]
    fn inspect_text_truncation_is_flagged_never_silent() {
        let _guard = test_lock();
        clear_live_snapshots_for_tests();
        let big = "x".repeat(MAX_TOOL_RESULT_BYTES + 16);
        publish_live_snapshot(live_data("t:77", 2, &big)).expect("publish");
        let mut service = ToolDispatchService::new();
        register_live_inspect_tools(&mut service).expect("register");
        let execution = service
            .dispatch(
                &ToolRequest::new(INSPECT_TEXT_TOOL, b"{}".to_vec()).with_target("t:77"),
                &granted_inspect(),
                &consented("bridge-tests", 1_000),
                "bridge-tests",
                1_000,
                45,
            )
            .expect("over-bound text serves flagged");
        assert!(execution.data.len() <= MAX_TOOL_RESULT_BYTES);
        assert!(
            execution.summary.contains("truncated"),
            "got {:?}",
            execution.summary
        );
    }

    #[test]
    fn helper_registers_only_read_only_inspect_tools() {
        let mut service = ToolDispatchService::new();
        register_live_inspect_tools(&mut service).expect("register");
        assert_eq!(service.tool_count(), 2);
        assert_eq!(
            service.tool_names(),
            vec![INSPECT_STATUS_TOOL.to_owned(), INSPECT_TEXT_TOOL.to_owned()]
        );
        assert!(service.contains(INSPECT_TEXT_TOOL));
        assert!(service.contains(INSPECT_STATUS_TOOL));
    }

    #[test]
    fn inspect_dispatch_keeps_scope_and_consent_gates() {
        let _guard = test_lock();
        clear_live_snapshots_for_tests();
        publish_live_snapshot(live_data("t:78", 1, "gated")).expect("publish");
        let mut service = ToolDispatchService::new();
        register_live_inspect_tools(&mut service).expect("register");
        let request = ToolRequest::new(INSPECT_TEXT_TOOL, b"{}".to_vec()).with_target("t:78");
        let empty = ScopeSet::new();
        let error = service
            .dispatch(
                &request,
                &empty,
                &consented("bridge-tests", 1_000),
                "bridge-tests",
                1_000,
                46,
            )
            .expect_err("missing scope must deny");
        assert!(
            matches!(error, IpcError::ScopeDenied { .. }),
            "got {error:?}"
        );
        let error = service
            .dispatch(
                &request,
                &granted_inspect(),
                &ConsentLedger::new(),
                "bridge-tests",
                1_000,
                47,
            )
            .expect_err("missing consent must deny");
        assert!(matches!(error, IpcError::Denied { .. }), "got {error:?}");
    }

    #[test]
    fn host_caller_binds_shape_and_server_authority() {
        use bitty_ipc_auth::auth::{PeerCredentials, verify_peer_for_connection};
        // CTX-0656: the marker is only mintable through verification — the
        // same-process harness proves locality via the headless UID check.
        let peer = verify_peer_for_connection(PeerCredentials::new(1000, 1000, 1), 1000)
            .expect("test-only local marker");
        let granted = granted_inspect();
        let caller = HostCaller::bind_for_tests(&peer, "bridge-tests", granted.clone(), 1_000)
            .expect("valid label binds");
        assert_eq!(caller.client_id(), "bridge-tests");
        assert_eq!(caller.now_ms(), 1_000);
        assert_eq!(caller.peer_uid(), 1000);
        assert!(caller.granted().contains(Scope::TerminalInspect));
        assert!(!caller.granted().contains(Scope::ProcessSpawn));
        let process_scope_error =
            HostCaller::bind_for_tests(&peer, "bridge-tests", ScopeSet::all(), 1_000)
                .expect_err("test-only host bridge must not mint process authority");
        assert!(matches!(process_scope_error, IpcError::ScopeDenied { .. }));
        let error = HostCaller::bind_for_tests(&peer, "", granted.clone(), 1_000)
            .expect_err("empty label must fail");
        assert!(
            matches!(error, IpcError::InvalidRequest { .. }),
            "got {error:?}"
        );
        let error = HostCaller::bind_for_tests(&peer, "x".repeat(65), granted, 1_000)
            .expect_err("over-bound label must fail");
        assert!(
            matches!(error, IpcError::LimitExceeded { .. }),
            "got {error:?}"
        );
    }
}
