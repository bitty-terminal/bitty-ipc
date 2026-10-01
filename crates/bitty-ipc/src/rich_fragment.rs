//! Bounded scene-fragment ingestion transport (CTX-0422, G-4).
//!
//! G-4 from the CTX-0407 pressure test: `RichBlock`/`Scene`
//! (`bitty-rich/src/scene.rs`) are Core-internal with no bounded ingestion
//! method for out-of-process producers. This module closes that gap with a
//! text-chunks-first transport: producers hand over bounded text fragments,
//! the service truncates to budget, labels them untrusted, and queues them
//! for the render side to drain. Full scene graphs and pixel buffers never
//! enter this path.
//!
//! # DTO contract (DIR-018 step 5)
//!
//! [`RichFragment`] carries exactly the ingestion field list: `terminal_id`
//! / `generation` / `seq` / `zone` / `text` / `truncated` /
//! `is_untrusted_surface`. `generation` is the damage generation the chunk
//! was cut from (snapshot `TerminalSnapshot::generation` precedent);
//! (`terminal_id`, `generation`, `seq`) is the dedup key ordering chunks
//! within one generation. `zone` reuses [`ZoneKind`](crate::snapshot::ZoneKind)
//! (CP-9 vocabulary) so no second zone enum exists; line anchoring stays a
//! projection-sequel concern (the render side maps chunks to lines when it
//! builds `RichBlock`s). `is_untrusted_surface` is always `true`: fragment
//! bytes are attacker-controlled observation data, never instructions
//! (T-10 / R-013).
//!
//! # Budgets (accepted contracts, verified first-hand)
//!
//! Every number below reuses an accepted `bitty-ipc` bound; no value is
//! invented here:
//!
//! - Text per fragment `<= 16 KiB` ([`MAX_FRAGMENT_TEXT_BYTES`],
//!   `devtools::MAX_INSPECT_TEXT_BYTES`, grid-text bound; the same 16 KiB
//!   already caps `ctl::MAX_SEND_TEXT_BYTES`, tool results
//!   (`tool_dispatch::MAX_TOOL_RESULT_BYTES`), and bridge params
//!   (`bridge::MAX_BRIDGE_PARAMS_BYTES`), so one fragment fits one bridge
//!   call). Over-ceiling producer text is truncated at a char boundary
//!   with `truncated = true` (snapshot/execution precedent); direct DTO
//!   validation still rejects over-ceiling text fail-closed.
//! - Queue depth `<= 64` ([`MAX_PENDING_FRAGMENTS`],
//!   `channel::MAX_PENDING_REQUESTS`, pending-table precedent, same as
//!   `execution::MAX_TRACKED_EXECUTIONS`). Duplicate
//!   (`terminal_id`, `generation`, `seq`) is rejected as `InvalidRequest`
//!   *before* the capacity check (tool-dispatch/execution
//!   duplicate-before-capacity precedent); overflow is `LimitExceeded`.
//! - `terminal_id`: host shape `t:<digits>` via `ctl::parse_terminal_id`
//!   (1..=10 digits, no leading zeros, snapshot precedent).
//! - Text must not contain NUL (`InvalidRequest`, execution/ctl precedent).
//!
//! Budget coherence with the scene that consumes this transport (read-only
//! reference, no dependency): 16 fragments of 16 KiB fill one
//! `SCENE_MAX_TEXT_BYTES_PER_BLOCK` (256 KiB) block, and a full 64-deep
//! queue holds at most 1 MiB, under `SCENE_MAX_RICH_BYTES_PER_TERMINAL`
//! (2 MiB). The 256 KiB frame ceiling (`frame::MAX_FRAME_BYTES`) is untouched.
//!
//! # What this module does not do
//!
//! No wire method is registered (`scope.rs` unchanged): authorization of a
//! future `rich.*` serving method, consent, and live render/projection
//! wiring (fragment-to-`RichBlock` mapping in `bitty-rich`) are sequel work.
//! There is no host provider callback, so the provider-echo check of the
//! sibling dispatch services has no call site here; the push-side analogue
//! holds instead — the transport stores the producer-supplied
//! (`terminal_id`, `generation`, `seq`) verbatim and rejects key mismatches
//! by construction (keys are derived from the stored DTO, never re-typed).
//!
//! The module is pure data, bounded, headless, and `forbid(unsafe)`: it owns
//! no socket, spawns no thread, performs no I/O, and depends on no workspace
//! crate beyond `bitty-ipc` itself. No network, no new external crates.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, VecDeque};

use crate::snapshot::ZoneKind;
use bitty_ipc_api::error::IpcError;

// ── bounds (accepted-contract sources inline) ───────────────────────────────

/// Maximum text bytes per fragment: 16 KiB grid-text bound
/// (`devtools::MAX_INSPECT_TEXT_BYTES`).
pub const MAX_FRAGMENT_TEXT_BYTES: usize = crate::devtools::MAX_INSPECT_TEXT_BYTES;

/// Maximum queued fragments: 64 pending-item bound
/// (`channel::MAX_PENDING_REQUESTS`).
pub const MAX_PENDING_FRAGMENTS: usize = bitty_ipc_api::channel::MAX_PENDING_REQUESTS;

// ── producer input (unbounded input, bounded by the service) ────────────────

/// Raw producer chunk before bounding (pre-bound input).
///
/// The producer cuts text from a damage generation; the service enforces
/// every bound and always labels the stored fragment `is_untrusted_surface`.
/// Producers never set the trust label themselves, so a compromised producer
/// cannot launder fragment bytes into instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentData {
    /// Host terminal id the chunk was cut from (must be `t:<digits>`).
    pub terminal_id: String,
    /// Damage generation the chunk corresponds to.
    pub generation: u64,
    /// Chunk index within (`terminal_id`, `generation`).
    pub seq: u64,
    /// Zone attribution for this chunk (`None` leaves zoning to projection).
    pub zone: Option<ZoneKind>,
    /// Raw chunk text (truncated to budget at a char boundary by the service).
    pub text: String,
}

// ── DTO (DIR-018 ingestion field list) ──────────────────────────────────────

/// Bounded text scene fragment (ingestion field list, never scene internals).
///
/// Exactly seven fields: `terminal_id` / `generation` / `seq` / `zone` /
/// `text` / `truncated` / `is_untrusted_surface`.
/// `is_untrusted_surface` is always `true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RichFragment {
    /// Host terminal id (`t:<digits>`).
    pub terminal_id: String,
    /// Damage generation the chunk was cut from.
    pub generation: u64,
    /// Chunk index within (`terminal_id`, `generation`).
    pub seq: u64,
    /// Zone attribution for this chunk.
    pub zone: Option<ZoneKind>,
    /// Bounded chunk text (char-boundary truncated).
    pub text: String,
    /// True when the producer text was truncated to fit its budget.
    pub truncated: bool,
    /// Always `true`: fragment bytes are untrusted observation data (T-10).
    pub is_untrusted_surface: bool,
}

impl RichFragment {
    /// Whether this fragment is an untrusted observation surface.
    ///
    /// Always `true`; provided so call sites read intent, not a field.
    #[must_use]
    pub fn is_untrusted_surface(&self) -> bool {
        self.is_untrusted_surface
    }

    /// Dedup key for this fragment.
    #[must_use]
    pub fn key(&self) -> (String, u64, u64) {
        (self.terminal_id.clone(), self.generation, self.seq)
    }

    /// Validate the DTO against its budgets (fail-closed).
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when `terminal_id` violates the host grammar, the
    ///   text contains NUL, or the trust label is not set.
    /// - `LimitExceeded` when `text` exceeds [`MAX_FRAGMENT_TEXT_BYTES`].
    pub fn validate(&self) -> Result<(), IpcError> {
        crate::ctl::parse_terminal_id(&self.terminal_id).map(|_| ())?;
        if !self.is_untrusted_surface {
            return Err(IpcError::InvalidRequest {
                reason: "rich fragments must be labeled is_untrusted_surface".into(),
            });
        }
        if self.text.len() > MAX_FRAGMENT_TEXT_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "text".into(),
                limit: MAX_FRAGMENT_TEXT_BYTES,
                actual: self.text.len(),
            });
        }
        if self.text.contains('\0') {
            return Err(IpcError::InvalidRequest {
                reason: "rich fragment text must not contain NUL".into(),
            });
        }
        Ok(())
    }
}

// ── bounding helper ─────────────────────────────────────────────────────────

/// Truncate `text` to `budget` bytes at a char boundary.
///
/// Returns the bounded text plus whether truncation occurred. A zero budget
/// yields empty text with `truncated` set when the input is non-empty
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

// ── ingestion transport ─────────────────────────────────────────────────────

/// Bounded producer-to-render fragment transport.
///
/// Holds validated [`RichFragment`]s in FIFO order for the render side to
/// drain. Ingestion validates shape, rejects duplicate keys, enforces the
/// depth cap, then bounds producer text; any refusal stores nothing
/// (FS-IP1 transactional denial).
#[derive(Debug, Default)]
pub struct FragmentIngestService {
    /// Queued fragments, oldest first.
    queue: VecDeque<RichFragment>,
    /// Keys currently queued (duplicate detection).
    keys: BTreeSet<(String, u64, u64)>,
}

impl FragmentIngestService {
    /// Empty transport: every drain is empty until a fragment ingests.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            keys: BTreeSet::new(),
        }
    }

    /// Number of queued fragments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether no fragment is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Whether (`terminal_id`, `generation`, `seq`) is currently queued.
    #[must_use]
    pub fn contains(&self, terminal_id: &str, generation: u64, seq: u64) -> bool {
        self.keys
            .contains(&(terminal_id.to_owned(), generation, seq))
    }

    /// Ingest one producer chunk (fail-closed, no partial state).
    ///
    /// Validates the terminal grammar and NUL shape, rejects duplicate keys,
    /// enforces the depth cap, then truncates producer text to
    /// [`MAX_FRAGMENT_TEXT_BYTES`] with `is_untrusted_surface` labeling.
    ///
    /// # Errors
    ///
    /// - `InvalidRequest` when the terminal grammar or text shape is bad,
    ///   or the key is already queued (checked before capacity).
    /// - `LimitExceeded` when the queue is at capacity.
    pub fn ingest(&mut self, data: FragmentData) -> Result<RichFragment, IpcError> {
        crate::ctl::parse_terminal_id(&data.terminal_id).map(|_| ())?;
        if data.text.contains('\0') {
            return Err(IpcError::InvalidRequest {
                reason: "rich fragment text must not contain NUL".into(),
            });
        }
        let key = (data.terminal_id.clone(), data.generation, data.seq);
        if self.keys.contains(&key) {
            return Err(IpcError::InvalidRequest {
                reason: format!(
                    "duplicate rich fragment '{}' gen {} seq {} (drain before re-cut)",
                    data.terminal_id, data.generation, data.seq
                ),
            });
        }
        if self.queue.len() >= MAX_PENDING_FRAGMENTS {
            return Err(IpcError::LimitExceeded {
                field: "pending fragments".into(),
                limit: MAX_PENDING_FRAGMENTS,
                actual: self.queue.len() + 1,
            });
        }
        let (text, truncated) = truncate_to_budget(&data.text, MAX_FRAGMENT_TEXT_BYTES);
        let fragment = RichFragment {
            terminal_id: data.terminal_id,
            generation: data.generation,
            seq: data.seq,
            zone: data.zone,
            text,
            truncated,
            is_untrusted_surface: true,
        };
        fragment.validate()?;
        self.keys.insert(fragment.key());
        self.queue.push_back(fragment.clone());
        Ok(fragment)
    }

    /// Drain up to `limit` queued fragments in FIFO order.
    ///
    /// Drained keys are released, so a later chunk may reuse the key. An
    /// empty queue drains to an empty vector.
    pub fn drain_bounded(&mut self, limit: usize) -> Vec<RichFragment> {
        let take = limit.min(self.queue.len());
        let mut out = Vec::with_capacity(take);
        for _ in 0..take {
            if let Some(fragment) = self.queue.pop_front() {
                self.keys.remove(&fragment.key());
                out.push(fragment);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(seq: u64, text: &str) -> FragmentData {
        FragmentData {
            terminal_id: "t:1".to_owned(),
            generation: 7,
            seq,
            zone: Some(ZoneKind::Output),
            text: text.to_owned(),
        }
    }

    #[test]
    fn budgets_match_accepted_bounds() {
        assert_eq!(
            MAX_FRAGMENT_TEXT_BYTES,
            crate::devtools::MAX_INSPECT_TEXT_BYTES
        );
        assert_eq!(MAX_FRAGMENT_TEXT_BYTES, 16 * 1024);
        assert_eq!(MAX_FRAGMENT_TEXT_BYTES, crate::ctl::MAX_SEND_TEXT_BYTES);
        assert_eq!(
            MAX_FRAGMENT_TEXT_BYTES,
            crate::tool_dispatch::MAX_TOOL_RESULT_BYTES
        );
        assert_eq!(
            MAX_FRAGMENT_TEXT_BYTES,
            crate::bridge::MAX_BRIDGE_PARAMS_BYTES
        );
        assert_eq!(
            MAX_PENDING_FRAGMENTS,
            bitty_ipc_api::channel::MAX_PENDING_REQUESTS
        );
        assert_eq!(
            MAX_PENDING_FRAGMENTS,
            crate::execution::MAX_TRACKED_EXECUTIONS
        );
    }

    #[test]
    fn ingest_bounds_text_at_char_boundary_and_flags_truncation() {
        let mut service = FragmentIngestService::new();
        let text = "é".repeat(20 * 1024);
        let fragment = service
            .ingest(chunk(0, &text))
            .expect("over-budget text truncates, never rejects");
        assert!(fragment.text.len() <= MAX_FRAGMENT_TEXT_BYTES);
        assert!(fragment.truncated);
        assert!(text.starts_with(fragment.text.as_str()));
        assert!(fragment.is_untrusted_surface);
        fragment.validate().expect("stored fragment validates");
    }

    #[test]
    fn in_budget_text_is_not_flagged() {
        let mut service = FragmentIngestService::new();
        let fragment = service.ingest(chunk(0, "hello")).expect("ingest");
        assert_eq!(fragment.text, "hello");
        assert!(!fragment.truncated);
    }

    #[test]
    fn nul_is_rejected_fail_closed() {
        let mut service = FragmentIngestService::new();
        let err = service
            .ingest(chunk(0, "ab\0cd"))
            .expect_err("NUL must fail closed");
        assert!(
            matches!(err, IpcError::InvalidRequest { .. }),
            "got {err:?}"
        );
        assert!(service.is_empty(), "refused ingest stores nothing");
    }

    #[test]
    fn bad_terminal_grammar_is_rejected() {
        let mut service = FragmentIngestService::new();
        let mut data = chunk(0, "hi");
        data.terminal_id = "x:1".to_owned();
        assert!(service.ingest(data).is_err());
        let mut data = chunk(1, "hi");
        data.terminal_id = "t:01".to_owned();
        assert!(service.ingest(data).is_err());
        assert!(service.is_empty(), "refused ingest stores nothing");
    }

    #[test]
    fn duplicate_key_is_rejected_before_capacity() {
        let mut service = FragmentIngestService::new();
        service.ingest(chunk(0, "first")).expect("first ingest");
        let err = service
            .ingest(chunk(0, "replay"))
            .expect_err("replay must fail closed");
        assert!(
            matches!(err, IpcError::InvalidRequest { .. }),
            "got {err:?}"
        );
        assert_eq!(service.len(), 1);
        // Fill to capacity, then prove a replay still reports InvalidRequest,
        // not LimitExceeded (duplicate-before-capacity).
        for seq in 1..MAX_PENDING_FRAGMENTS as u64 {
            service.ingest(chunk(seq, "pad")).expect("fill to capacity");
        }
        assert_eq!(service.len(), MAX_PENDING_FRAGMENTS);
        let err = service
            .ingest(chunk(0, "replay at capacity"))
            .expect_err("replay at capacity must stay InvalidRequest");
        assert!(
            matches!(err, IpcError::InvalidRequest { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn capacity_is_fail_closed() {
        let mut service = FragmentIngestService::new();
        for seq in 0..MAX_PENDING_FRAGMENTS as u64 {
            service.ingest(chunk(seq, "pad")).expect("fill to capacity");
        }
        let err = service
            .ingest(chunk(MAX_PENDING_FRAGMENTS as u64, "one too many"))
            .expect_err("overflow must fail closed");
        assert!(matches!(err, IpcError::LimitExceeded { .. }), "got {err:?}");
        assert_eq!(service.len(), MAX_PENDING_FRAGMENTS);
    }

    #[test]
    fn distinct_generations_share_seq_space() {
        let mut service = FragmentIngestService::new();
        service.ingest(chunk(0, "gen seven")).expect("gen 7 seq 0");
        let mut other = chunk(0, "gen eight");
        other.generation = 8;
        service
            .ingest(other)
            .expect("gen 8 seq 0 is a distinct key");
        assert_eq!(service.len(), 2);
    }

    #[test]
    fn untrusted_label_cannot_be_cleared() {
        let mut service = FragmentIngestService::new();
        let mut fragment = service.ingest(chunk(0, "hi")).expect("ingest");
        assert!(fragment.is_untrusted_surface());
        fragment.is_untrusted_surface = false;
        assert!(fragment.validate().is_err());
    }

    #[test]
    fn over_ceiling_dto_fails_validation() {
        let fragment = RichFragment {
            terminal_id: "t:1".to_owned(),
            generation: 1,
            seq: 0,
            zone: None,
            text: "x".repeat(MAX_FRAGMENT_TEXT_BYTES + 1),
            truncated: true,
            is_untrusted_surface: true,
        };
        assert!(matches!(
            fragment.validate(),
            Err(IpcError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn drain_bounded_preserves_fifo_and_frees_capacity() {
        let mut service = FragmentIngestService::new();
        for seq in 0..3 {
            service
                .ingest(chunk(seq, &format!("chunk-{seq}")))
                .expect("ingest");
        }
        let drained = service.drain_bounded(2);
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].seq, 0);
        assert_eq!(drained[1].seq, 1);
        assert_eq!(service.len(), 1);
        // Drained keys are released: the same key may ingest again.
        service
            .ingest(chunk(0, "re-cut"))
            .expect("drained key is reusable");
        assert!(service.contains("t:1", 7, 0));
        assert!(!service.contains("t:1", 7, 5));
        let rest = service.drain_bounded(99);
        assert_eq!(rest.len(), 2);
        assert!(service.is_empty());
        assert!(service.drain_bounded(8).is_empty());
    }
}
