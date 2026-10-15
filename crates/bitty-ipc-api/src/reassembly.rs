//! Generic wire-level chunk receiver (RC-10 reassembly).
//!
//! [`validate_chunk`](crate::wire::validate_chunk) gates each chunk in
//! isolation (`seq < total`, `total > 0`, `bytes <= 256 KiB`); it cannot tell
//! whether the chunks of one logical payload fit together. [`ChunkReassembler`]
//! closes that gap: feed validated chunks in, get exactly-once completed
//! payloads out.
//!
//! The design generalizes the devtools-local continuation pattern without
//! moving it: unlike that single-connection, strictly-ordered state machine,
//! this receiver multiplexes many interleaved assemblies by envelope `id` and
//! accepts out-of-order chunks, buffering each sequence slot until the set is
//! complete. What it keeps from the pattern is the fail-closed discipline:
//! any violation discards the offending assembly (never a silent
//! dedupe-accept), stale assemblies expire on caller-supplied `now_ms`
//! (deterministic, no clock), and every allocation is pre-bounded.
//!
//! This module is headless, bounded, `forbid(unsafe)`, and keeps no
//! dependencies beyond `std`. No socket, transport, I/O, clock, or threads.

use std::collections::HashMap;

use crate::error::IpcError;
use crate::wire::{MAX_ID_BYTES, validate_chunk};

/// Per-assembly byte cap: exactly the RC-9 logical payload cap (1 MiB).
///
/// Rationale: reassembled output feeds handlers gated by that same cap, so
/// parity guarantees this layer can never hand downstream a payload the next
/// layer must refuse. Chunks carry no declared byte total, so the cap is
/// enforced incrementally: the chunk that would push an assembly past it is
/// refused with `Denied/PayloadCap`, the same code the RC-9
/// `check_payload_cap` helper uses.
pub const MAX_ASSEMBLY_BYTES: usize = 1024 * 1024;

/// Maximum chunk count (`total`) per assembly.
///
/// Rationale: a canonical RC-10 sender emits `<= 256 KiB` chunks, so a full
/// 1 MiB payload needs only 4; 64 gives 16x headroom (average chunk `>= 16
/// KiB` at full size) while bounding the per-assembly slot table to 64
/// entries (~1.5 KiB). A larger declared `total` is refused before any slot
/// allocation, so a hostile `total: u32::MAX` cannot force allocation.
pub const MAX_CHUNKS_PER_ASSEMBLY: u32 = 64;

/// Maximum concurrently open assemblies.
///
/// Rationale: parity with the RC-9 connection ceiling (16 per endpoint); one
/// in-flight reassembly per connection is the expected shape, so worst-case
/// buffered bytes are `16 x 1 MiB`, all refuse-on-excess. A new assembly past
/// the ceiling is refused without touching open ones.
pub const MAX_OPEN_ASSEMBLIES: usize = 16;

/// Stale-assembly TTL in milliseconds, measured from the first chunk.
///
/// Rationale: parity with the devtools continuation deadline (5 s for the
/// same 1 MiB logical budget); an assembly that cannot complete within one
/// budget window is discarded fail-closed. Expiry runs on caller-supplied
/// `now_ms` only: backwards clock steps saturate to zero elapsed and never
/// expire early.
pub const REASSEMBLY_TTL_MS: u64 = 5_000;

/// Outcome of feeding one chunk to a [`ChunkReassembler`].
#[derive(Debug, PartialEq, Eq)]
pub enum FeedOutcome {
    /// Chunk buffered; the assembly needs more sequence numbers.
    Pending,
    /// All `total` sequence numbers arrived exactly once. The assembly is
    /// consumed, so this payload is delivered exactly once: a later duplicate
    /// finds no open assembly and is refused, never re-delivered.
    Complete(Vec<u8>),
}

/// One open assembly: the buffered slots of a single envelope `id`.
#[derive(Debug)]
struct Assembly {
    /// Declared chunk count; every chunk of this assembly must agree on it.
    total: u32,
    /// Slots filled so far.
    received: u32,
    /// Sum of buffered chunk lengths; always `<= MAX_ASSEMBLY_BYTES`.
    bytes: usize,
    /// `now_ms` of the first chunk; expiry anchor.
    started_ms: u64,
    /// Chunk bytes by sequence number; `slots[seq]` is `Some` once seen.
    slots: Vec<Option<Vec<u8>>>,
}

/// Generic receiver for RC-10 chunk frames.
///
/// Feed every validated chunk through [`Self::feed`] keyed by its envelope
/// `id`. Assemblies interleave freely and chunks may arrive out of order;
/// each sequence number is accepted exactly once per assembly, and completion
/// concatenates slots in sequence order. Every violation (duplicate,
/// conflicting `total`, byte-cap breach, oversize declaration, stale feed,
/// unknown shape) discards only the offending assembly and reports an
/// [`IpcError`]; other assemblies are untouched.
///
/// Replay boundary: completion consumes the assembly, so a duplicate that
/// arrives *while open* is refused, and a lone post-completion re-feed opens
/// a fresh assembly rather than re-delivering. A byte-identical full replay
/// after completion would assemble anew; callers needing cross-completion
/// dedup must key on the envelope `id` at the dispatch layer, which owns
/// exactly-once execution.
#[derive(Debug, Default)]
pub struct ChunkReassembler {
    assemblies: HashMap<String, Assembly>,
}

impl ChunkReassembler {
    /// A receiver with no open assemblies.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of currently open assemblies.
    #[must_use]
    pub fn open_count(&self) -> usize {
        self.assemblies.len()
    }

    /// Whether no assembly is open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.assemblies.is_empty()
    }

    /// Whether `id` has an open assembly.
    #[must_use]
    pub fn is_open(&self, id: &str) -> bool {
        self.assemblies.contains_key(id)
    }

    /// Feed one validated chunk read at `now_ms`.
    ///
    /// Runs [`validate_chunk`](crate::wire::validate_chunk) again so the type
    /// stays fail-closed even if a caller skips the per-chunk gate, then
    /// applies assembly-level checks (id bound, chunk-count bound, open-count
    /// bound, `total` agreement, staleness, duplicate, byte cap) in that
    /// order. Reasons never echo peer bytes: only sequence numbers, counts,
    /// and limits appear.
    ///
    /// # Errors
    ///
    /// Returns the [`validate_chunk`](crate::wire::validate_chunk) error for
    /// malformed chunks, [`IpcError::InvalidRequest`] for an unusable `id`,
    /// [`IpcError::PayloadTooLarge`] for an oversize `total` declaration,
    /// [`IpcError::PendingLimitExceeded`] past [`MAX_OPEN_ASSEMBLIES`], and
    /// [`IpcError::Denied`] (`ChunkConflict`, `ChunkDuplicate`, `PayloadCap`,
    /// `ReassemblyExpired`) for assembly violations. Any error discards the
    /// offending assembly when one is open; a ceiling refusal creates none.
    pub fn feed(
        &mut self,
        id: &str,
        seq: u32,
        total: u32,
        chunk: &[u8],
        now_ms: u64,
    ) -> Result<FeedOutcome, IpcError> {
        validate_chunk(seq, total, chunk)?;
        if id.is_empty() || id.len() > MAX_ID_BYTES {
            return Err(IpcError::InvalidRequest {
                reason: "chunk assembly id must be 1..=64 bytes".into(),
            });
        }
        if total > MAX_CHUNKS_PER_ASSEMBLY {
            self.assemblies.remove(id);
            return Err(IpcError::PayloadTooLarge {
                field: "chunk.total".into(),
                limit: MAX_CHUNKS_PER_ASSEMBLY as usize,
                actual: total as usize,
            });
        }
        let outcome = self.feed_inner(id, seq, total, chunk, now_ms);
        if outcome.is_err() {
            self.assemblies.remove(id);
        }
        outcome
    }

    /// Discard assemblies whose first chunk is older than
    /// [`REASSEMBLY_TTL_MS`]. Returns the number discarded.
    pub fn expire_stale(&mut self, now_ms: u64) -> usize {
        let before = self.assemblies.len();
        self.assemblies
            .retain(|_, a| now_ms.saturating_sub(a.started_ms) <= REASSEMBLY_TTL_MS);
        before - self.assemblies.len()
    }

    fn feed_inner(
        &mut self,
        id: &str,
        seq: u32,
        total: u32,
        chunk: &[u8],
        now_ms: u64,
    ) -> Result<FeedOutcome, IpcError> {
        if !self.assemblies.contains_key(id) {
            if self.assemblies.len() >= MAX_OPEN_ASSEMBLIES {
                return Err(IpcError::PendingLimitExceeded {
                    limit: MAX_OPEN_ASSEMBLIES,
                    actual: self.assemblies.len(),
                });
            }
            // `total >= 1` (per-chunk gate) and `total <= 64` (checked above),
            // so this table is at most 64 entries.
            self.assemblies.insert(
                id.to_owned(),
                Assembly {
                    total,
                    received: 0,
                    bytes: 0,
                    started_ms: now_ms,
                    slots: vec![None; total as usize],
                },
            );
        }
        let assembly = self.assemblies.get_mut(id).expect("just inserted or open");
        if now_ms.saturating_sub(assembly.started_ms) > REASSEMBLY_TTL_MS {
            return Err(IpcError::Denied {
                code: "ReassemblyExpired".into(),
                reason: format!("assembly exceeded {REASSEMBLY_TTL_MS} ms budget"),
            });
        }
        if total != assembly.total {
            return Err(IpcError::Denied {
                code: "ChunkConflict".into(),
                reason: format!(
                    "chunk total {total} conflicts with declared {}",
                    assembly.total
                ),
            });
        }
        if assembly.slots[seq as usize].is_some() {
            return Err(IpcError::Denied {
                code: "ChunkDuplicate".into(),
                reason: format!("duplicate chunk seq {seq} of {total}"),
            });
        }
        if assembly.bytes.saturating_add(chunk.len()) > MAX_ASSEMBLY_BYTES {
            return Err(IpcError::Denied {
                code: "PayloadCap".into(),
                reason: format!(
                    "assembly would exceed {MAX_ASSEMBLY_BYTES} bytes with chunk seq {seq}"
                ),
            });
        }
        assembly.slots[seq as usize] = Some(chunk.to_vec());
        assembly.received += 1;
        assembly.bytes += chunk.len();
        if assembly.received < assembly.total {
            return Ok(FeedOutcome::Pending);
        }
        let assembly = self.assemblies.remove(id).expect("open assembly");
        let mut payload = Vec::with_capacity(assembly.bytes);
        for slot in assembly.slots {
            payload.extend_from_slice(slot.as_ref().expect("all slots filled"));
        }
        Ok(FeedOutcome::Complete(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::CHUNK_CEILING;

    fn denied_code(err: &IpcError) -> &str {
        match err {
            IpcError::Denied { code, .. } => code,
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn caps_match_rc9_and_frame_bounds() {
        assert_eq!(MAX_ASSEMBLY_BYTES, 1024 * 1024);
        assert_eq!(MAX_ASSEMBLY_BYTES, CHUNK_CEILING * 4);
        assert_eq!(REASSEMBLY_TTL_MS, 5_000);
        assert_eq!(MAX_OPEN_ASSEMBLIES, 16);
    }

    #[test]
    fn in_order_chunks_complete() {
        let mut r = ChunkReassembler::new();
        assert_eq!(r.feed("a", 0, 3, b"one", 0).unwrap(), FeedOutcome::Pending);
        assert_eq!(r.feed("a", 1, 3, b"two", 0).unwrap(), FeedOutcome::Pending);
        assert!(r.is_open("a"));
        assert_eq!(
            r.feed("a", 2, 3, b"three", 0).unwrap(),
            FeedOutcome::Complete(b"onetwothree".to_vec())
        );
        assert!(r.is_empty());
    }

    #[test]
    fn out_of_order_chunks_complete_in_sequence_order() {
        let mut r = ChunkReassembler::new();
        assert_eq!(r.feed("a", 2, 3, b"C", 0).unwrap(), FeedOutcome::Pending);
        assert_eq!(r.feed("a", 0, 3, b"A", 0).unwrap(), FeedOutcome::Pending);
        assert_eq!(
            r.feed("a", 1, 3, b"B", 0).unwrap(),
            FeedOutcome::Complete(b"ABC".to_vec())
        );
    }

    #[test]
    fn single_chunk_assembly_completes_at_once() {
        let mut r = ChunkReassembler::new();
        assert_eq!(
            r.feed("solo", 0, 1, b"only", 7).unwrap(),
            FeedOutcome::Complete(b"only".to_vec())
        );
    }

    #[test]
    fn duplicate_chunk_is_refused_and_discards_assembly() {
        let mut r = ChunkReassembler::new();
        assert_eq!(r.feed("a", 0, 2, b"x", 0).unwrap(), FeedOutcome::Pending);
        let err = r.feed("a", 0, 2, b"x", 0).unwrap_err();
        assert_eq!(denied_code(&err), "ChunkDuplicate");
        assert!(!r.is_open("a"), "violation must discard the assembly");
        // The same id must restart from scratch: the duplicate bought nothing.
        assert_eq!(r.feed("a", 0, 2, b"x", 0).unwrap(), FeedOutcome::Pending);
        assert_eq!(
            r.feed("a", 1, 2, b"y", 0).unwrap(),
            FeedOutcome::Complete(b"xy".to_vec())
        );
    }

    #[test]
    fn duplicate_after_completion_does_not_redeliver() {
        let mut r = ChunkReassembler::new();
        assert_eq!(r.feed("a", 0, 2, b"do", 0).unwrap(), FeedOutcome::Pending);
        assert_eq!(
            r.feed("a", 1, 2, b"ne", 0).unwrap(),
            FeedOutcome::Complete(b"done".to_vec())
        );
        // A lone re-feed opens a fresh assembly (Pending), never a replay.
        assert_eq!(r.feed("a", 0, 2, b"do", 0).unwrap(), FeedOutcome::Pending);
    }

    #[test]
    fn conflicting_total_is_refused() {
        let mut r = ChunkReassembler::new();
        assert_eq!(r.feed("a", 0, 3, b"x", 0).unwrap(), FeedOutcome::Pending);
        let err = r.feed("a", 1, 4, b"y", 0).unwrap_err();
        assert_eq!(denied_code(&err), "ChunkConflict");
        assert!(!r.is_open("a"));
    }

    #[test]
    fn oversize_byte_sum_is_refused_with_payload_cap() {
        let mut r = ChunkReassembler::new();
        let big = vec![0xABu8; CHUNK_CEILING];
        for seq in 0..4 {
            assert_eq!(r.feed("a", seq, 5, &big, 0).unwrap(), FeedOutcome::Pending);
        }
        // 4 x 256 KiB == 1 MiB exactly; any further byte breaches the cap.
        let err = r.feed("a", 4, 5, b"one byte too many", 0).unwrap_err();
        assert_eq!(denied_code(&err), "PayloadCap");
        assert!(!r.is_open("a"));
    }

    #[test]
    fn exact_cap_boundary_completes() {
        let mut r = ChunkReassembler::new();
        let big = vec![0xCDu8; CHUNK_CEILING];
        for seq in 0..3 {
            assert_eq!(
                r.feed("full", seq, 4, &big, 0).unwrap(),
                FeedOutcome::Pending
            );
        }
        let mut expected = Vec::with_capacity(MAX_ASSEMBLY_BYTES);
        for _ in 0..4 {
            expected.extend_from_slice(&big);
        }
        assert_eq!(
            r.feed("full", 3, 4, &big, 0).unwrap(),
            FeedOutcome::Complete(expected)
        );
    }

    #[test]
    fn oversize_total_declaration_is_refused_before_allocation() {
        let mut r = ChunkReassembler::new();
        let err = r
            .feed("evil", 0, MAX_CHUNKS_PER_ASSEMBLY + 1, b"x", 0)
            .unwrap_err();
        assert!(matches!(err, IpcError::PayloadTooLarge { .. }));
        assert!(!r.is_open("evil"));
    }

    #[test]
    fn open_ceiling_sheds_newest_without_touching_open() {
        let mut r = ChunkReassembler::new();
        for i in 0..MAX_OPEN_ASSEMBLIES {
            let id = format!("id-{i}");
            assert_eq!(r.feed(&id, 0, 2, b"x", 0).unwrap(), FeedOutcome::Pending);
        }
        let err = r.feed("newest", 0, 2, b"x", 0).unwrap_err();
        assert!(matches!(err, IpcError::PendingLimitExceeded { .. }));
        assert!(!r.is_open("newest"));
        assert!(r.is_open("id-0"));
        assert_eq!(r.open_count(), MAX_OPEN_ASSEMBLIES);
    }

    #[test]
    fn stale_feed_is_refused_and_sweep_discards_only_stale() {
        let mut r = ChunkReassembler::new();
        assert_eq!(r.feed("old", 0, 2, b"x", 0).unwrap(), FeedOutcome::Pending);
        assert_eq!(
            r.feed("new", 0, 2, b"x", REASSEMBLY_TTL_MS).unwrap(),
            FeedOutcome::Pending
        );
        // On-deadline feed is still accepted.
        assert_eq!(
            r.feed("new", 1, 2, b"y", REASSEMBLY_TTL_MS).unwrap(),
            FeedOutcome::Complete(b"xy".to_vec())
        );
        // Past-deadline feed on the old assembly is refused.
        let err = r
            .feed("old", 1, 2, b"y", REASSEMBLY_TTL_MS + 1)
            .unwrap_err();
        assert_eq!(denied_code(&err), "ReassemblyExpired");
        assert!(!r.is_open("old"));
    }

    #[test]
    fn expire_stale_sweeps_by_first_chunk_age() {
        let mut r = ChunkReassembler::new();
        assert_eq!(r.feed("a", 0, 2, b"x", 0).unwrap(), FeedOutcome::Pending);
        assert_eq!(
            r.feed("b", 0, 2, b"x", 1_000).unwrap(),
            FeedOutcome::Pending
        );
        assert_eq!(r.expire_stale(1_000 + REASSEMBLY_TTL_MS), 1);
        assert!(!r.is_open("a"));
        assert!(r.is_open("b"));
        assert_eq!(r.expire_stale(u64::MAX), 1);
        assert!(r.is_empty());
    }

    #[test]
    fn backwards_clock_never_expires_early() {
        let mut r = ChunkReassembler::new();
        assert_eq!(
            r.feed("a", 0, 2, b"x", 5_000).unwrap(),
            FeedOutcome::Pending
        );
        assert_eq!(r.expire_stale(0), 0);
        assert_eq!(
            r.feed("a", 1, 2, b"y", 0).unwrap(),
            FeedOutcome::Complete(b"xy".to_vec())
        );
    }

    #[test]
    fn interleaved_assemblies_complete_independently() {
        let mut r = ChunkReassembler::new();
        assert_eq!(r.feed("a", 1, 2, b"A2", 0).unwrap(), FeedOutcome::Pending);
        assert_eq!(r.feed("b", 0, 2, b"B1", 0).unwrap(), FeedOutcome::Pending);
        assert_eq!(
            r.feed("b", 1, 2, b"B2", 0).unwrap(),
            FeedOutcome::Complete(b"B1B2".to_vec())
        );
        assert!(r.is_open("a"));
        assert!(!r.is_open("b"));
        assert_eq!(
            r.feed("a", 0, 2, b"A1", 0).unwrap(),
            FeedOutcome::Complete(b"A1A2".to_vec())
        );
        assert!(r.is_empty());
    }

    #[test]
    fn violation_in_one_assembly_leaves_others_open() {
        let mut r = ChunkReassembler::new();
        assert_eq!(r.feed("good", 0, 2, b"x", 0).unwrap(), FeedOutcome::Pending);
        assert_eq!(r.feed("bad", 0, 2, b"x", 0).unwrap(), FeedOutcome::Pending);
        assert!(r.feed("bad", 0, 2, b"x", 0).is_err());
        assert!(!r.is_open("bad"));
        assert!(r.is_open("good"));
        assert_eq!(
            r.feed("good", 1, 2, b"y", 0).unwrap(),
            FeedOutcome::Complete(b"xy".to_vec())
        );
    }

    #[test]
    fn per_chunk_gate_still_applies_inside_feed() {
        let mut r = ChunkReassembler::new();
        assert!(r.feed("a", 3, 3, b"x", 0).is_err()); // seq >= total
        assert!(r.feed("a", 0, 0, b"x", 0).is_err()); // total == 0
        let big = vec![0u8; CHUNK_CEILING + 1];
        assert!(r.feed("a", 0, 2, &big, 0).is_err()); // chunk over ceiling
        assert!(!r.is_open("a"));
    }

    #[test]
    fn assembly_id_is_bounded() {
        let mut r = ChunkReassembler::new();
        assert!(r.feed("", 0, 1, b"x", 0).is_err());
        let long = "i".repeat(MAX_ID_BYTES + 1);
        assert!(r.feed(&long, 0, 1, b"x", 0).is_err());
        let max = "i".repeat(MAX_ID_BYTES);
        assert_eq!(
            r.feed(&max, 0, 1, b"x", 0).unwrap(),
            FeedOutcome::Complete(b"x".to_vec())
        );
    }
}
