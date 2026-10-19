//! Provider-publication control record contract (pure types and codec).
//!
//! This module implements the binary control record contract and the
//! provider-routing publication payload from the draft
//! `authenticated-provider-publication` and the accepted
//! `execution-ownership-r1` provider/routing binding contract. It is a pure,
//! headless contract: no TLS, authentication, OS handles, provider I/O,
//! registry population, secret resolution, or proof minting lives here.
//!
//! Every record starts with the fixed 49-byte header:
//!
//! ```text
//! magic     4 bytes   ASCII `BPPC`
//! version   u16       `1`
//! kind      u16       records `1`..=`13`
//! sender    u8        `1` Core, `2` helper
//! sequence  u64       per-direction, starts at `1`
//! session   32 bytes  launch nonce
//! ```
//!
//! All integers are unsigned big-endian. Variable byte strings use a `u32`
//! byte length followed by exactly that many bytes. There is no padding,
//! compression, extension, duplicate field, unknown tag, or trailing byte.
//! The outer `u32` frame length from the control transport is deliberately
//! not part of this module: callers pass exactly one complete record.
//!
//! # Named bounds
//!
//! The constants in this module are the single source for the proposed policy
//! bounds used by the control record codec; TLS wrapper limits around the
//! transport stay out of scope here. They are **proposed policy
//! constants, not current implementation claims**: no transport in this
//! repository is required to implement them yet. Units are bytes, records,
//! entries, levels, or seconds as named.
//!
//! | Constant | Value | Unit / meaning |
//! | --- | --- | --- |
//! | [`CONTROL_FRAME_MAX_BYTES`] | 262144 | decrypted record bytes, excluding the outer `u32` |
//! | [`CONTROL_INFLIGHT_MAX_BYTES`] | 524288 | accepted bytes per direction |
//! | [`CONTROL_TLS_BUFFER_MAX_BYTES`] | 65536 | ciphertext/handshake buffering per direction |
//! | [`CONTROL_HANDSHAKE_MAX_BYTES`] | 65536 | handshake bytes per peer |
//! | [`CONTROL_SMALL_RECORD_MAX_BYTES`] | 4096 | complete small record |
//! | [`CONTROL_BOOTSTRAP_MAX_BYTES`] | 4096 | one launch bootstrap record |
//! | [`CONTROL_PAYLOAD_MAX_BYTES`] | 261632 | canonical publication payload (`frame - 512`) |
//! | [`CONTROL_QUEUE_MAX_RECORDS`] | 2 | queued records per direction |
//! | [`CONTROL_PENDING_PUBLICATIONS`] | 1 | current publication tuple |
//! | [`CONTROL_PENDING_STRICT_REQUESTS`] | 1 | strict data-frame permit |
//! | [`CONTROL_ACTIVE_RECEIPTS`] | 1 | current helper proof receipt |
//! | [`CONTROL_ENDPOINT_HANDLES_MAX`] | 64 | retained endpoint references per helper |
//! | [`CONTROL_MODELS_MAX`] | 64 | models across all providers |
//! | [`CONTROL_PROVIDER_GROUPS_MAX`] | 64 | provider groups (derived: every group has a model) |
//! | [`CONTROL_CAPABILITIES_MAX`] | 8 | capability labels per model |
//! | [`CONTROL_STRING_MAX_BYTES`] | 128 | one bounded identity/label string |
//! | [`CONTROL_JSON_DEPTH_MAX`] | 8 | canonical JSON nesting levels |
//! | [`LAUNCH_CERT_MAX_BYTES`] | 1024 | one DER leaf certificate |
//! | [`LAUNCH_KEY_MAX_BYTES`] | 256 | one PKCS#8 private key |
//! | [`RANDOM_ID_BYTES`] | 32 | launch/channel/lifetime/receipt identifiers |
//! | [`LIFETIME_SECRET_BYTES`] | 32 | helper-private lifetime capability |
//! | [`CONTROL_ESTABLISH_TIMEOUT`] | 5 | seconds from spawn |
//! | [`CONTROL_TRANSACTION_TIMEOUT`] | 5 | seconds per transaction |
//! | [`CONTROL_SESSION_MAX_AGE`] | 60 | seconds of authority age |
//! | [`CONTROL_RECORD_RATE`] | 100 | records per second, sustained |
//! | [`CONTROL_RECORD_BURST`] | 200 | records in one second |
//!
//! The sender accepted by a record kind is fixed by [`Kind::direction`].
//! [`ControlRecord::decode`] rejects the reserved kind, wrong senders,
//! sequence `0`, unknown closed-enum values, and contradictory establishment
//! launch nonces. It does not implement receiver state ordering; callers use
//! [`validate_incoming_sequence`] and [`validate_session`] with their own
//! per-direction high-water mark.

mod error;
mod ids;
mod payload;
mod record;
mod sha256;

#[cfg(test)]
mod tests;

pub use error::{ControlError, PayloadError, TextViolation};
pub use ids::{AckId, Digest, LifetimeId, Nonce, PublicationId, ReceiptId, SessionId};
pub use payload::{
    Capability, ModelEntry, PROVIDER_ROUTING_DOMAIN, ProviderEntry, ProviderRoutingProjection,
};
pub use record::{
    AckBody, AdmitBody, AdmittedBody, BindBody, BoundBody, ControlRecord, Direction, Domain,
    ErrorCode, EstablishedBody, EstablishmentEcho, InvalidateBody, Kind, LifetimeBody,
    ProjectionBody, PublishBody, Reason, RecordBody, RecordHeader, Sender, Tuple,
};
use std::time::Duration;

// ── fixed protocol values ──────────────────────────────────────────────────

/// ASCII magic that starts every control record.
pub const CONTROL_MAGIC: [u8; 4] = *b"BPPC";

/// Binary control record version.
pub const CONTROL_VERSION: u16 = 1;

/// Bootstrap manifest format version.
pub const BOOTSTRAP_FORMAT_VERSION: u16 = 1;

/// Control protocol version echoed in the establishment manifest.
pub const CONTROL_PROTOCOL_VERSION: u16 = CONTROL_VERSION;

/// Fixed Core role byte (`core-supervisor`, TLS client).
pub const ROLE_CORE: u8 = 1;

/// Fixed helper role byte (`ai-helper`, TLS server).
pub const ROLE_HELPER: u8 = 2;

/// Sole delegation purpose for this contract.
pub const DELEGATION_PURPOSE: &str = "provider-routing-publication";

/// Control profile and ALPN name for this contract.
pub const CONTROL_PROFILE: &str = "provider-publication-control/1";

/// ALPN protocol name; identical to [`CONTROL_PROFILE`].
pub const ALPN_PROTOCOL: &str = CONTROL_PROFILE;

/// Key-material block profile: launch-scoped ECDSA P-256 mutual certificates.
pub const KEY_MATERIAL_PROFILE: u8 = 1;

/// Key type: ECDSA P-256.
pub const KEY_TYPE_ECDSA_P256: u8 = 1;

/// Fixed record header length in bytes.
pub const CONTROL_HEADER_BYTES: usize = 4 + 2 + 2 + 1 + 8 + 32;

/// Outer control frame length prefix (`u32` big-endian) in bytes.
pub const CONTROL_FRAME_PREFIX_BYTES: usize = 4;

// ── named policy bounds ─────────────────────────────────────────────────────

/// Maximum decrypted record bytes per frame, excluding the outer `u32`.
pub const CONTROL_FRAME_MAX_BYTES: usize = 256 * 1024;

/// Accepted control bytes per direction (two-frame buffering ceiling).
pub const CONTROL_INFLIGHT_MAX_BYTES: usize = 512 * 1024;

/// Ciphertext/handshake buffering bound per direction.
pub const CONTROL_TLS_BUFFER_MAX_BYTES: usize = 64 * 1024;

/// Handshake bytes per peer, including the single self-signed leaf.
pub const CONTROL_HANDSHAKE_MAX_BYTES: usize = 64 * 1024;

/// Maximum complete record size for fixed/bounded non-payload records.
pub const CONTROL_SMALL_RECORD_MAX_BYTES: usize = 4 * 1024;

/// Maximum size of the one-shot launch bootstrap record.
pub const CONTROL_BOOTSTRAP_MAX_BYTES: usize = 4 * 1024;

/// Maximum canonical publication payload bytes (`frame - 512`).
pub const CONTROL_PAYLOAD_MAX_BYTES: usize = CONTROL_FRAME_MAX_BYTES - 512;

/// Maximum queued records per direction.
pub const CONTROL_QUEUE_MAX_RECORDS: usize = 2;

/// Maximum current publication tuples.
pub const CONTROL_PENDING_PUBLICATIONS: usize = 1;

/// Maximum pending strict data-frame permits.
pub const CONTROL_PENDING_STRICT_REQUESTS: usize = 1;

/// Maximum active helper proof receipts.
pub const CONTROL_ACTIVE_RECEIPTS: usize = 1;

/// Maximum retained endpoint handles per supervised helper.
pub const CONTROL_ENDPOINT_HANDLES_MAX: usize = 64;

/// Maximum model entries across all providers in one projection.
pub const CONTROL_MODELS_MAX: usize = 64;

/// Maximum provider groups in one projection.
///
/// Derived from [`CONTROL_MODELS_MAX`] because every group carries at least
/// one model.
pub const CONTROL_PROVIDER_GROUPS_MAX: usize = CONTROL_MODELS_MAX;

/// Maximum capability labels per model.
pub const CONTROL_CAPABILITIES_MAX: usize = 8;

/// Maximum bytes in one bounded identity/label/manifest string.
pub const CONTROL_STRING_MAX_BYTES: usize = 128;

/// Maximum canonical JSON nesting depth for the provider-routing payload.
pub const CONTROL_JSON_DEPTH_MAX: usize = 8;

/// Maximum bytes in one DER-encoded self-signed leaf certificate.
pub const LAUNCH_CERT_MAX_BYTES: usize = 1024;

/// Maximum bytes in one PKCS#8 DER private key.
pub const LAUNCH_KEY_MAX_BYTES: usize = 256;

/// Bytes in a fresh launch/channel/lifetime/receipt identifier.
pub const RANDOM_ID_BYTES: usize = 32;

/// Bytes in the helper-private lifetime capability value.
pub const LIFETIME_SECRET_BYTES: usize = 32;

/// Establishment deadline from spawn.
pub const CONTROL_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(5);

/// Whole feed/publication/ack/bind/permit transaction deadline.
pub const CONTROL_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Provider-publication authority maximum age.
pub const CONTROL_SESSION_MAX_AGE: Duration = Duration::from_secs(60);

/// Sustained control record rate per second.
pub const CONTROL_RECORD_RATE: u32 = 100;

/// Control record burst capacity in one second.
pub const CONTROL_RECORD_BURST: u32 = 200;

/// Window for [`CONTROL_RECORD_BURST`].
pub const CONTROL_RECORD_BURST_WINDOW: Duration = Duration::from_secs(1);

const _: () = assert!(CONTROL_HEADER_BYTES == 49);
const _: () = assert!(CONTROL_FRAME_MAX_BYTES == crate::frame::MAX_FRAME_BYTES);
const _: () = assert!(CONTROL_PAYLOAD_MAX_BYTES == 261_632);
const _: () = assert!(CONTROL_INFLIGHT_MAX_BYTES >= 2 * CONTROL_FRAME_MAX_BYTES);

// ── validation helpers ──────────────────────────────────────────────────────

/// Return the next exact per-direction sequence after `last_accepted`.
///
/// Sequences start at `1`: `last_accepted == 0` yields `1`. Application
/// sequence overflow is terminal and must revoke the session rather than
/// wrap.
///
/// # Errors
///
/// Returns [`ControlError::SequenceExhausted`] when `last_accepted` is
/// [`u64::MAX`].
pub fn next_expected_sequence(last_accepted: u64) -> Result<u64, ControlError> {
    last_accepted
        .checked_add(1)
        .ok_or(ControlError::SequenceExhausted)
}

/// Validate one received per-direction sequence against the last accepted one.
///
/// # Errors
///
/// Returns [`ControlError::SequenceZero`] for sequence `0`,
/// [`ControlError::SequenceExhausted`] when the peer has already consumed
/// [`u64::MAX`], or [`ControlError::SequenceMismatch`] for a skipped,
/// replayed, duplicate, or reordered value.
pub fn validate_incoming_sequence(last_accepted: u64, received: u64) -> Result<(), ControlError> {
    if received == 0 {
        return Err(ControlError::SequenceZero);
    }
    let expected = next_expected_sequence(last_accepted)?;
    if received != expected {
        return Err(ControlError::SequenceMismatch { expected, received });
    }
    Ok(())
}

/// Compare the session binding of an authenticated control stream.
///
/// # Errors
///
/// Returns [`ControlError::SessionMismatch`] when the launch nonces differ.
pub fn validate_session(expected: SessionId, received: SessionId) -> Result<(), ControlError> {
    if expected == received {
        Ok(())
    } else {
        Err(ControlError::SessionMismatch)
    }
}
