//! Error vocabulary for the provider-publication control contract.

use std::fmt;

use super::record::{Kind, Sender};

/// Why a bounded text field was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextViolation {
    /// The field is empty.
    Empty,
    /// The field is longer than [`super::CONTROL_STRING_MAX_BYTES`].
    TooLong {
        /// Configured limit in bytes.
        limit: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// The field contains a Unicode control character.
    ControlCharacter,
    /// The field is not valid UTF-8.
    InvalidUtf8,
}

/// Why a provider-routing canonical payload was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadError {
    /// Canonical payload exceeds [`super::CONTROL_PAYLOAD_MAX_BYTES`].
    TooLarge {
        /// Actual byte length.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// JSON nesting exceeds [`super::CONTROL_JSON_DEPTH_MAX`].
    JsonDepthExceeded {
        /// Configured limit.
        limit: usize,
    },
    /// The payload is not well-formed canonical JSON.
    InvalidJson,
    /// The payload domain is not `provider-routing`.
    InvalidDomain,
    /// The payload bytes are well-formed but not in canonical form.
    NonCanonical,
    /// Two provider groups use the same identity.
    DuplicateProvider,
    /// Two models in one provider use the same name.
    DuplicateModel,
    /// A model repeats a capability label.
    DuplicateCapability,
    /// A provider group carries no models.
    EmptyProviderGroup,
    /// A model carries no capability labels.
    EmptyCapabilityGroup,
    /// A provider group carries more models than the remaining total allows.
    TooManyModels {
        /// Actual total model count.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// More provider groups than the contract allows.
    TooManyProviders {
        /// Actual group count.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// A model carries more capability labels than the contract allows.
    TooManyCapabilities {
        /// Actual label count.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// A capability label is outside the closed vocabulary.
    UnknownCapability,
    /// A bounded provider or model string is invalid.
    InvalidText {
        /// Stable field name.
        field: &'static str,
        /// Why the text was refused.
        reason: TextViolation,
    },
    /// A registry integer exceeded the `u32` range or was not canonical.
    NumberOutOfRange {
        /// Stable field name.
        field: &'static str,
    },
}

impl fmt::Display for TextViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("must not be empty"),
            Self::TooLong { limit, actual } => {
                write!(f, "{actual} bytes exceeds the {limit}-byte limit")
            }
            Self::ControlCharacter => f.write_str("must not contain control characters"),
            Self::InvalidUtf8 => f.write_str("must be valid UTF-8"),
        }
    }
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { actual, limit } => {
                write!(f, "payload is {actual} bytes, limit {limit}")
            }
            Self::JsonDepthExceeded { limit } => {
                write!(f, "canonical JSON exceeds depth {limit}")
            }
            Self::InvalidJson => f.write_str("payload is not canonical JSON"),
            Self::InvalidDomain => f.write_str("payload domain is not provider-routing"),
            Self::NonCanonical => f.write_str("payload is not in canonical byte form"),
            Self::DuplicateProvider => f.write_str("duplicate provider identity"),
            Self::DuplicateModel => f.write_str("duplicate model name within a provider"),
            Self::DuplicateCapability => f.write_str("duplicate capability label"),
            Self::EmptyProviderGroup => f.write_str("provider group has no models"),
            Self::EmptyCapabilityGroup => f.write_str("model has no capabilities"),
            Self::TooManyModels { actual, limit } => {
                write!(f, "{actual} models exceeds the {limit}-model limit")
            }
            Self::TooManyProviders { actual, limit } => {
                write!(
                    f,
                    "{actual} provider groups exceeds the {limit}-group limit"
                )
            }
            Self::TooManyCapabilities { actual, limit } => {
                write!(
                    f,
                    "{actual} capabilities exceeds the {limit}-capability limit"
                )
            }
            Self::UnknownCapability => f.write_str("capability label is outside the closed set"),
            Self::InvalidText { field, reason } => write!(f, "{field} {reason}"),
            Self::NumberOutOfRange { field } => {
                write!(f, "{field} is outside the canonical u32 range")
            }
        }
    }
}

impl std::error::Error for PayloadError {}

/// A provider-publication control codec or contract failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    /// The record ended before a field could be read.
    Truncated {
        /// Stable field name.
        field: &'static str,
        /// Bytes required by the field.
        needed: usize,
        /// Bytes remaining in the record.
        remaining: usize,
    },
    /// A complete record exceeds [`super::CONTROL_FRAME_MAX_BYTES`].
    FrameTooLarge {
        /// Actual byte length.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// Bytes remain after the exact body.
    TrailingBytes {
        /// Number of unconsumed bytes.
        remaining: usize,
    },
    /// The magic prefix is not ASCII `BPPC`.
    InvalidMagic,
    /// The header or manifest version is unsupported.
    UnsupportedVersion {
        /// Version found on the wire.
        actual: u16,
    },
    /// The record kind is outside `1`..=`13`.
    UnknownKind {
        /// Kind found on the wire.
        actual: u16,
    },
    /// The sender byte is neither `1` nor `2`.
    UnknownSender {
        /// Sender found on the wire.
        actual: u8,
    },
    /// Kind `9` is reserved and is a protocol error in either direction.
    ReservedKind,
    /// The record kind is not legal for the sender.
    WrongDirection {
        /// Record kind.
        kind: Kind,
        /// Sender found on the wire.
        sender: Sender,
    },
    /// A fixed establishment role byte was not `1` then `2`.
    InvalidRole {
        /// Role byte position (`0` Core, `1` helper).
        index: u8,
        /// Role byte found on the wire.
        actual: u8,
    },
    /// The bootstrap format version is unsupported.
    UnsupportedBootstrapVersion {
        /// Version found in the record.
        actual: u16,
    },
    /// The control protocol version is unsupported.
    UnsupportedControlProtocolVersion {
        /// Version found in the record.
        actual: u16,
    },
    /// The key-material profile is unsupported.
    UnsupportedKeyMaterialProfile {
        /// Profile found in the record.
        actual: u8,
    },
    /// The key type is unsupported.
    UnsupportedKeyType {
        /// Key type found in the record.
        actual: u8,
    },
    /// A fixed constant field did not match the contract.
    UnexpectedConstant {
        /// Stable field name.
        field: &'static str,
    },
    /// The tuple domain byte is not `1`.
    UnknownDomain {
        /// Domain found on the wire.
        actual: u8,
    },
    /// The invalidation reason is outside `1`..=`6`.
    UnknownReason {
        /// Reason found on the wire.
        actual: u8,
    },
    /// The error code is outside `1`..=`4`.
    UnknownErrorCode {
        /// Error code found on the wire.
        actual: u8,
    },
    /// A bounded text field is invalid.
    InvalidText {
        /// Stable field name.
        field: &'static str,
        /// Why the text was refused.
        reason: TextViolation,
    },
    /// A declared field length exceeds its named bound.
    FieldTooLarge {
        /// Stable field name.
        field: &'static str,
        /// Configured limit.
        limit: usize,
        /// Declared length.
        actual: usize,
    },
    /// A required `u64` is zero.
    ZeroValue {
        /// Stable field name.
        field: &'static str,
    },
    /// A carried digest does not match the canonical payload bytes.
    DigestMismatch,
    /// The establishment echo launch nonce differs from the header session.
    SessionMismatch,
    /// A non-payload record exceeds [`super::CONTROL_SMALL_RECORD_MAX_BYTES`].
    SmallRecordTooLarge {
        /// Actual record length.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// A declared payload length exceeds [`super::CONTROL_PAYLOAD_MAX_BYTES`].
    PayloadTooLarge {
        /// Declared or actual length.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// The canonical provider-routing payload is invalid.
    Payload(PayloadError),
    /// A sequence value was zero.
    SequenceZero,
    /// A sequence value was not the exact next value for its direction.
    SequenceMismatch {
        /// Exact expected value.
        expected: u64,
        /// Received value.
        received: u64,
    },
    /// The per-direction sequence cannot advance past [`u64::MAX`].
    SequenceExhausted,
    /// Length arithmetic overflowed `usize`.
    LengthOverflow,
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                field,
                needed,
                remaining,
            } => write!(f, "{field} needs {needed} bytes, {remaining} remain"),
            Self::FrameTooLarge { actual, limit } => {
                write!(f, "record is {actual} bytes, limit {limit}")
            }
            Self::TrailingBytes { remaining } => {
                write!(f, "{remaining} trailing bytes after the record body")
            }
            Self::InvalidMagic => f.write_str("control magic is not BPPC"),
            Self::UnsupportedVersion { actual } => {
                write!(f, "unsupported control record version {actual}")
            }
            Self::UnknownKind { actual } => write!(f, "unknown control record kind {actual}"),
            Self::UnknownSender { actual } => write!(f, "unknown control sender {actual}"),
            Self::ReservedKind => f.write_str("control kind 9 is reserved"),
            Self::WrongDirection { kind, sender } => {
                write!(f, "{kind} is not legal for sender {sender}")
            }
            Self::InvalidRole { index, actual } => {
                write!(
                    f,
                    "establishment role {index} is {actual}, not the fixed role"
                )
            }
            Self::UnsupportedBootstrapVersion { actual } => {
                write!(f, "unsupported bootstrap format version {actual}")
            }
            Self::UnsupportedControlProtocolVersion { actual } => {
                write!(f, "unsupported control protocol version {actual}")
            }
            Self::UnsupportedKeyMaterialProfile { actual } => {
                write!(f, "unsupported key-material profile {actual}")
            }
            Self::UnsupportedKeyType { actual } => {
                write!(f, "unsupported key type {actual}")
            }
            Self::UnexpectedConstant { field } => write!(f, "{field} does not match the contract"),
            Self::UnknownDomain { actual } => write!(f, "unknown domain byte {actual}"),
            Self::UnknownReason { actual } => write!(f, "unknown invalidation reason {actual}"),
            Self::UnknownErrorCode { actual } => write!(f, "unknown error code {actual}"),
            Self::InvalidText { field, reason } => write!(f, "{field} {reason}"),
            Self::FieldTooLarge {
                field,
                limit,
                actual,
            } => write!(f, "{field} is {actual} bytes, limit {limit}"),
            Self::ZeroValue { field } => write!(f, "{field} must not be zero"),
            Self::DigestMismatch => f.write_str("digest does not match the canonical payload"),
            Self::SessionMismatch => f.write_str("launch nonce differs from the header session"),
            Self::SmallRecordTooLarge { actual, limit } => {
                write!(f, "small record is {actual} bytes, limit {limit}")
            }
            Self::PayloadTooLarge { actual, limit } => {
                write!(f, "payload is {actual} bytes, limit {limit}")
            }
            Self::Payload(error) => write!(f, "payload: {error}"),
            Self::SequenceZero => f.write_str("control sequence must start at 1"),
            Self::SequenceMismatch { expected, received } => {
                write!(f, "control sequence {received}, expected {expected}")
            }
            Self::SequenceExhausted => f.write_str("control sequence exhausted"),
            Self::LengthOverflow => f.write_str("control length arithmetic overflow"),
        }
    }
}

impl std::error::Error for ControlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Payload(error) => Some(error),
            _ => None,
        }
    }
}
