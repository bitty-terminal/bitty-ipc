//! `bitty-ipc-api`: Pure API types for Bitty IPC (zero dependencies).
//!
//! This crate contains only type definitions, constants, and traits for the
//! IPC boundary. It has **zero dependencies** and is the only crate that
//! cross-repo consumers (like `bitty-agent`, `bitty-ai`) depend on.
//!
//! # What this crate owns
//!
//! - Error types: `IpcError`, `ErrorClass`
//! - S2 refusal mapping: `AgentRefusal` (wiring item 4)
//! - Correlation: `WireBinding`, `AttributionHandles`, `args_digest` (item 5)
//! - Timeout mapping: `validate_domain_timeout`, `domain_deadline_ms` (item 6)
//! - JSON mapping rules and string bounds: `validate_params_json` (item 2)
//! - Per-method `ai.*` params/result schemas: `validate_ai_params` (CTX-0011)
//! - Scope types: `Scope`, `ScopeSet`, `ConsentGrant`, `ConsentLedger`
//! - Wire types: wire version, envelope validation bounds
//! - Chunk reassembly: `ChunkReassembler`, `FeedOutcome`, assembly bounds
//! - Frame types: `Frame`, frame size bounds
//! - Channel types: `RequestId`, `IpcRequest`, `IpcResponse`, capacity bounds
//!
//! # Architecture
//!
//! This is the **API layer** in the bitty-ipc stack:
//!
//! ```text
//! bitty-ipc-api (this crate) ← zero dependencies
//!     ↑
//! bitty-ipc-core
//!     ↑
//! bitty-ipc-auth, bitty-ipc-devtools
//!     ↑
//! bitty-ipc
//! ```

#![forbid(unsafe_code)]

pub mod channel;
pub mod correlation;
pub mod deadline;
pub mod error;
pub mod frame;
pub mod json;
pub mod provider_publication;
pub mod reassembly;
pub mod refusal;
pub mod schema;
pub mod scope;
pub mod wire;

pub use channel::{
    BoundedChannel, DEFAULT_REQUEST_CAPACITY, DEFAULT_RESPONSE_CAPACITY, IpcEndpoint, IpcRequest,
    IpcResponse, MAX_CHANNEL_CAPACITY, MAX_METHOD_BYTES, MAX_PENDING_REQUESTS, RequestId,
};
pub use correlation::{AttributionHandles, WireBinding, args_digest, verify_args_digest};
pub use deadline::{
    DOMAIN_DEFAULT_TIMEOUT_MS, DOMAIN_TIMEOUT_CEILING_MS, domain_deadline_ms,
    validate_domain_timeout,
};
pub use error::{ErrorClass, IpcError};
pub use frame::{Frame, Framer, MAX_BUFFERED_BYTES, MAX_FRAME_BYTES, decode_frame, encode_frame};
pub use json::{
    MAX_AGENT_ALIAS_BYTES, MAX_MANIFEST_FIELD_BYTES, validate_alias, validate_manifest_field,
    validate_params_json, validate_result_json,
};
pub use provider_publication::{
    ALPN_PROTOCOL, AckBody, AckId, AdmitBody, AdmittedBody, BOOTSTRAP_FORMAT_VERSION, BindBody,
    BoundBody, CONTROL_ACTIVE_RECEIPTS, CONTROL_BOOTSTRAP_MAX_BYTES, CONTROL_CAPABILITIES_MAX,
    CONTROL_ENDPOINT_HANDLES_MAX, CONTROL_ESTABLISH_TIMEOUT, CONTROL_FRAME_MAX_BYTES,
    CONTROL_FRAME_PREFIX_BYTES, CONTROL_HANDSHAKE_MAX_BYTES, CONTROL_HEADER_BYTES,
    CONTROL_INFLIGHT_MAX_BYTES, CONTROL_JSON_DEPTH_MAX, CONTROL_MAGIC, CONTROL_MODELS_MAX,
    CONTROL_PAYLOAD_MAX_BYTES, CONTROL_PENDING_PUBLICATIONS, CONTROL_PENDING_STRICT_REQUESTS,
    CONTROL_PROFILE, CONTROL_PROTOCOL_VERSION, CONTROL_PROVIDER_GROUPS_MAX,
    CONTROL_QUEUE_MAX_RECORDS, CONTROL_RECORD_BURST, CONTROL_RECORD_BURST_WINDOW,
    CONTROL_RECORD_RATE, CONTROL_SESSION_MAX_AGE, CONTROL_SMALL_RECORD_MAX_BYTES,
    CONTROL_STRING_MAX_BYTES, CONTROL_TLS_BUFFER_MAX_BYTES, CONTROL_TRANSACTION_TIMEOUT,
    CONTROL_VERSION, Capability, ControlError, ControlRecord, DELEGATION_PURPOSE, Digest,
    Direction, Domain, ErrorCode, EstablishedBody, EstablishmentEcho, InvalidateBody,
    KEY_MATERIAL_PROFILE, KEY_TYPE_ECDSA_P256, Kind, LAUNCH_CERT_MAX_BYTES, LAUNCH_KEY_MAX_BYTES,
    LIFETIME_SECRET_BYTES, LifetimeBody, LifetimeId, ModelEntry, Nonce, PROVIDER_ROUTING_DOMAIN,
    PayloadError, ProjectionBody, ProviderEntry, ProviderRoutingProjection, PublicationId,
    PublishBody, RANDOM_ID_BYTES, ROLE_CORE, ROLE_HELPER, Reason, ReceiptId, RecordBody,
    RecordHeader, Sender, SessionId, TextViolation, Tuple, next_expected_sequence,
    validate_incoming_sequence, validate_session,
};
pub use reassembly::{
    ChunkReassembler, FeedOutcome, MAX_ASSEMBLY_BYTES, MAX_CHUNKS_PER_ASSEMBLY,
    MAX_OPEN_ASSEMBLIES, REASSEMBLY_TTL_MS,
};
pub use refusal::{AgentRefusal, ContextReadCount};
pub use schema::{
    MAX_SCHEMA_ABSENCES, MAX_SCHEMA_ACTIVATION_POINT_BYTES, MAX_SCHEMA_ALLOWED,
    MAX_SCHEMA_CANONICAL_PREFIX_BYTES, MAX_SCHEMA_CONTEXT_REF_BYTES, MAX_SCHEMA_CONTEXT_REFS,
    MAX_SCHEMA_ENABLE_LIST, MAX_SCHEMA_ERROR_NAME_BYTES, MAX_SCHEMA_ID_LIST,
    MAX_SCHEMA_MESSAGE_BYTES, MAX_SCHEMA_MESSAGES, MAX_SCHEMA_MODEL_NAME_BYTES, MAX_SCHEMA_MODELS,
    MAX_SCHEMA_PROVIDER_ID_BYTES, MAX_SCHEMA_REASON_BYTES, MAX_SCHEMA_RECORD_BODY_BYTES,
    MAX_SCHEMA_RECORDS, MAX_SCHEMA_STABLE_ID_BYTES, MAX_SCHEMA_SUMMARY_BYTES,
    MAX_SCHEMA_TEXT_BYTES, MAX_SCHEMA_TIMEOUT_MS, MAX_SCHEMA_TOOL_ARGUMENTS_BYTES,
    MAX_SCHEMA_TOOL_CALLS, MAX_SCHEMA_TOOL_NAME_BYTES, MAX_SCHEMA_TOOLS, validate_ai_params,
    validate_ai_result,
};
pub use scope::{
    ConsentGrant, ConsentLedger, Scope, ScopeSet, all_known_methods, authorize_method,
    required_scope_for_method, validate_method_name,
};
pub use wire::{
    CHUNK_CEILING, MAX_ID_BYTES, MAX_JSON_DEPTH, SUPPORTED_WIRE_VERSIONS, WIRE_VERSION,
    negotiate_wire_version, validate_chunk, validate_request_envelope, validate_response_envelope,
    validate_wire_version,
};
