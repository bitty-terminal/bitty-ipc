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
//! bitty-ipc-auth, bitty-ipc-devtools, bitty-ipc-mcp
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
pub mod reassembly;
pub mod refusal;
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
pub use reassembly::{
    ChunkReassembler, FeedOutcome, MAX_ASSEMBLY_BYTES, MAX_CHUNKS_PER_ASSEMBLY,
    MAX_OPEN_ASSEMBLIES, REASSEMBLY_TTL_MS,
};
pub use refusal::{AgentRefusal, ContextReadCount};
pub use scope::{
    ConsentGrant, ConsentLedger, Scope, ScopeSet, all_known_methods, authorize_method,
    required_scope_for_method, validate_method_name,
};
pub use wire::{
    CHUNK_CEILING, MAX_ID_BYTES, MAX_JSON_DEPTH, SUPPORTED_WIRE_VERSIONS, WIRE_VERSION,
    negotiate_wire_version, validate_chunk, validate_request_envelope, validate_response_envelope,
    validate_wire_version,
};
