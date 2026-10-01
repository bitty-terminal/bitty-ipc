//! `bitty-ipc-api`: Pure API types for Bitty IPC (zero dependencies).
//!
//! This crate contains only type definitions, constants, and traits for the
//! IPC boundary. It has **zero dependencies** and is the only crate that
//! cross-repo consumers (like `bitty-agent`, `bitty-ai`) depend on.
//!
//! # What this crate owns
//!
//! - Error types: `IpcError`, `ErrorClass`
//! - Scope types: `Scope`, `ScopeSet`, `ConsentGrant`, `ConsentLedger`
//! - Wire types: wire version, envelope validation bounds
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
pub mod error;
pub mod frame;
pub mod scope;
pub mod wire;

pub use channel::{
    BoundedChannel, DEFAULT_REQUEST_CAPACITY, DEFAULT_RESPONSE_CAPACITY, IpcEndpoint, IpcRequest,
    IpcResponse, MAX_CHANNEL_CAPACITY, MAX_METHOD_BYTES, MAX_PENDING_REQUESTS, RequestId,
};
pub use error::{ErrorClass, IpcError};
pub use frame::{Frame, Framer, MAX_BUFFERED_BYTES, MAX_FRAME_BYTES, decode_frame, encode_frame};
pub use scope::{
    ConsentGrant, ConsentLedger, Scope, ScopeSet, all_known_methods, authorize_method,
    required_scope_for_method, validate_method_name,
};
pub use wire::{
    CHUNK_CEILING, MAX_ID_BYTES, MAX_JSON_DEPTH, SUPPORTED_WIRE_VERSIONS, WIRE_VERSION,
    negotiate_wire_version, validate_chunk, validate_request_envelope, validate_response_envelope,
    validate_wire_version,
};
