//! `bitty-ipc`: Full IPC implementation with BridgeClient.

#![forbid(unsafe_code)]

pub mod bridge;
pub mod execution;
pub mod execution_verbs;
pub mod host_bridge;
pub mod rich_fragment;

pub use bridge::*;
pub use execution::*;
pub use execution_verbs::*;
pub use host_bridge::*;
pub use rich_fragment::*;

// Re-export all public items from sub-crates
pub use bitty_ipc_api::*;
pub use bitty_ipc_auth::*;
pub use bitty_ipc_core::*;
pub use bitty_ipc_devtools::*;
pub use bitty_ipc_mcp::*;
