//! `bitty-ipc-core`: Core IPC implementation (framing, wire, limits, transport).

#![forbid(unsafe_code)]

pub mod limits;
pub mod transport;

pub use limits::*;
pub use transport::*;
