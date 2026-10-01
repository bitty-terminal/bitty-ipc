//! `bitty-ipc-core`: Core IPC implementation (framing, wire, limits, transport).

#![forbid(unsafe_code)]

pub mod limits;
pub mod transport;

pub use limits::RateLimiter;
pub use transport::{DEFAULT_TRANSPORT_CAPACITY, MAX_TRANSPORT_CAPACITY};
