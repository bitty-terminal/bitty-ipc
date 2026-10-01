//! `bitty-ipc-core`: Core IPC implementation (framing, wire, limits, transport).

#![forbid(unsafe_code)]

pub mod limits;
pub mod transport;

pub use limits::{
    RC9_BURST_LIMIT, RC9_INTERVAL_MS, RC9_MAX_CONNECTIONS, RC9_REPLENISH, RateLimiter,
};
pub use transport::{DEFAULT_TRANSPORT_CAPACITY, MAX_TRANSPORT_CAPACITY};
