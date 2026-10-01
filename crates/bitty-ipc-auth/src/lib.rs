//! `bitty-ipc-auth`: Platform authentication for Bitty IPC.

#![forbid(unsafe_code)]

pub mod auth;
pub mod peer;

pub use auth::*;
pub use peer::*;
