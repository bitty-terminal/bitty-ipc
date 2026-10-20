//! `bitty-ipc-winpipe`: the narrow, reviewed Windows named-pipe transport for
//! Bitty IPC (CTX-0016; consumer `bitty` CTX-1405, issues #2244/#2243).
//!
//! This crate is to the IPC transport what `bitty-winjob` is to owned process
//! trees: the one place Windows system calls are made, wrapped in a safe API.
//! Every `unsafe` block lives in the private [`ffi`] module, each with a
//! `SAFETY` rationale. The crate root denies `unsafe_code`; only that module is
//! allowed it.
//!
//! # Surface (Windows only)
//!
//! - [`PipeListener`]: binds `\\.\pipe\bitty-<instance>` with a protected
//!   current-user-only DACL, optionally attests the created endpoint, and
//!   accepts client connections without blocking shutdown forever.
//! - [`PipeConnection`]: a duplex byte-mode pipe with per-read/write timeout
//!   support (`Read`/`Write` plus explicit timeout setters), client-process
//!   identity queries ([`PipeConnection::peer_sid`],
//!   [`PipeConnection::peer_pid`]), and server identity checks
//!   ([`PipeConnection::server_sid`]).
//! - [`connect`]: opens an existing pipe, waits for a free instance within a
//!   bounded timeout, and refuses a server whose process token SID is not the
//!   current user's.
//! - [`current_user_sid`]: the process token user SID used for both sides of
//!   the comparison.
//!
//! On every other platform the crate compiles to an empty surface with no
//! dependencies.
//!
//! # Security posture
//!
//! - The pipe is created with a protected DACL (`D:P`) that grants only the
//!   current process token user SID; no inherited or foreign ACE is added. The
//!   created endpoint is re-read with `GetSecurityInfo` and attested before it
//!   serves (owner SID equality plus every ACE being an allow for that SID).
//! - The server reads the connecting client's process token user SID and the
//!   caller compares it with its own before any request byte is parsed. The
//!   comparison lives in `bitty-ipc-auth`; this crate returns only the
//!   sanitized [`Sid`] value.
//! - `PIPE_REJECT_REMOTE_CLIENTS` refuses remote pipe clients; there is no TCP
//!   or any other transport here.
//! - Every operation is bounded: frame bounds and rate/connection limits stay
//!   in `bitty-ipc-devtools`; this crate bounds pipe-name length, connect wait,
//!   and per-read/write waits.

#![deny(unsafe_code)]

#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi;

#[cfg(windows)]
mod pipe;

#[cfg(windows)]
pub use pipe::{MAX_PIPE_NAME_CHARS, PipeConnection, PipeListener, Sid, connect, current_user_sid};
