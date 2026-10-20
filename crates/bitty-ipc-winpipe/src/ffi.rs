//! Every `unsafe` block of `bitty-ipc-winpipe`: the raw Win32 calls behind the
//! safe named-pipe adapter (CTX-0016).
//!
//! # Boundary rules
//!
//! - Inputs are pipe names this crate's safe layer validated (non-empty,
//!   bounded, NUL-free), SIDs copied out of kernel-owned token/security
//!   buffers, owned handles, and caller buffers whose length is passed exactly.
//! - Every out-parameter is a `#[repr(C)]` `windows-sys` struct living on this
//!   module's stack, passed with its exact `size_of` length, so the kernel
//!   never writes past it.
//! - A raw `HANDLE` leaves this module only as an [`OwnedHandle`] after its
//!   documented failure sentinel is checked; `SECURITY_DESCRIPTOR` allocations
//!   are freed exactly once in `Drop`.
//! - Overlapped I/O uses one `OVERLAPPED` per call, waits with
//!   `GetOverlappedResultEx`, and on timeout cancels and drains the operation
//!   before the caller's buffer may go out of scope.
//! - Every failure is `io::Error::last_os_error()` read immediately after the
//!   failing call, before any other system call can overwrite it.

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::ptr;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_PENDING,
    ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, ERROR_SUCCESS,
    FALSE, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree, TRUE,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetExplicitEntriesFromAclW, GetSecurityInfo,
    NO_MULTIPLE_TRUSTEE, SDDL_REVISION_1, SE_FILE_OBJECT, TRUSTEE_IS_SID,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetLengthSid, GetTokenInformation, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::IO::{
    CancelIoEx, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT, SetNamedPipeHandleState, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::pipe::Sid;

/// `GetOverlappedResultEx` infinite wait.
const INFINITE_MS: u32 = u32::MAX;

/// Kernel-side pipe buffer per direction (bounds a peer that writes before the
/// server reads; the frame bound remains `bitty-ipc`'s `MAX_FRAME_BYTES`).
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;

/// Wraps a handle returned by a call whose failure sentinel is NULL.
fn owned_or_null(raw: HANDLE) -> io::Result<OwnedHandle> {
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is non-NULL, so the call that produced it succeeded and
    // returned a fresh handle this process owns and nothing else references;
    // `OwnedHandle` takes sole ownership and closes it exactly once.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

/// Creates a manual-reset, initially non-signaled, unnamed event.
///
/// Each overlapped operation uses its own event: signaling completion through
/// the pipe handle is ambiguous when a duplex connection has concurrent reads
/// and writes on shared clone handles.
fn operation_event() -> io::Result<OwnedHandle> {
    // SAFETY: default security attributes, manual-reset, initially
    // non-signaled, unnamed event; the handle is checked for NULL.
    owned_or_null(unsafe { CreateEventW(ptr::null(), TRUE, FALSE, ptr::null()) })
}

/// Maps a Win32 `BOOL` result onto `io::Result`.
fn check(ok: windows_sys::core::BOOL) -> io::Result<()> {
    if ok == FALSE {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Last-error kind for a Win32 status code.
fn os_error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

/// UTF-16, NUL-terminated pipe name.
pub(crate) fn wide_name(name: &str) -> io::Result<Vec<u16>> {
    if name.is_empty() || name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pipe name must be non-empty and NUL-free",
        ));
    }
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    if wide.len() >= crate::pipe::MAX_PIPE_NAME_CHARS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pipe name exceeds the Windows namespace bound",
        ));
    }
    wide.push(0);
    Ok(wide)
}

/// Owns a `SECURITY_DESCRIPTOR` allocated by
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
pub(crate) struct SecurityDescriptor {
    raw: PSECURITY_DESCRIPTOR,
}

impl SecurityDescriptor {
    /// Raw descriptor for `SECURITY_ATTRIBUTES`.
    pub(crate) fn raw(&self) -> PSECURITY_DESCRIPTOR {
        self.raw
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: `raw` was produced by a documented `LocalAlloc`-based API
        // (ConvertStringSecurityDescriptorToSecurityDescriptorW) and is not
        // freed anywhere else; `LocalFree` releases it exactly once.
        unsafe {
            LocalFree(self.raw.cast::<c_void>() as HLOCAL);
        }
    }
}

/// Copies an aligned SID into a stack buffer whose pointer can be passed to
/// Win32.
fn sid_words(sid: Sid) -> [u64; 9] {
    let mut words = [0u64; 9];
    // SAFETY: the buffer is a live `[u64; 9]` (72 bytes) covering the maximum
    // 68-byte SID; `sid.len()` never exceeds that, so the copy stays in bounds.
    let bytes = unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), 9 * 8) };
    bytes[..sid.len()].copy_from_slice(sid.as_bytes());
    words
}

/// Reads a kernel-owned SID pointer into the owned [`Sid`] value.
pub(crate) fn sid_from_ptr(ptr: PSID) -> io::Result<Sid> {
    if ptr.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel returned a null SID",
        ));
    }
    // SAFETY: `ptr` points at a valid SID structure (token user or an ACE SID
    // inside a security descriptor the caller still owns). `GetLengthSid`
    // reports its documented length; the copy is bounded by that length and
    // never exceeds the fixed SID capacity.
    let len = unsafe { GetLengthSid(ptr) };
    let len = usize::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SID length does not fit usize"))?;
    if !(8..=crate::pipe::MAX_SID_BYTES).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel returned an invalid SID length",
        ));
    }
    // SAFETY: see above; `len` is the SID's own reported length.
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    Sid::from_bytes(bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "kernel returned an invalid SID"))
}

/// Process token user SID for `process`.
fn process_token_sid(process: HANDLE) -> io::Result<Sid> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: `process` is a live process handle with
    // PROCESS_QUERY_LIMITED_INFORMATION; `token` is a stack out-parameter and
    // the call writes exactly one handle on success.
    check(unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) })?;
    let token = owned_or_null(token)?;
    token_user_sid(token.as_raw_handle())
}

/// Token user SID for an open token handle.
fn token_user_sid(token: HANDLE) -> io::Result<Sid> {
    let mut len = 0u32;
    // SAFETY: querying the required buffer length with a null buffer is the
    // documented two-call pattern; the call writes only `len`.
    let ok = unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut len) };
    if ok != FALSE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "token user query unexpectedly succeeded with no buffer",
        ));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(error);
    }
    if len == 0 || len as usize > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "token user information exceeds the bounded size",
        ));
    }
    // `TOKEN_USER` contains pointers, so the buffer must be pointer-aligned;
    // a `Vec<usize>` provides that alignment.
    let words = (len as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0usize; words];
    // SAFETY: the buffer is live, pointer-aligned, and at least `len` bytes;
    // `len` is passed exactly and the kernel writes only that many bytes.
    check(unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            len,
            &mut len,
        )
    })?;
    // SAFETY: the call above succeeded, so the buffer holds a `TOKEN_USER`
    // whose `User.Sid` points inside this still-live allocation.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_from_ptr(user.User.Sid)
}

/// Current process token user SID.
pub(crate) fn current_user_sid() -> io::Result<Sid> {
    // SAFETY: `GetCurrentProcess` returns the process pseudo-handle, which is
    // valid for token queries and must not be closed.
    process_token_sid(unsafe { GetCurrentProcess() })
}

/// Builds a protected current-user-only security descriptor.
///
/// SDDL `O:<sid>D:P(A;;GA;;;<sid>)`: owner is the current user, the DACL is
/// protected (no inherited ACEs), and the only ACE grants that same SID
/// generic access.
pub(crate) fn security_descriptor(sid: Sid) -> io::Result<SecurityDescriptor> {
    let words = sid_words(sid);
    let mut sid_string: windows_sys::core::PWSTR = ptr::null_mut();
    // SAFETY: `words` holds a valid, aligned SID copied from a kernel SID;
    // `sid_string` is a stack out-parameter receiving one LocalAlloc string.
    check(unsafe {
        ConvertSidToStringSidW(words.as_ptr().cast_mut().cast::<c_void>(), &mut sid_string)
    })?;
    let sid_text = {
        // SAFETY: the call succeeded and returned a NUL-terminated UTF-16
        // string; the pointer is walked only until that terminator.
        let mut len = 0usize;
        unsafe {
            while *sid_string.add(len) != 0 {
                len = len.saturating_add(1);
                if len > 256 {
                    break;
                }
            }
        }
        let text = unsafe { std::slice::from_raw_parts(sid_string, len) };
        let text = String::from_utf16_lossy(text);
        // SAFETY: `sid_string` came from a LocalAlloc-based API and is not
        // used after this free.
        unsafe {
            LocalFree(sid_string.cast::<c_void>() as HLOCAL);
        }
        text
    };
    if sid_text.is_empty() || sid_text.len() > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "current-user SID text is empty or overlong",
        ));
    }
    let sddl = format!("O:{sid_text}D:P(A;;GA;;;{sid_text})");
    let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut raw: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated and live for the call; `raw` is a stack
    // out-parameter receiving one LocalAlloc descriptor owned by the returned
    // `SecurityDescriptor`.
    check(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut raw,
            ptr::null_mut(),
        )
    })?;
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(SecurityDescriptor { raw })
}

/// Creates one named-pipe instance.
pub(crate) fn create_pipe(
    name: &str,
    first_instance: bool,
    max_instances: u32,
    user_sid: Sid,
) -> io::Result<OwnedHandle> {
    let name = wide_name(name)?;
    let descriptor = security_descriptor(user_sid)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.raw(),
        bInheritHandle: FALSE,
    };
    let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first_instance {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    // SAFETY: the name is NUL-terminated and live; `attributes` is a fully
    // initialized SECURITY_ATTRIBUTES whose descriptor is live for the call;
    // the returned handle is checked for INVALID_HANDLE_VALUE before use.
    let raw = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            open_mode,
            pipe_mode,
            max_instances.max(1),
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            &attributes,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        // `FILE_FLAG_FIRST_PIPE_INSTANCE` reports an existing pipe (a live
        // Bitty instance or a foreign squatter) as ERROR_ACCESS_DENIED. Map
        // that collision to AddrInUse so the servo can report "already
        // served" instead of an authentication failure.
        if first_instance && error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "pipe name is already owned by another server",
            ));
        }
        return Err(error);
    }
    owned_or_null(raw)
}

/// Attests that `handle`'s owner and every DACL ACE are `expected`.
///
/// A missing DACL (NULL = allow all), a foreign owner, a deny/other ACE, or an
/// inherited ACE is refused. Runs on the server-created handle before the
/// endpoint serves.
pub(crate) fn attest_current_user_only(handle: HANDLE, expected: Sid) -> io::Result<()> {
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `handle` is a live pipe handle; all out-parameters are stack
    // locals and the status is checked before any of them is read.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(os_error(status));
    }
    let result = (|| {
        let actual_owner = sid_from_ptr(owner)?;
        if actual_owner != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pipe owner is not the current user",
            ));
        }
        if dacl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pipe has a null DACL (allow-all)",
            ));
        }
        // Enumerate the DACL through `GetExplicitEntriesFromAclW`, which
        // copies the ACEs into a typed, API-owned array. No raw ACE pointer
        // arithmetic is performed here; every entry is checked to be a plain
        // grant to the expected SID with no inheritance or second trustee.
        let mut count = 0u32;
        let mut entries: *mut EXPLICIT_ACCESS_W = ptr::null_mut();
        // SAFETY: `dacl` is the live ACL inside the security descriptor above;
        // `count` and `entries` are stack out-parameters. On success the API
        // allocates an array this function frees with LocalFree below.
        let status = unsafe { GetExplicitEntriesFromAclW(dacl, &mut count, &mut entries) };
        if status != ERROR_SUCCESS {
            return Err(os_error(status));
        }
        if entries.is_null() || count == 0 || count > 16 {
            // SAFETY: `entries` is either NULL (LocalFree is a no-op) or the
            // API allocation for `count` entries; it is freed exactly once.
            unsafe {
                LocalFree(entries.cast::<c_void>() as HLOCAL);
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pipe DACL has no bounded explicit entries",
            ));
        }
        let result = (|| {
            // SAFETY: the API returned `count` initialized entries in one
            // allocation (count was bounded above), and the allocation is
            // freed only after this slice is no longer used.
            let entries = unsafe { std::slice::from_raw_parts(entries, count as usize) };
            for entry in entries {
                if entry.grfAccessMode != GRANT_ACCESS
                    || entry.grfInheritance != 0
                    || entry.Trustee.TrusteeForm != TRUSTEE_IS_SID
                    || entry.Trustee.MultipleTrusteeOperation != NO_MULTIPLE_TRUSTEE
                    || !entry.Trustee.pMultipleTrustee.is_null()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "pipe DACL contains a deny, inherited, or non-SID entry",
                    ));
                }
                let ace_sid = sid_from_ptr(entry.Trustee.ptstrName.cast::<c_void>())?;
                if ace_sid != expected {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "pipe DACL grants a SID other than the current user",
                    ));
                }
            }
            Ok(())
        })();
        // SAFETY: `entries` is the allocation returned above (or NULL);
        // LocalFree releases it exactly once after the slice borrow ends.
        unsafe {
            LocalFree(entries.cast::<c_void>() as HLOCAL);
        }
        result
    })();
    // SAFETY: `descriptor` is the allocation produced by GetSecurityInfo (or
    // NULL on failure, where LocalFree(NULL) is a no-op).
    unsafe {
        LocalFree(descriptor.cast::<c_void>() as HLOCAL);
    }
    result
}

/// Waits for one client to connect to `handle`.
///
/// `shutdown` is checked every `poll` interval while the overlapped connect is
/// pending, so the accept thread can stop without waiting for a client. A
/// client that connects and closes before `ConnectNamedPipe` observes it
/// (`ERROR_NO_DATA`) recycles the same instance with `DisconnectNamedPipe`
/// instead of killing the listener.
pub(crate) fn accept_connection(
    handle: HANDLE,
    shutdown: &std::sync::atomic::AtomicBool,
    poll: Duration,
) -> io::Result<()> {
    use std::sync::atomic::Ordering;

    let poll_ms = poll.as_millis().clamp(1, u32::MAX as u128 - 1) as u32;
    'recycle: loop {
        let event = operation_event()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.as_raw_handle(),
            ..Default::default()
        };
        // SAFETY: `handle` is a live overlapped pipe instance; `overlapped`
        // and its event stay alive until the operation completes or is
        // cancelled below.
        let ok = unsafe { ConnectNamedPipe(handle, &mut overlapped) };
        if ok != FALSE {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(code) if code == ERROR_PIPE_CONNECTED as i32 => return Ok(()),
            Some(code) if code == ERROR_IO_PENDING as i32 => {}
            Some(code) if code == ERROR_NO_DATA as i32 => {
                // SAFETY: `handle` is a live server-side pipe instance that
                // has no connected client; disconnect recycles it.
                unsafe {
                    DisconnectNamedPipe(handle);
                }
                if shutdown.load(Ordering::SeqCst) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "pipe accept cancelled by shutdown",
                    ));
                }
                continue 'recycle;
            }
            _ => return Err(error),
        }
        loop {
            let mut transferred = 0u32;
            // SAFETY: `handle`, `overlapped`, and `event` identify the pending
            // connect above; `transferred` is a stack out-parameter.
            let done = unsafe {
                GetOverlappedResultEx(handle, &overlapped, &mut transferred, poll_ms, FALSE)
            };
            if done != FALSE {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(code) if code == WAIT_TIMEOUT as i32 => {
                    if shutdown.load(Ordering::SeqCst) {
                        let _ = cancel_and_drain(handle, &overlapped)?;
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "pipe accept cancelled by shutdown",
                        ));
                    }
                }
                Some(code) if code == ERROR_NO_DATA as i32 || code == ERROR_BROKEN_PIPE as i32 => {
                    // The pending connect completed with a peer that already
                    // closed. The operation is complete (no drain needed);
                    // recycle the instance and wait for the next client.
                    // SAFETY: `handle` is a live server-side pipe instance.
                    unsafe {
                        DisconnectNamedPipe(handle);
                    }
                    if shutdown.load(Ordering::SeqCst) {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "pipe accept cancelled by shutdown",
                        ));
                    }
                    continue 'recycle;
                }
                _ => {
                    let _ = cancel_and_drain(handle, &overlapped)?;
                    return Err(error);
                }
            }
        }
    }
}

/// Maps a timeout to milliseconds (`None` = infinite).
fn timeout_ms(timeout: Option<Duration>) -> u32 {
    match timeout {
        None => INFINITE_MS,
        Some(timeout) => timeout.as_millis().clamp(1, u128::from(u32::MAX - 1)) as u32,
    }
}

/// Cancels a timed-out overlapped operation and waits for its completion.
///
/// Returns `Some(n)` when the operation actually completed before the cancel
/// landed (`n` bytes transferred), so a caller can honor completed I/O instead
/// of discarding it as a timeout. Returns `None` when the operation was
/// canceled/failed; either way the caller's buffer is safe to release.
fn cancel_and_drain(handle: HANDLE, overlapped: &OVERLAPPED) -> io::Result<Option<u32>> {
    // SAFETY: `overlapped` identifies the pending operation on `handle`; after
    // CancelIoEx, GetOverlappedResult(TRUE) waits until the operation is
    // complete (success, error, or aborted), so the caller's buffer is safe to
    // release.
    unsafe {
        CancelIoEx(handle, overlapped);
        let mut transferred = 0u32;
        if GetOverlappedResult(handle, overlapped, &mut transferred, TRUE) != FALSE {
            return Ok(Some(transferred));
        }
    }
    Ok(None)
}

/// Reads up to `buf.len()` bytes with an optional timeout.
pub(crate) fn read(handle: HANDLE, buf: &mut [u8], timeout: Option<Duration>) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
    let event = operation_event()?;
    let mut overlapped = OVERLAPPED {
        hEvent: event.as_raw_handle(),
        ..Default::default()
    };
    let mut read = 0u32;
    // SAFETY: `handle` is a live overlapped pipe; `buf` is live for at least
    // `len` bytes; `overlapped` and its event stay alive until the operation
    // completes or is cancelled below.
    let ok = unsafe { ReadFile(handle, buf.as_mut_ptr(), len, &mut read, &mut overlapped) };
    if ok != FALSE {
        return Ok(read as usize);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(code) if code == ERROR_IO_PENDING as i32 => {}
        Some(code)
            if code == ERROR_BROKEN_PIPE as i32 || code == ERROR_PIPE_NOT_CONNECTED as i32 =>
        {
            return Ok(0);
        }
        _ => return Err(error),
    }
    let mut transferred = 0u32;
    // SAFETY: same pending operation and live buffer as above.
    let done = unsafe {
        GetOverlappedResultEx(
            handle,
            &overlapped,
            &mut transferred,
            timeout_ms(timeout),
            FALSE,
        )
    };
    if done != FALSE {
        return Ok(transferred as usize);
    }
    let error = io::Error::last_os_error();
    // Every pending failure drains the operation before `buf`/`overlapped`
    // leave scope, so the kernel can never write into a returned stack frame.
    if let Some(completed) = cancel_and_drain(handle, &overlapped)? {
        if completed > 0 {
            return Ok(completed as usize);
        }
    }
    if error.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "pipe read timed out",
        ));
    }
    if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32)
        || error.raw_os_error() == Some(ERROR_PIPE_NOT_CONNECTED as i32)
    {
        return Ok(0);
    }
    Err(error)
}

/// Writes up to `buf.len()` bytes with an optional timeout.
pub(crate) fn write(handle: HANDLE, buf: &[u8], timeout: Option<Duration>) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
    let event = operation_event()?;
    let mut overlapped = OVERLAPPED {
        hEvent: event.as_raw_handle(),
        ..Default::default()
    };
    let mut written = 0u32;
    // SAFETY: `handle` is a live overlapped pipe; `buf` is live for at least
    // `len` bytes; `overlapped` and its event stay alive until the operation
    // completes or is cancelled below.
    let ok = unsafe { WriteFile(handle, buf.as_ptr(), len, &mut written, &mut overlapped) };
    if ok != FALSE {
        return Ok(written as usize);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(code) if code == ERROR_IO_PENDING as i32 => {}
        Some(code)
            if code == ERROR_NO_DATA as i32
                || code == ERROR_BROKEN_PIPE as i32
                || code == ERROR_PIPE_NOT_CONNECTED as i32 =>
        {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "pipe peer closed",
            ));
        }
        _ => return Err(error),
    }
    let mut transferred = 0u32;
    // SAFETY: same pending operation and live buffer as above.
    let done = unsafe {
        GetOverlappedResultEx(
            handle,
            &overlapped,
            &mut transferred,
            timeout_ms(timeout),
            FALSE,
        )
    };
    if done != FALSE {
        return Ok(transferred as usize);
    }
    let error = io::Error::last_os_error();
    // Drain before the buffer leaves scope; see `read`.
    if let Some(completed) = cancel_and_drain(handle, &overlapped)? {
        if completed > 0 {
            return Ok(completed as usize);
        }
    }
    if error.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "pipe write timed out",
        ));
    }
    if error.raw_os_error() == Some(ERROR_NO_DATA as i32)
        || error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32)
        || error.raw_os_error() == Some(ERROR_PIPE_NOT_CONNECTED as i32)
    {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "pipe peer closed",
        ));
    }
    Err(error)
}

/// Opens one client connection, retrying `ERROR_PIPE_BUSY` within `wait`.
pub(crate) fn connect_client(name: &str, wait: Duration) -> io::Result<OwnedHandle> {
    let name_wide = wide_name(name)?;
    let deadline = std::time::Instant::now() + wait;
    loop {
        // SAFETY: `name_wide` is NUL-terminated and live; all other arguments
        // are documented valid constants/NULL; the handle is checked against
        // INVALID_HANDLE_VALUE before use.
        let raw = unsafe {
            CreateFileW(
                name_wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                // Identification-level impersonation: the server may query
                // this client's identity but cannot act as it. Without the
                // SQOS flags Windows defaults to SecurityImpersonation.
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if raw != INVALID_HANDLE_VALUE {
            let handle = owned_or_null(raw)?;
            let mode = PIPE_READMODE_BYTE;
            // SAFETY: `handle` is a live pipe handle; `mode` is a stack value
            // and the optional out-parameters are NULL.
            check(unsafe {
                SetNamedPipeHandleState(handle.as_raw_handle(), &mode, ptr::null(), ptr::null())
            })?;
            return Ok(handle);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) {
            return Err(error);
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "pipe stayed busy for the whole connect window",
            ));
        }
        let remaining = deadline.saturating_duration_since(now);
        let wait_ms = remaining.as_millis().clamp(1, u128::from(u32::MAX - 1)) as u32;
        // SAFETY: the name buffer is NUL-terminated and live; the call only
        // waits for a free instance.
        if unsafe { WaitNamedPipeW(name_wide.as_ptr(), wait_ms) } == FALSE {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "pipe connect timed out",
                ));
            }
            return Err(error);
        }
    }
}

/// Client process id of a connected server-side pipe.
pub(crate) fn client_process_id(handle: HANDLE) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: `handle` is a live server-side pipe handle; `pid` is a stack
    // out-parameter written only on success.
    check(unsafe { GetNamedPipeClientProcessId(handle, &mut pid) })?;
    Ok(pid)
}

/// Server process id of a connected client-side pipe.
pub(crate) fn server_process_id(handle: HANDLE) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: `handle` is a live client-side pipe handle; `pid` is a stack
    // out-parameter written only on success.
    check(unsafe { GetNamedPipeServerProcessId(handle, &mut pid) })?;
    Ok(pid)
}

/// User SID of the process owning a client connection.
pub(crate) fn client_process_sid(handle: HANDLE) -> io::Result<Sid> {
    let pid = client_process_id(handle)?;
    // SAFETY: plain value arguments; the result is checked for NULL.
    let process =
        owned_or_null(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) })?;
    process_token_sid(process.as_raw_handle())
}

/// User SID of the process serving a client connection.
pub(crate) fn server_process_sid(handle: HANDLE) -> io::Result<Sid> {
    let pid = server_process_id(handle)?;
    // SAFETY: plain value arguments; the result is checked for NULL.
    let process =
        owned_or_null(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) })?;
    process_token_sid(process.as_raw_handle())
}
