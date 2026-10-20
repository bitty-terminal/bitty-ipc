//! Safe Windows named-pipe listener, connection, and client surface.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::windows::io::AsRawHandle as _;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use windows_sys::Win32::Foundation::HANDLE;

use crate::ffi;

/// Maximum bytes in a Windows SID (`SECURITY_MAX_SID_SIZE`).
pub const MAX_SID_BYTES: usize = 68;

/// Maximum pipe-name length in UTF-16 code units (Windows namespace bound).
pub const MAX_PIPE_NAME_CHARS: usize = 256;

/// Accepted polling interval for a pending `ConnectNamedPipe`.
const ACCEPT_POLL: Duration = Duration::from_millis(20);

/// Windows security identifier copied out of a process token or ACL.
///
/// The bytes are the SID's binary representation; equality is exact SID
/// equality. The value is sanitized identity data (no handle or token), and
/// [`fmt::Debug`] deliberately does not print the SID.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sid {
    len: u8,
    bytes: [u8; MAX_SID_BYTES],
}

impl Sid {
    /// Build a SID from its binary representation.
    ///
    /// Returns `None` unless the value has the documented SID shape: revision
    /// 1, a subauthority count of 0..=15, and an exact `8 + 4 * count` length
    /// within [`MAX_SID_BYTES`]. This constructor is data-only; it grants no
    /// authority (peer markers are minted only by `bitty-ipc-auth`).
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if !(8..=MAX_SID_BYTES).contains(&bytes.len()) {
            return None;
        }
        if bytes[0] != 1 {
            return None;
        }
        let subauthorities = usize::from(bytes[1]);
        if subauthorities > 15 || 8 + subauthorities * 4 != bytes.len() {
            return None;
        }
        let mut owned = [0u8; MAX_SID_BYTES];
        owned[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            len: u8::try_from(bytes.len()).ok()?,
            bytes: owned,
        })
    }

    /// Binary SID bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// SID byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Whether this is the empty marker (never produced by the kernel).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Sid")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// Server-side listener for one instance pipe.
///
/// `bind` creates the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE` and
/// a protected current-user-only DACL, then attests the created endpoint.
/// `accept` waits in short slices so shutdown is observed, re-attests the
/// connected instance, creates the next instance, and returns the connection.
pub struct PipeListener {
    name: String,
    handle: Option<std::os::windows::io::OwnedHandle>,
    user_sid: Sid,
    max_instances: u32,
}

impl PipeListener {
    /// Create the first instance of `name` for the current user.
    ///
    /// `max_connections` bounds concurrently served connections; the listener
    /// keeps one extra instance for the pending accept.
    ///
    /// # Errors
    ///
    /// `AddrInUse` when another server already owns the name (including a
    /// foreign user's pipe), `PermissionDenied` when the created endpoint does
    /// not attest as current-user-only, and any other Win32 failure.
    pub fn bind(name: &str, max_connections: u32) -> io::Result<Self> {
        ffi::wide_name(name)?;
        let user_sid = ffi::current_user_sid()?;
        let max_instances = max_connections.saturating_add(1).clamp(2, 255);
        let handle = ffi::create_pipe(name, true, max_instances, user_sid)?;
        ffi::attest_current_user_only(handle.as_raw_handle(), user_sid)?;
        Ok(Self {
            name: name.to_string(),
            handle: Some(handle),
            user_sid,
            max_instances,
        })
    }

    /// Pipe path served.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Wait for the next client.
    ///
    /// Returns `Interrupted` when `shutdown` is set while waiting. Any other
    /// error leaves the listener without a pending instance; the caller should
    /// stop serving.
    ///
    /// # Errors
    ///
    /// Forwards Win32 connect/create failures, maps shutdown to `Interrupted`,
    /// and refuses an instance whose endpoint no longer attests.
    pub fn accept(&mut self, shutdown: &AtomicBool) -> io::Result<PipeConnection> {
        let handle = self.handle.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "pipe listener has no pending instance",
            )
        })?;
        ffi::accept_connection(handle.as_raw_handle(), shutdown, ACCEPT_POLL)?;
        ffi::attest_current_user_only(handle.as_raw_handle(), self.user_sid)?;
        let next = ffi::create_pipe(&self.name, false, self.max_instances, self.user_sid)?;
        ffi::attest_current_user_only(next.as_raw_handle(), self.user_sid)?;
        self.handle = Some(next);
        Ok(PipeConnection::new(handle))
    }
}

/// One duplex byte-mode pipe connection.
///
/// Cloning shares the underlying handle and the timeout state, which is what
/// the serving recheck needs (a retained handle for per-dispatch identity
/// checks). Reads and writes apply the configured timeout through overlapped
/// I/O; a timed-out operation is cancelled and drained before returning.
#[derive(Clone)]
pub struct PipeConnection {
    inner: Arc<Inner>,
}

struct Inner {
    handle: std::os::windows::io::OwnedHandle,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
}

impl fmt::Debug for PipeConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PipeConnection")
            .field("read_timeout", &self.read_timeout())
            .field("write_timeout", &self.write_timeout())
            .finish_non_exhaustive()
    }
}

impl PipeConnection {
    fn new(handle: std::os::windows::io::OwnedHandle) -> Self {
        Self {
            inner: Arc::new(Inner {
                handle,
                read_timeout: Mutex::new(None),
                write_timeout: Mutex::new(None),
            }),
        }
    }

    fn raw_handle(&self) -> HANDLE {
        self.inner.handle.as_raw_handle()
    }

    /// Client process id (server side).
    ///
    /// # Errors
    ///
    /// Fails closed when the handle is not a connected server-side pipe.
    pub fn peer_pid(&self) -> io::Result<u32> {
        ffi::client_process_id(self.raw_handle())
    }

    /// Client process token user SID (server side).
    ///
    /// # Errors
    ///
    /// Fails closed when the client process cannot be queried.
    pub fn peer_sid(&self) -> io::Result<Sid> {
        ffi::client_process_sid(self.raw_handle())
    }

    /// Server process token user SID (client side).
    ///
    /// # Errors
    ///
    /// Fails closed when the server process cannot be queried (including a
    /// remote pipe, which the server also refuses to create).
    pub fn server_sid(&self) -> io::Result<Sid> {
        ffi::server_process_sid(self.raw_handle())
    }

    /// Configure the read timeout (`None` = block indefinitely).
    pub fn set_read_timeout(&self, timeout: Option<Duration>) {
        *self
            .inner
            .read_timeout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = timeout;
    }

    /// Configure the write timeout (`None` = block indefinitely).
    pub fn set_write_timeout(&self, timeout: Option<Duration>) {
        *self
            .inner
            .write_timeout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = timeout;
    }

    /// Current read timeout.
    #[must_use]
    pub fn read_timeout(&self) -> Option<Duration> {
        *self
            .inner
            .read_timeout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Current write timeout.
    #[must_use]
    pub fn write_timeout(&self) -> Option<Duration> {
        *self
            .inner
            .write_timeout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Read for PipeConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        ffi::read(self.raw_handle(), buf, self.read_timeout())
    }
}

impl Write for PipeConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        ffi::write(self.raw_handle(), buf, self.write_timeout())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Current process token user SID.
///
/// # Errors
///
/// Fails closed when the process token cannot be queried.
pub fn current_user_sid() -> io::Result<Sid> {
    ffi::current_user_sid()
}

/// Connect to `name`, waiting up to `wait` for a free instance.
///
/// After connecting, the server process token SID is compared with the current
/// user's; a pipe served by any other principal is refused before this
/// function returns.
///
/// # Errors
///
/// `NotFound` when no pipe exists, `TimedOut` when every instance stays busy
/// for `wait`, `PermissionDenied` when the server principal differs (or cannot
/// be established), and any other Win32 failure.
pub fn connect(name: &str, wait: Duration) -> io::Result<PipeConnection> {
    ffi::wide_name(name)?;
    let handle = ffi::connect_client(name, wait)?;
    let connection = PipeConnection::new(handle);
    let expected = ffi::current_user_sid()?;
    let actual = ffi::server_process_sid(connection.raw_handle())?;
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pipe server principal is not the current user",
        ));
    }
    Ok(connection)
}
