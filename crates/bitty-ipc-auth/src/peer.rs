#[cfg(unix)]
use crate::auth::PeerCredentials;
#[cfg(unix)]
use crate::auth::{VerifiedPeer, verify_peer_for_connection};
use bitty_ipc_api::error::IpcError;

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamIdentity {
    pub device: u64,
    pub inode: u64,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn stream_identity(
    stream: &std::os::unix::net::UnixStream,
) -> Result<StreamIdentity, IpcError> {
    let stat = rustix::fs::fstat(stream).map_err(|err| IpcError::Unavailable {
        reason: format!("accepted-stream identity query failed: {err}"),
    })?;
    Ok(StreamIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    })
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
pub fn stream_identity(
    stream: &std::os::unix::net::UnixStream,
) -> Result<StreamIdentity, IpcError> {
    let stat = nix::sys::stat::fstat(stream).map_err(|err| IpcError::Unavailable {
        reason: format!("accepted-stream identity query failed: {err}"),
    })?;
    Ok(StreamIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    })
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    )),
))]
pub fn stream_identity(
    _stream: &std::os::unix::net::UnixStream,
) -> Result<StreamIdentity, IpcError> {
    Err(IpcError::Unavailable {
        reason: "accepted-stream identity is unsupported on this Unix platform".into(),
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_credentials(stream: &std::os::unix::net::UnixStream) -> Result<PeerCredentials, IpcError> {
    let credentials =
        rustix::net::sockopt::socket_peercred(stream).map_err(|err| IpcError::Unavailable {
            reason: format!("accepted-stream peer credential query failed: {err}"),
        })?;
    Ok(PeerCredentials::from_platform(
        credentials.uid.as_raw(),
        credentials.gid.as_raw(),
        credentials.pid.as_raw_pid(),
    ))
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
fn peer_credentials(stream: &std::os::unix::net::UnixStream) -> Result<PeerCredentials, IpcError> {
    let (uid, gid) = nix::unistd::getpeereid(stream).map_err(|err| IpcError::Unavailable {
        reason: format!("accepted-stream peer credential query failed: {err}"),
    })?;
    Ok(PeerCredentials::from_platform(
        uid.as_raw(),
        gid.as_raw(),
        0,
    ))
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    )),
))]
fn peer_credentials(_stream: &std::os::unix::net::UnixStream) -> Result<PeerCredentials, IpcError> {
    Err(IpcError::Unavailable {
        reason: "accepted-stream peer credentials are unsupported on this Unix platform".into(),
    })
}

#[must_use]
pub const fn accepted_stream_peer_attestation_available() -> bool {
    cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))
}

pub fn current_unix_uid() -> Result<u32, IpcError> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        Ok(rustix::process::getuid().as_raw())
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    {
        Ok(nix::unistd::getuid().as_raw())
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    )))]
    {
        Err(IpcError::Unavailable {
            reason: "current Unix uid is unavailable on this platform".into(),
        })
    }
}

#[cfg(unix)]
pub fn verify_unix_stream(
    stream: &std::os::unix::net::UnixStream,
    expected_uid: u32,
) -> Result<VerifiedPeer, IpcError> {
    verify_peer_for_connection(peer_credentials(stream)?, expected_uid)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{current_unix_uid, verify_unix_stream};
    use bitty_ipc_api::error::IpcError;
    use std::os::unix::net::UnixStream;

    #[test]
    fn linux_real_stream_credentials_are_checked() {
        let (_client, server) = UnixStream::pair().unwrap();
        let uid = current_unix_uid().unwrap();
        let peer = verify_unix_stream(&server, uid).unwrap();
        assert_eq!(peer.peer_uid(), uid);
    }

    #[test]
    fn linux_real_stream_uid_mismatch_is_rejected() {
        let (_client, server) = UnixStream::pair().unwrap();
        let uid = current_unix_uid().unwrap();
        let other_uid = if uid == u32::MAX { uid - 1 } else { uid + 1 };
        assert!(matches!(
            verify_unix_stream(&server, other_uid),
            Err(IpcError::Unauthenticated { .. })
        ));
    }
}

#[cfg(all(
    test,
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ),
))]
mod bsd_tests {
    use super::{current_unix_uid, verify_unix_stream};
    use bitty_ipc_api::error::IpcError;
    use std::os::unix::net::UnixStream;

    #[test]
    fn bsd_real_stream_credentials_are_checked() {
        let (_client, server) = UnixStream::pair().unwrap();
        let uid = current_unix_uid().unwrap();
        assert_eq!(verify_unix_stream(&server, uid).unwrap().peer_uid(), uid);
        let other_uid = if uid == u32::MAX { uid - 1 } else { uid + 1 };
        assert!(matches!(
            verify_unix_stream(&server, other_uid),
            Err(IpcError::Unauthenticated { .. })
        ));
    }
}

#[cfg(all(
    test,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    )),
))]
mod unsupported_tests {
    use super::{accepted_stream_peer_attestation_available, current_unix_uid};

    #[test]
    fn unsupported_platform_fails_closed() {
        assert!(!accepted_stream_peer_attestation_available());
        assert!(current_unix_uid().is_err());
    }
}
