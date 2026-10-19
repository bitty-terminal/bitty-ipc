//! Fixed-size identifiers and digests for the control contract.

use std::fmt;

use super::sha256::sha256;

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_hex(out: &mut String, bytes: &[u8]) {
    out.reserve(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    push_hex(&mut out, bytes);
    out
}

macro_rules! fixed_bytes {
    ($name:ident, $len:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Fixed byte length.
            pub const LEN: usize = $len;

            /// All-zero value.
            pub const ZERO: Self = Self([0; $len]);

            /// Wrap exactly `LEN` bytes.
            #[must_use]
            pub const fn new(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Borrow the raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Lowercase hexadecimal rendering.
            #[must_use]
            pub fn to_hex(&self) -> String {
                to_hex(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }
    };
}

fixed_bytes!(
    Nonce,
    32,
    "A 32-byte public nonce (Core instance, control channel, or data channel)."
);
fixed_bytes!(
    SessionId,
    32,
    "A 32-byte launch nonce used as the control header session identifier."
);
fixed_bytes!(
    LifetimeId,
    32,
    "A fresh 32-byte public helper lifetime identifier."
);
fixed_bytes!(AckId, 32, "A fresh 32-byte acknowledgement identifier.");
fixed_bytes!(ReceiptId, 32, "A fresh 32-byte helper proof receipt.");
fixed_bytes!(
    Digest,
    32,
    "A 32-byte SHA-256 digest over exact bytes (never authentication by itself)."
);

impl Digest {
    /// Hash `bytes` with SHA-256.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(sha256(bytes))
    }
}

/// Opaque 40-byte publication identity: launch nonce followed by version.
///
/// The identity is 80 lowercase hexadecimal characters when mapped to the
/// bounded string vocabulary. It never repeats within a Core run.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicationId([u8; 40]);

impl PublicationId {
    /// Fixed byte length.
    pub const LEN: usize = 40;

    /// Wrap exactly 40 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 40]) -> Self {
        Self(bytes)
    }

    /// Build the identity from the launch nonce and publication version.
    #[must_use]
    pub fn from_parts(launch_nonce: SessionId, version: u64) -> Self {
        let mut bytes = [0u8; 40];
        bytes[..32].copy_from_slice(launch_nonce.as_bytes());
        bytes[32..].copy_from_slice(&version.to_be_bytes());
        Self(bytes)
    }

    /// Borrow the raw 40 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 40] {
        &self.0
    }

    /// The 32-byte launch nonce prefix.
    #[must_use]
    pub fn launch_nonce(&self) -> SessionId {
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&self.0[..32]);
        SessionId::new(nonce)
    }

    /// The big-endian publication version suffix.
    #[must_use]
    pub fn version(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.0[32..]);
        u64::from_be_bytes(bytes)
    }

    /// Lowercase hexadecimal rendering (80 characters).
    #[must_use]
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

impl fmt::Debug for PublicationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicationId({})", self.to_hex())
    }
}

impl fmt::Display for PublicationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}
