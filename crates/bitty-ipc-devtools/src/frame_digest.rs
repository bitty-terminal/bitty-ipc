//! `bitty.debug/frameHash` digest primitives (CTX-0244).
//!
//! The visual-test gates (CTX-0242 V1-V3) ask an **equality** question —
//! "does the frame the IPC path observed equal the frame the present path
//! produced?" — not a transport question. A collision-resistant digest over
//! canonical frame bytes answers equality in 32 bytes with zero
//! redaction-boundary movement (P0-AC-026 parity): digests are
//! uninvertible, carry no text, and cannot leak clipboard/env bytes.
//!
//! No raw pixel channel exists: pixel bytes never cross IPC under any grant
//! (that option stays deferred indefinitely; see the CTX-0244 design note).
//!
//! SHA-256 here is std-only on purpose: no `sha2`/`blake3` crate exists in
//! the workspace lockfile, and a 32-byte digest does not justify a new
//! dependency. The implementation is FIPS 180-4 SHA-256, pinned against the
//! NIST `"abc"` vector plus fixed canonical-frame vectors below so the
//! hash can never silently drift (any future layout change bumps
//! [`FRAME_DIGEST_ALGO`] `sha256-v1` to `v2` with dual-verify migration).

/// Digest algorithm label served on the wire (`frameHash.algo`).
pub const FRAME_DIGEST_ALGO: &str = "sha256-v1";

/// Maximum TTL for a [`crate::devtools::AutomationFamily::FrameDigest`]
/// bearer in ms (2 min, strictly below the 10 min automation cap).
/// Test sessions are minutes-long; the short cap bounds digest-oracle
/// exploitation windows and stale grants left by crashed harnesses.
pub const FRAME_DIGEST_TTL_MS: u64 = 120_000;

/// Sustained `frameHash` digests per second per bearer (5x tighter than the
/// 10 fps `captureFrame` ceiling: the digest answers equality, tests need
/// at most one per frame-step). Overruns yield `budget`/`RateLimited`.
pub const MAX_FRAME_DIGEST_PER_SEC: usize = 2;

/// Canonical header magic: `v1 || width_be32 || height_be32 || frameSeq_be64`
/// followed by the raw premultiplied RGBA bytes. Identical pixels with a
/// different header encoding MUST NOT verify.
const CANONICAL_MAGIC: &[u8; 4] = b"BFH1";

/// Canonical frame bytes shared by both sides of the equality proof: the
/// IPC handler hashes these, and the harness hashes its local
/// `headless_rgba` through this same helper. Length is
/// `20 + rgba.len()`; callers bound `rgba` before calling (the serving
/// layer reuses the present-path allocation caps).
#[must_use]
pub fn canonical_frame_bytes(
    width_px: u32,
    height_px: u32,
    frame_seq: u64,
    rgba: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + rgba.len());
    out.extend_from_slice(CANONICAL_MAGIC);
    out.extend_from_slice(&width_px.to_be_bytes());
    out.extend_from_slice(&height_px.to_be_bytes());
    out.extend_from_slice(&frame_seq.to_be_bytes());
    out.extend_from_slice(rgba);
    out
}

/// Round constants (first 32 bits of the fractional parts of the cube
/// roots of the first sixty-four primes).
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// One SHA-256 compression round over a 64-byte block.
fn compress_block(block: &[u8; 64], h: &mut [u32; 8]) {
    let mut w = [0u32; 64];
    for (i, chunk) in block.chunks_exact(4).enumerate().take(16) {
        w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
        (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// FIPS 180-4 SHA-256 over `data` (std-only; see module docs for why no
/// hash crate is used).
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    // Initial hash values (first 32 bits of the fractional parts of the
    // square roots of the first eight primes).
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    // Padded message: data || 0x80 || zero pad || 64-bit big-endian length,
    // processed in 64-byte blocks without retaining the full padding.
    let mut block = [0u8; 64];

    let mut chunks = data.chunks_exact(64);
    for chunk in &mut chunks {
        block.copy_from_slice(chunk);
        compress_block(&block, &mut h);
    }
    let rem = chunks.remainder();
    block.fill(0);
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] = 0x80;
    // Length field needs the final 8 bytes; if it does not fit, this block
    // is full (process it) and the length lands in a fresh block.
    if rem.len() + 1 > 56 {
        compress_block(&block, &mut h);
        block.fill(0);
    }
    block[56..64].copy_from_slice(&bit_len.to_be_bytes());
    compress_block(&block, &mut h);

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Lowercase hex of [`sha256`] (64 chars; safe to log — uninvertible).
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = sha256(data);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Convenience: hex digest of [`canonical_frame_bytes`] for one frame.
#[must_use]
pub fn frame_digest_hex(width_px: u32, height_px: u32, frame_seq: u64, rgba: &[u8]) -> String {
    sha256_hex(&canonical_frame_bytes(width_px, height_px, frame_seq, rgba))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_nist_vectors() {
        // FIPS 180-4 Appendix B vectors: the hash implementation can never
        // silently drift (a drift breaks every digest comparison loudly).
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // Multi-block input (112 bytes > one 64-byte block after padding).
        let long = vec![0x61u8; 1_000_000];
        assert_eq!(
            sha256_hex(&long),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn canonical_header_encoding_is_fixed() {
        // Byte-exact header contract: magic + width_be32 + height_be32 +
        // frameSeq_be64. A different encoding MUST NOT verify (no false
        // pass across `algo` versions).
        let bytes = canonical_frame_bytes(0x0102_0304, 0x0506_0708, 0x090a_0b0c_0d0e_0f10, &[]);
        assert_eq!(
            bytes,
            vec![
                0x42, 0x46, 0x48, 0x31, // "BFH1"
                0x01, 0x02, 0x03, 0x04, // width_be32
                0x05, 0x06, 0x07, 0x08, // height_be32
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // frameSeq_be64
            ]
        );
        // Fixed digest vector: any implementation change that alters one
        // hashed byte fails here (cross-checked against Python hashlib).
        assert_eq!(
            frame_digest_hex(2, 1, 7, &[1, 2, 3, 4, 5, 6, 7, 8]),
            "e7380e8d0953d0df1f937809825d8b99f93f8ee5d41cbe9d39ab2b6e8c530513"
        );
        assert_eq!(canonical_frame_bytes(2, 1, 7, &[1]).len(), 21);
    }

    #[test]
    fn digest_avalanches_on_single_bit_change() {
        let base = frame_digest_hex(64, 48, 3, &vec![0xabu8; 64 * 48 * 4]);
        // One flipped bit anywhere (header or pixel) changes the digest.
        let mut perturbed = vec![0xabu8; 64 * 48 * 4];
        perturbed[1234] ^= 0x01;
        assert_ne!(base, frame_digest_hex(64, 48, 3, &perturbed));
        assert_ne!(
            base,
            frame_digest_hex(64, 48, 4, &vec![0xabu8; 64 * 48 * 4])
        );
        assert_ne!(
            base,
            frame_digest_hex(65, 48, 3, &vec![0xabu8; 64 * 48 * 4])
        );
    }
}
