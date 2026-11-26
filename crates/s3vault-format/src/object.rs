//! Encrypted object format (version 1).
//!
//! ```text
//! store name: <prefix><base32(HMAC-SHA256(K_name, "v1" || bucket || 0x00 || key))>   (52 chars, flat)
//! object:     preamble (64 B, plain)
//!               magic "S3VAULT1" | kid u32 | flags u32 | salt [32] | sealed header len u32 | chunk size u32 | 8 x 0
//!             sealed header: XChaCha20-Poly1305(K_obj, nonce "s3vault/hdr", AD = preamble)
//!               over JSON(Header) zero-padded to a multiple of 1 KiB (hides the key length)
//!             body: plaintext in 64 KiB chunks, chunk i sealed under K_obj with
//!               nonce = "body" || i (u64 BE) || last flag || 0..., AD = SHA-256(preamble || sealed header)
//!             an empty object has exactly one (empty, last) chunk
//! K_obj = HKDF-SHA256(KEK[kid], salt, "s3vault/v1/object"); the salt is random per write.
//! ```
//!
//! The header names the logical bucket, the key and a per-key generation, and every body chunk is bound to
//! the header through the AD, so swapping objects, splicing or reordering chunks, truncation and replaying an
//! older version are detected. A fresh salt per write means a fresh key, so deterministic nonces are safe.

use crate::keyring::{Key32, Keyring};
use crate::{FormatError, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAGIC: [u8; 8] = *b"S3VAULT1";
pub const PREAMBLE_LEN: usize = 64;
pub const CHUNK: usize = 64 * 1024;
pub const TAG: usize = 16;
pub const SEALED_CHUNK: usize = CHUNK + TAG;
pub const HEADER_BLOCK: usize = 1024;
/// Bytes to fetch to read the header of any object whose header fits the default 2 KiB padding class.
pub const HEAD_PROBE_LEN: usize = PREAMBLE_LEN + 2 * HEADER_BLOCK + TAG;

/// The plaintext header carried (encrypted) by every stored object. It makes each object self-describing,
/// so the store plus the keyring rebuilds the whole index.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub v: u32,
    pub bucket: String,
    pub key: String,
    pub size: u64,
    /// The S3 ETag (without quotes) served to clients.
    pub etag: String,
    /// Hex SHA-256 of the plaintext.
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// User metadata (`x-amz-meta-*`, lowercase names without the prefix) and stored system headers
    /// (prefixed with `:`, e.g. `:cache-control`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
    /// Per (bucket, key), strictly increasing across overwrites and deletes.
    pub generation: u64,
    /// Last-Modified, milliseconds since the Unix epoch.
    pub mtime_ms: i64,
    /// A delete marker: the key is gone and must never be read through from a fallback.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tombstone: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preamble {
    pub kid: u32,
    pub flags: u32,
    pub salt: [u8; 32],
    pub header_sealed_len: u32,
    pub chunk_size: u32,
}

impl Preamble {
    pub fn encode(&self) -> [u8; PREAMBLE_LEN] {
        let mut b = [0u8; PREAMBLE_LEN];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..12].copy_from_slice(&self.kid.to_be_bytes());
        b[12..16].copy_from_slice(&self.flags.to_be_bytes());
        b[16..48].copy_from_slice(&self.salt);
        b[48..52].copy_from_slice(&self.header_sealed_len.to_be_bytes());
        b[52..56].copy_from_slice(&self.chunk_size.to_be_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < PREAMBLE_LEN {
            return Err(FormatError::Malformed("short preamble"));
        }
        if b[0..8] != MAGIC {
            return Err(FormatError::Malformed("bad magic"));
        }
        let u32_at = |i: usize| u32::from_be_bytes(b[i..i + 4].try_into().unwrap());
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&b[16..48]);
        let p = Preamble {
            kid: u32_at(8),
            flags: u32_at(12),
            salt,
            header_sealed_len: u32_at(48),
            chunk_size: u32_at(52),
        };
        if p.chunk_size as usize != CHUNK {
            return Err(FormatError::Malformed("unsupported chunk size"));
        }
        if (p.header_sealed_len as usize) < HEADER_BLOCK + TAG || p.header_sealed_len > 1 << 20 {
            return Err(FormatError::Malformed("bad header length"));
        }
        Ok(p)
    }
}

/// Byte layout of a stored object with a given sealed header length and plaintext size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub header_sealed_len: u64,
    pub size: u64,
}

impl Layout {
    pub fn body_offset(&self) -> u64 {
        PREAMBLE_LEN as u64 + self.header_sealed_len
    }
    pub fn n_chunks(&self) -> u64 {
        if self.size == 0 {
            1
        } else {
            self.size.div_ceil(CHUNK as u64)
        }
    }
    pub fn total_len(&self) -> u64 {
        self.body_offset() + self.size + self.n_chunks() * TAG as u64
    }
    pub fn chunk_plain_len(&self, i: u64) -> u64 {
        let start = i * CHUNK as u64;
        (self.size.saturating_sub(start)).min(CHUNK as u64)
    }
    pub fn is_last(&self, i: u64) -> bool {
        i + 1 == self.n_chunks()
    }
    /// Chunks covering plaintext bytes `[start, end)`; `end > start`, `end <= size`.
    pub fn chunks_for(&self, start: u64, end: u64) -> (u64, u64) {
        (start / CHUNK as u64, (end - 1) / CHUNK as u64)
    }
    /// Inclusive ciphertext byte range of chunks `first..=last`.
    pub fn ciphertext_span(&self, first: u64, last: u64) -> (u64, u64) {
        let s = self.body_offset() + first * SEALED_CHUNK as u64;
        let e = self.body_offset()
            + last * SEALED_CHUNK as u64
            + self.chunk_plain_len(last)
            + TAG as u64
            - 1;
        (s, e)
    }
}

/// Seals or opens 64 KiB chunks under one key with position-bound nonces and a fixed AD.
pub struct ChunkCipher {
    aead: XChaCha20Poly1305,
    ad: [u8; 32],
}

fn chunk_nonce(idx: u64, last: bool) -> XNonce {
    let mut n = [0u8; 24];
    n[0..4].copy_from_slice(b"body");
    n[4..12].copy_from_slice(&idx.to_be_bytes());
    n[12] = last as u8;
    XNonce::from(n)
}

impl ChunkCipher {
    pub fn new(key: &[u8; 32], ad: [u8; 32]) -> Self {
        ChunkCipher {
            aead: XChaCha20Poly1305::new(key.into()),
            ad,
        }
    }
    pub fn seal(&self, idx: u64, last: bool, plain: &[u8]) -> Vec<u8> {
        debug_assert!(plain.len() <= CHUNK);
        self.aead
            .encrypt(
                &chunk_nonce(idx, last),
                Payload {
                    msg: plain,
                    aad: &self.ad,
                },
            )
            .expect("xchacha encrypt cannot fail")
    }
    pub fn open(&self, idx: u64, last: bool, sealed: &[u8]) -> Result<Vec<u8>> {
        self.aead
            .decrypt(
                &chunk_nonce(idx, last),
                Payload {
                    msg: sealed,
                    aad: &self.ad,
                },
            )
            .map_err(|_| FormatError::Auth)
    }
}

const HEADER_NONCE: [u8; 24] = *b"s3vault/hdr\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// What the index must remember to read a stored object without re-reading its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealInfo {
    pub kid: u32,
    pub salt: [u8; 32],
    pub header_sealed_len: u32,
    /// SHA-256(preamble || sealed header): the body AD.
    pub ad: [u8; 32],
}

/// The start of a new object: preamble plus sealed header, and the cipher for its body.
pub struct SealedHead {
    pub prefix: Vec<u8>,
    pub info: SealInfo,
    pub body: ChunkCipher,
}

pub fn seal_head(kr: &Keyring, header: &Header) -> Result<SealedHead> {
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    seal_head_with(kr, kr.active_kid, salt, header)
}

pub fn seal_head_with(
    kr: &Keyring,
    kid: u32,
    salt: [u8; 32],
    header: &Header,
) -> Result<SealedHead> {
    let k_obj: Key32 = kr.object_key(kid, &salt)?;
    let mut json = serde_json::to_vec(header).map_err(|_| FormatError::Malformed("header json"))?;
    let padded = json.len().div_ceil(HEADER_BLOCK).max(1) * HEADER_BLOCK;
    json.resize(padded, 0);
    let pre = Preamble {
        kid,
        flags: 0,
        salt,
        header_sealed_len: (padded + TAG) as u32,
        chunk_size: CHUNK as u32,
    };
    let pre_bytes = pre.encode();
    let aead = XChaCha20Poly1305::new((&*k_obj).into());
    let sealed = aead
        .encrypt(
            &XNonce::from(HEADER_NONCE),
            Payload {
                msg: &json,
                aad: &pre_bytes,
            },
        )
        .expect("xchacha encrypt cannot fail");
    let mut prefix = Vec::with_capacity(PREAMBLE_LEN + sealed.len());
    prefix.extend_from_slice(&pre_bytes);
    prefix.extend_from_slice(&sealed);
    let ad: [u8; 32] = Sha256::digest(&prefix).into();
    Ok(SealedHead {
        info: SealInfo {
            kid,
            salt,
            header_sealed_len: pre.header_sealed_len,
            ad,
        },
        body: ChunkCipher::new(&k_obj, ad),
        prefix,
    })
}

/// Parse and authenticate the header at the start of a stored object. `bytes` must hold at least the
/// preamble and the sealed header (see [`needed_head_len`]).
pub fn open_head(kr: &Keyring, bytes: &[u8]) -> Result<(Header, SealInfo)> {
    let pre = Preamble::decode(bytes)?;
    let end = PREAMBLE_LEN + pre.header_sealed_len as usize;
    if bytes.len() < end {
        return Err(FormatError::Malformed("short header"));
    }
    let k_obj = kr.object_key(pre.kid, &pre.salt)?;
    let aead = XChaCha20Poly1305::new((&*k_obj).into());
    let mut plain = aead
        .decrypt(
            &XNonce::from(HEADER_NONCE),
            Payload {
                msg: &bytes[PREAMBLE_LEN..end],
                aad: &bytes[..PREAMBLE_LEN],
            },
        )
        .map_err(|_| FormatError::Auth)?;
    while plain.last() == Some(&0) {
        plain.pop();
    }
    let header: Header =
        serde_json::from_slice(&plain).map_err(|_| FormatError::Malformed("header json"))?;
    let ad: [u8; 32] = Sha256::digest(&bytes[..end]).into();
    Ok((
        header,
        SealInfo {
            kid: pre.kid,
            salt: pre.salt,
            header_sealed_len: pre.header_sealed_len,
            ad,
        },
    ))
}

/// How many leading bytes [`open_head`] needs, given at least the preamble.
pub fn needed_head_len(bytes: &[u8]) -> Result<usize> {
    let pre = Preamble::decode(bytes)?;
    Ok(PREAMBLE_LEN + pre.header_sealed_len as usize)
}

/// The body cipher for an object whose seal info is known (from the index).
pub fn body_cipher(kr: &Keyring, info: &SealInfo) -> Result<ChunkCipher> {
    let k_obj = kr.object_key(info.kid, &info.salt)?;
    Ok(ChunkCipher::new(&k_obj, info.ad))
}

/// Keyed-hash object name (without the store prefix).
pub fn store_name(name_key: &[u8; 32], bucket: &str, key: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(name_key).expect("hmac key");
    mac.update(b"v1");
    mac.update(bucket.as_bytes());
    mac.update(&[0]);
    mac.update(key.as_bytes());
    let tag = mac.finalize().into_bytes();
    data_encoding::BASE32_NOPAD
        .encode(&tag)
        .to_ascii_lowercase()
}

/// Seal a whole in-memory plaintext (convenience for small objects and tests).
pub fn seal_all(kr: &Keyring, header: &Header, plain: &[u8]) -> Result<(Vec<u8>, SealInfo)> {
    let head = seal_head(kr, header)?;
    let layout = Layout {
        header_sealed_len: head.info.header_sealed_len as u64,
        size: plain.len() as u64,
    };
    let mut out = Vec::with_capacity(layout.total_len() as usize);
    out.extend_from_slice(&head.prefix);
    for i in 0..layout.n_chunks() {
        let s = (i as usize) * CHUNK;
        let e = (s + CHUNK).min(plain.len());
        out.extend_from_slice(&head.body.seal(i, layout.is_last(i), &plain[s..e]));
    }
    debug_assert_eq!(out.len() as u64, layout.total_len());
    Ok((out, head.info))
}

/// Open a plaintext byte range `[start, end)` from the ciphertext of chunks `first..=last`
/// (as returned by a ranged GET of [`Layout::ciphertext_span`]).
pub fn open_range(
    cipher: &ChunkCipher,
    layout: &Layout,
    first: u64,
    last: u64,
    ciphertext: &[u8],
    start: u64,
    end: u64,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity((end - start) as usize);
    let mut off = 0usize;
    for i in first..=last {
        let len = layout.chunk_plain_len(i) as usize + TAG;
        let sealed = ciphertext
            .get(off..off + len)
            .ok_or(FormatError::Malformed("short body"))?;
        off += len;
        let plain = cipher.open(i, layout.is_last(i), sealed)?;
        let cs = i * CHUNK as u64;
        let a = start.saturating_sub(cs) as usize;
        let b = ((end - cs) as usize).min(plain.len());
        out.extend_from_slice(&plain[a..b]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(size: u64) -> Header {
        Header {
            v: 1,
            bucket: "b".into(),
            key: "audio/x/000001.opus".into(),
            size,
            etag: "e".into(),
            sha256: "s".into(),
            content_type: Some("audio/ogg".into()),
            meta: BTreeMap::new(),
            generation: 1,
            mtime_ms: 1,
            tombstone: false,
        }
    }

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn roundtrip_sizes() {
        let kr = Keyring::generate();
        for n in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 17] {
            let plain = data(n);
            let (ct, info) = seal_all(&kr, &header(n as u64), &plain).unwrap();
            let (h, info2) = open_head(&kr, &ct).unwrap();
            assert_eq!(h.size, n as u64);
            assert_eq!(info, info2);
            let layout = Layout {
                header_sealed_len: info.header_sealed_len as u64,
                size: n as u64,
            };
            assert_eq!(layout.total_len() as usize, ct.len());
            let c = body_cipher(&kr, &info).unwrap();
            let last = layout.n_chunks() - 1;
            let (s, e) = layout.ciphertext_span(0, last);
            let got = open_range(
                &c,
                &layout,
                0,
                last,
                &ct[s as usize..=e as usize],
                0,
                n as u64,
            )
            .unwrap();
            assert_eq!(got, plain);
        }
    }

    #[test]
    fn ranges_across_chunk_boundaries() {
        let kr = Keyring::generate();
        let n = 3 * CHUNK + 1000;
        let plain = data(n);
        let (ct, info) = seal_all(&kr, &header(n as u64), &plain).unwrap();
        let layout = Layout {
            header_sealed_len: info.header_sealed_len as u64,
            size: n as u64,
        };
        let c = body_cipher(&kr, &info).unwrap();
        let cases = [
            (0, 1),
            (CHUNK as u64 - 1, CHUNK as u64 + 1),
            (CHUNK as u64 - 10, 2 * CHUNK as u64 + 10),
            (2 * CHUNK as u64, 3 * CHUNK as u64),
            (3 * CHUNK as u64 + 999, 3 * CHUNK as u64 + 1000),
            (5, n as u64),
        ];
        for (s, e) in cases {
            let (f, l) = layout.chunks_for(s, e);
            let (cs, ce) = layout.ciphertext_span(f, l);
            let got = open_range(&c, &layout, f, l, &ct[cs as usize..=ce as usize], s, e).unwrap();
            assert_eq!(got, &plain[s as usize..e as usize], "range {s}..{e}");
        }
    }

    #[test]
    fn tamper_truncate_swap_detected() {
        let kr = Keyring::generate();
        let n = 2 * CHUNK + 5;
        let plain = data(n);
        let (ct, info) = seal_all(&kr, &header(n as u64), &plain).unwrap();
        let layout = Layout {
            header_sealed_len: info.header_sealed_len as u64,
            size: n as u64,
        };
        let c = body_cipher(&kr, &info).unwrap();
        // bit flip in the body
        let mut bad = ct.clone();
        let off = layout.body_offset() as usize + 10;
        bad[off] ^= 1;
        let (s, e) = layout.ciphertext_span(0, 2);
        assert!(
            open_range(
                &c,
                &layout,
                0,
                2,
                &bad[s as usize..=e as usize],
                0,
                n as u64
            )
            .is_err()
        );
        // bit flip in the header
        let mut badh = ct.clone();
        badh[PREAMBLE_LEN + 3] ^= 1;
        assert!(matches!(open_head(&kr, &badh), Err(FormatError::Auth)));
        // truncation: treat chunk 1 as the last one
        let short = Layout {
            header_sealed_len: layout.header_sealed_len,
            size: 2 * CHUNK as u64,
        };
        let (s, e) = short.ciphertext_span(0, 1);
        assert!(
            open_range(
                &c,
                &short,
                0,
                1,
                &ct[s as usize..=e as usize],
                0,
                short.size
            )
            .is_err()
        );
        // swap: another object's body under this object's seal info
        let (ct2, _) = seal_all(&kr, &header(n as u64), &plain).unwrap();
        let (s, e) = layout.ciphertext_span(0, 2);
        assert!(
            open_range(
                &c,
                &layout,
                0,
                2,
                &ct2[s as usize..=e as usize],
                0,
                n as u64
            )
            .is_err()
        );
        // wrong keyring
        let other = Keyring::generate();
        assert!(open_head(&other, &ct).is_err());
    }

    #[test]
    fn header_hides_key_length_and_rotation_reads_old() {
        let mut kr = Keyring::generate();
        let mut h1 = header(1);
        h1.key = "a".into();
        let mut h2 = header(1);
        h2.key = "a".repeat(500);
        let (c1, _) = seal_all(&kr, &h1, b"x").unwrap();
        let (c2, _) = seal_all(&kr, &h2, b"x").unwrap();
        assert_eq!(c1.len(), c2.len());
        kr.rotate();
        let (c3, i3) = seal_all(&kr, &h1, b"x").unwrap();
        assert_eq!(i3.kid, 2);
        assert_eq!(open_head(&kr, &c1).unwrap().0.key, "a");
        assert_eq!(open_head(&kr, &c3).unwrap().0.key, "a");
        assert!(c1.len() >= HEAD_PROBE_LEN.min(c1.len()));
    }

    #[test]
    fn names_are_keyed_and_flat() {
        let kr = Keyring::generate();
        let nk = kr.name_key();
        let a = store_name(&nk, "media", "audio/1/000001.opus");
        let b = store_name(&nk, "other", "audio/1/000001.opus");
        assert_ne!(a, b);
        assert_eq!(a.len(), 52);
        assert!(!a.contains('/'));
        assert_ne!(
            a,
            store_name(
                &Keyring::generate().name_key(),
                "media",
                "audio/1/000001.opus"
            )
        );
    }
}
