//! Local spool files (upload bodies above the memory limit, multipart parts).
//!
//! ```text
//! file = salt [32] || sealed chunk 0 || sealed chunk 1 || ... || sealed final chunk
//! ```
//!
//! Every chunk but the last carries exactly 64 KiB of plaintext; the final chunk carries less (possibly 0)
//! and has the last flag set, so a reader knows the end from the file length and truncation is detected.
//! Key = HKDF(spool key, salt, "s3vault/v1/spool-file"), AD = salt. The salt is random per file.

use crate::object::ChunkCipher;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 32;

pub fn cipher(spool_key: &[u8; 32], salt: &[u8; 32]) -> ChunkCipher {
    let hk = Hkdf::<Sha256>::new(Some(salt), spool_key);
    let mut k = Zeroizing::new([0u8; 32]);
    hk.expand(b"s3vault/v1/spool-file", &mut *k).expect("hkdf");
    ChunkCipher::new(&k, *salt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::CHUNK;

    #[test]
    fn spool_chunks_roundtrip() {
        let c = cipher(&[7u8; 32], &[9u8; 32]);
        let a = c.seal(0, false, &vec![1u8; CHUNK]);
        let b = c.seal(1, true, b"tail");
        assert_eq!(c.open(0, false, &a).unwrap(), vec![1u8; CHUNK]);
        assert_eq!(c.open(1, true, &b).unwrap(), b"tail");
        assert!(c.open(1, false, &b).is_err());
        assert!(cipher(&[7u8; 32], &[8u8; 32]).open(0, false, &a).is_err());
    }
}
