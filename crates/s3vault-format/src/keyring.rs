//! The master keyring.
//!
//! Text format (one directive per line, `#` comments):
//!
//! ```text
//! s3vault-keyring v1
//! name 1
//! active 1
//! key 1 <base64 of 32 random bytes>
//! ```
//!
//! * `key <kid> <b64>`: a 256-bit key encryption key. Several may exist (rotation).
//! * `active <kid>`: the key used for new objects. Older keys stay readable.
//! * `name <kid>`: the key from which the object-name key, the index-database key and the staging key
//!   derive. Changing it means renaming every stored object, so it normally never changes.

use crate::{FormatError, Result};
use data_encoding::BASE64;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

pub type Key32 = Zeroizing<[u8; 32]>;

pub struct Keyring {
    pub name_kid: u32,
    pub active_kid: u32,
    keys: BTreeMap<u32, Key32>,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("name_kid", &self.name_kid)
            .field("active_kid", &self.active_kid)
            .field("kids", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

const HEADER_LINE: &str = "s3vault-keyring v1";

impl Keyring {
    /// A fresh keyring with one random key (kid 1), used for both names and new objects.
    pub fn generate() -> Self {
        let mut k = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *k);
        let mut keys = BTreeMap::new();
        keys.insert(1, k);
        Keyring {
            name_kid: 1,
            active_kid: 1,
            keys,
        }
    }

    /// Add a new random key and make it active. Returns its kid.
    pub fn rotate(&mut self) -> u32 {
        let kid = self.keys.keys().max().copied().unwrap_or(0) + 1;
        let mut k = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *k);
        self.keys.insert(kid, k);
        self.active_kid = kid;
        kid
    }

    pub fn kids(&self) -> Vec<u32> {
        self.keys.keys().copied().collect()
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut lines = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'));
        if lines.next() != Some(HEADER_LINE) {
            return Err(FormatError::Keyring(
                "missing 's3vault-keyring v1' header".into(),
            ));
        }
        let mut name = None;
        let mut active = None;
        let mut keys = BTreeMap::new();
        for line in lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            match parts.as_slice() {
                ["name", kid] => name = Some(parse_kid(kid)?),
                ["active", kid] => active = Some(parse_kid(kid)?),
                ["key", kid, b64] => {
                    let kid = parse_kid(kid)?;
                    let mut raw = BASE64
                        .decode(b64.as_bytes())
                        .map_err(|_| FormatError::Keyring(format!("key {kid}: bad base64")))?;
                    if raw.len() != 32 {
                        raw.zeroize();
                        return Err(FormatError::Keyring(format!("key {kid}: must be 32 bytes")));
                    }
                    let mut k = Zeroizing::new([0u8; 32]);
                    k.copy_from_slice(&raw);
                    raw.zeroize();
                    if keys.insert(kid, k).is_some() {
                        return Err(FormatError::Keyring(format!("key {kid} defined twice")));
                    }
                }
                _ => return Err(FormatError::Keyring("unrecognised line".into())),
            }
        }
        let name_kid = name.ok_or_else(|| FormatError::Keyring("missing 'name'".into()))?;
        let active_kid = active.ok_or_else(|| FormatError::Keyring("missing 'active'".into()))?;
        for kid in [name_kid, active_kid] {
            if !keys.contains_key(&kid) {
                return Err(FormatError::Keyring(format!(
                    "kid {kid} referenced but not defined"
                )));
            }
        }
        Ok(Keyring {
            name_kid,
            active_kid,
            keys,
        })
    }

    /// Serialise. The result holds key material: keep it in a `Zeroizing` and never log it.
    pub fn to_text(&self) -> Zeroizing<String> {
        let mut s = String::new();
        s.push_str(HEADER_LINE);
        s.push('\n');
        s.push_str("# Master keyring. Losing it makes all data unrecoverable; leaking it exposes all data.\n");
        s.push_str(&format!(
            "name {}\nactive {}\n",
            self.name_kid, self.active_kid
        ));
        for (kid, k) in &self.keys {
            s.push_str(&format!("key {kid} {}\n", BASE64.encode(&k[..])));
        }
        Zeroizing::new(s)
    }

    pub fn kek(&self, kid: u32) -> Result<&[u8; 32]> {
        self.keys
            .get(&kid)
            .map(|k| &**k)
            .ok_or(FormatError::UnknownKid(kid))
    }

    fn derive(&self, kid: u32, salt: Option<&[u8]>, info: &[u8]) -> Result<Key32> {
        let hk = Hkdf::<Sha256>::new(salt, self.kek(kid)?);
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(info, &mut *out)
            .map_err(|_| FormatError::Malformed("hkdf"))?;
        Ok(out)
    }

    /// Key for the keyed-hash object names.
    pub fn name_key(&self) -> Key32 {
        self.derive(self.name_kid, None, b"s3vault/v1/name")
            .expect("name kid present")
    }

    /// Key for the local index database (SQLCipher raw key).
    pub fn index_db_key(&self) -> Key32 {
        self.derive(self.name_kid, None, b"s3vault/v1/index-db")
            .expect("name kid present")
    }

    /// Master key for local spool and multipart staging files (each file adds its own random salt).
    pub fn spool_key(&self) -> Key32 {
        self.derive(self.name_kid, None, b"s3vault/v1/spool")
            .expect("name kid present")
    }

    /// Per-object content key.
    pub fn object_key(&self, kid: u32, salt: &[u8; 32]) -> Result<Key32> {
        self.derive(kid, Some(salt), b"s3vault/v1/object")
    }

    /// A short, non-secret fingerprint (first 8 bytes of a hash of the name key) for logs and status.
    pub fn fingerprint(&self) -> String {
        let fk = self
            .derive(self.name_kid, None, b"s3vault/v1/fingerprint")
            .expect("name kid present");
        hex::encode(&fk[..8])
    }
}

fn parse_kid(s: &str) -> Result<u32> {
    s.parse::<u32>()
        .ok()
        .filter(|k| *k > 0)
        .ok_or_else(|| FormatError::Keyring("bad kid".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_rotate() {
        let mut kr = Keyring::generate();
        let fp = kr.fingerprint();
        let k2 = kr.rotate();
        assert_eq!(k2, 2);
        let text = kr.to_text();
        let back = Keyring::parse(&text).unwrap();
        assert_eq!(back.name_kid, 1);
        assert_eq!(back.active_kid, 2);
        assert_eq!(back.fingerprint(), fp, "rotation keeps the name key");
        assert_eq!(&*back.name_key(), &*kr.name_key());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Keyring::parse("nope").is_err());
        assert!(Keyring::parse("s3vault-keyring v1\nname 1\nactive 1\n").is_err());
        assert!(Keyring::parse("s3vault-keyring v1\nname 1\nactive 1\nkey 1 AAAA\n").is_err());
    }

    #[test]
    fn debug_does_not_leak() {
        let kr = Keyring::generate();
        let dbg = format!("{kr:?}");
        let text = kr.to_text();
        let b64 = text
            .lines()
            .find(|l| l.starts_with("key "))
            .unwrap()
            .split(' ')
            .nth(2)
            .unwrap();
        assert!(!dbg.contains(b64));
    }
}
