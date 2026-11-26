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
//! * `pending <kid>`: a rotated key that is not used for writes yet. It becomes active only when an escrow
//!   copy holding it is confirmed (`escrow` below), so a key can never exist only on the key host.
//! * `escrow <max_kid> <digest> <unix time> <place>`: a confirmed offline copy of every key up to `max_kid`.
//!   `digest` is [`Keyring::escrow_digest_upto`] of those keys (non-secret), computed by the owner from the
//!   copy itself, so a record cannot be written without the copy existing.
//!
//! Escrow rule (review H2): new objects are sealed under [`Keyring::write_kid`], the highest key that is
//! either the first key (escrowed by the install procedure) or covered by an escrow record. An unescrowed
//! `active` key is never used for writes.

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
    /// A rotated key waiting for its escrow confirmation.
    pub pending_kid: Option<u32>,
    pub escrows: Vec<EscrowRecord>,
    keys: BTreeMap<u32, Key32>,
}

/// One confirmed offline copy of the keyring (keys `1..=max_kid`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowRecord {
    pub max_kid: u32,
    pub digest: String,
    pub at: u64,
    pub place: String,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("name_kid", &self.name_kid)
            .field("active_kid", &self.active_kid)
            .field("pending_kid", &self.pending_kid)
            .field("escrows", &self.escrows.len())
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
            pending_kid: None,
            escrows: Vec::new(),
            keys,
        }
    }

    /// Add a new random key as **pending**: it is not used for writes until [`Keyring::confirm_escrow`]
    /// records an offline copy that holds it. Returns its kid. A second rotation while one is pending
    /// is refused (confirm or discard the first).
    pub fn rotate(&mut self) -> Result<u32> {
        if let Some(p) = self.pending_kid {
            return Err(FormatError::Keyring(format!(
                "key {p} is still pending escrow confirmation"
            )));
        }
        let kid = self.keys.keys().max().copied().unwrap_or(0) + 1;
        let mut k = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *k);
        self.keys.insert(kid, k);
        self.pending_kid = Some(kid);
        Ok(kid)
    }

    /// Non-secret digest of keys `1..=max_kid` (hex, 32 chars). The owner computes it from the escrow copy
    /// (`s3vault-keyd escrow-digest --file COPY`); the key host compares it before recording the escrow.
    pub fn escrow_digest_upto(&self, max_kid: u32) -> String {
        let mut h = <Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut h, b"s3vault/escrow-digest/v1");
        for (kid, k) in self.keys.range(..=max_kid) {
            sha2::Digest::update(&mut h, kid.to_be_bytes());
            sha2::Digest::update(&mut h, &k[..]);
        }
        hex::encode(&sha2::Digest::finalize(h)[..16])
    }

    /// Digest of every key in this keyring (what an escrow copy of this file proves).
    pub fn escrow_digest(&self) -> String {
        self.escrow_digest_upto(self.max_kid())
    }

    pub fn max_kid(&self) -> u32 {
        self.keys.keys().max().copied().unwrap_or(0)
    }

    /// Record a confirmed escrow copy. `digest` must be the digest of **all** keys of this keyring (as
    /// computed from the copy). A pending key becomes active.
    pub fn confirm_escrow(&mut self, digest: &str, place: &str, at: u64) -> Result<()> {
        let want = self.escrow_digest();
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            want.as_bytes(),
            digest.trim().as_bytes(),
        )) {
            return Err(FormatError::Keyring(
                "escrow digest does not match this keyring (the copy is stale or different)".into(),
            ));
        }
        let place: String = place
            .chars()
            .map(|c| if c.is_whitespace() { '_' } else { c })
            .collect();
        if place.is_empty() {
            return Err(FormatError::Keyring("escrow place must not be empty".into()));
        }
        self.escrows.push(EscrowRecord {
            max_kid: self.max_kid(),
            digest: want,
            at,
            place,
        });
        if let Some(p) = self.pending_kid.take() {
            self.active_kid = p;
        }
        Ok(())
    }

    /// Whether `kid` is covered by an escrow record whose digest matches the keys it claims to cover, or
    /// is the first key (escrowed by the install procedure).
    pub fn is_escrowed(&self, kid: u32) -> bool {
        if Some(&kid) == self.keys.keys().next() {
            return true;
        }
        self.escrows
            .iter()
            .any(|r| r.max_kid >= kid && r.digest == self.escrow_digest_upto(r.max_kid))
    }

    /// The key for new objects: `active` if escrowed, else the highest escrowed key not above it.
    pub fn write_kid(&self) -> u32 {
        if self.is_escrowed(self.active_kid) {
            return self.active_kid;
        }
        self.keys
            .keys()
            .rev()
            .copied()
            .find(|k| *k < self.active_kid && self.is_escrowed(*k))
            .unwrap_or(self.active_kid)
    }

    /// Escrow places recorded for the keys in use (status output; no secrets).
    pub fn escrow_places(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .escrows
            .iter()
            .filter(|r| r.max_kid >= self.active_kid)
            .map(|r| r.place.clone())
            .collect();
        v.sort();
        v.dedup();
        v
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
        let mut pending = None;
        let mut escrows = Vec::new();
        let mut keys = BTreeMap::new();
        for line in lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            match parts.as_slice() {
                ["name", kid] => name = Some(parse_kid(kid)?),
                ["active", kid] => active = Some(parse_kid(kid)?),
                ["pending", kid] => pending = Some(parse_kid(kid)?),
                ["escrow", max_kid, digest, at, place] => escrows.push(EscrowRecord {
                    max_kid: parse_kid(max_kid)?,
                    digest: digest.to_string(),
                    at: at
                        .parse()
                        .map_err(|_| FormatError::Keyring("bad escrow time".into()))?,
                    place: place.to_string(),
                }),
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
        for kid in [name_kid, active_kid].into_iter().chain(pending) {
            if !keys.contains_key(&kid) {
                return Err(FormatError::Keyring(format!(
                    "kid {kid} referenced but not defined"
                )));
            }
        }
        Ok(Keyring {
            name_kid,
            active_kid,
            pending_kid: pending,
            escrows,
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
        if let Some(p) = self.pending_kid {
            s.push_str(&format!("pending {p}\n"));
        }
        for r in &self.escrows {
            s.push_str(&format!(
                "escrow {} {} {} {}\n",
                r.max_kid, r.digest, r.at, r.place
            ));
        }
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
        let k2 = kr.rotate().unwrap();
        assert_eq!(k2, 2);
        kr.confirm_escrow(&kr.escrow_digest(), "owner-mac", 1).unwrap();
        let text = kr.to_text();
        let back = Keyring::parse(&text).unwrap();
        assert_eq!(back.name_kid, 1);
        assert_eq!(back.active_kid, 2);
        assert_eq!(back.write_kid(), 2);
        assert_eq!(back.fingerprint(), fp, "rotation keeps the name key");
        assert_eq!(&*back.name_key(), &*kr.name_key());
    }

    /// H2: a rotated key is never used for writes before an escrow copy holding it is confirmed.
    #[test]
    fn rotation_needs_escrow() {
        let mut kr = Keyring::generate();
        let k2 = kr.rotate().unwrap();
        assert_eq!(kr.active_kid, 1, "rotation leaves the key pending");
        assert_eq!(kr.pending_kid, Some(2));
        assert!(kr.rotate().is_err(), "one pending key at a time");
        // A copy taken before the rotation does not cover the new key.
        let mut old = Keyring::parse(&kr.to_text()).unwrap();
        old.keys.remove(&k2);
        old.pending_kid = None;
        assert!(kr.confirm_escrow(&old.escrow_digest(), "mac", 5).is_err());
        assert_eq!(kr.active_kid, 1);
        // The right copy promotes it.
        let copy = Keyring::parse(&kr.to_text()).unwrap();
        kr.confirm_escrow(&copy.escrow_digest(), "usb in the safe", 6)
            .unwrap();
        assert_eq!(kr.active_kid, 2);
        assert_eq!(kr.write_kid(), 2);
        assert_eq!(kr.escrows[0].place, "usb_in_the_safe");
        let back = Keyring::parse(&kr.to_text()).unwrap();
        assert_eq!(back.escrows, kr.escrows);
        assert!(back.is_escrowed(2));
        // A hand-edited keyring that activates an unescrowed key: the proxy keeps writing under the last
        // escrowed one.
        let mut hand = Keyring::parse(&kr.to_text()).unwrap();
        hand.escrows.clear();
        hand.active_kid = 2;
        assert_eq!(hand.write_kid(), 1);
        // A forged escrow record (digest not matching the keys) does not count.
        let mut forged = Keyring::parse(&kr.to_text()).unwrap();
        forged.escrows = vec![EscrowRecord {
            max_kid: 2,
            digest: "00".repeat(16),
            at: 1,
            place: "x".into(),
        }];
        assert_eq!(forged.write_kid(), 1);
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
