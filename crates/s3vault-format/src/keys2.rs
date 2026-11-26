//! Keys of object format v2: a master keyring with **deterministic** key derivation from one root, and a
//! tenant keyring with one random secret per tenant (review section 3.2).
//!
//! ```text
//! master keyring (owner hardware + offline escrow; the root never changes)
//!   KEK[n]  = HKDF(root, "s3vault/v2/kek" || n)     rotation = `active n+1`, no new secret, no new escrow
//!   K_name  = HKDF(root, "s3vault/v2/name")
//!   K_tbox  = HKDF(root, "s3vault/v2/tenant-box")   seals only the tenant id in each object
//!   K_tag   = HKDF(root, "s3vault/v2/tenant-tag")   the per-tenant store prefix
//!   K_sys   = HKDF(root, "s3vault/v2/system-db")    the proxy's small system database
//!   K_esc   = HKDF(root, "s3vault/v2/tenant-escrow") seals escrow copies of the tenant keyring
//! tenant keyring (key service; escrow copies kept at most R_tk days)
//!   tenant t: name, id_t (random 128 bit), K_t (random 256 bit), status pending | active | erased
//! derived per tenant (proxy RAM only)
//!   K_obj   = HKDF(ikm = KEK[kid] || K_t, salt = object salt, info = "s3vault/v2/object" || id_t)
//!   K_nm_t  = HKDF(ikm = K_name || K_t, info = "s3vault/v2/name" || id_t)
//!   K_idx_t = HKDF(ikm = K_t, info = "s3vault/v2/index" || id_t)
//!   K_stg_t = HKDF(ikm = K_t, info = "s3vault/v2/staging" || id_t)   multipart staging files
//!   tag_t   = base32(HMAC(K_tag, id_t))[..16]                         store names: <prefix><tag_t>/<name>
//! ```
//!
//! Destroying `K_t` (and its escrow copies) makes every object, index snapshot and staging file of the
//! tenant unreadable wherever a copy lives, without touching ciphertext.
//!
//! Master keyring text:
//!
//! ```text
//! s3vault-keyring v2
//! root <base64 32 bytes>
//! active <n>                               KEK generation for new objects (default 1)
//! escrow <digest> <unix> <place>           confirmed offline copies (the root must have one before use)
//! legacy-name <kid> / legacy-active <kid> / legacy-key <kid> <b64>   v1 keys, kept to migrate v1 objects
//! ```
//!
//! Tenant keyring text:
//!
//! ```text
//! s3vault-tenants v1
//! tenant <name> <id hex> <pending|active|erased> <created unix> <erased unix or -> <K_t base64 or ->
//! escrow <digest> <unix> <place>           a confirmed escrow copy (digest of the sealed copy file)
//! ```

use crate::keyring::{EscrowRecord, Key32, Keyring};
use crate::{FormatError, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::BASE64;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

const MASTER_V2: &str = "s3vault-keyring v2";
const TENANTS_V1: &str = "s3vault-tenants v1";

fn kerr(m: impl Into<String>) -> FormatError {
    FormatError::Keyring(m.into())
}

fn b64_key(s: &str, what: &str) -> Result<Key32> {
    let mut raw = BASE64
        .decode(s.as_bytes())
        .map_err(|_| kerr(format!("{what}: bad base64")))?;
    if raw.len() != 32 {
        raw.zeroize();
        return Err(kerr(format!("{what}: must be 32 bytes")));
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&raw);
    raw.zeroize();
    Ok(k)
}

fn random_key() -> Key32 {
    let mut k = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *k);
    k
}

fn hkdf(ikm: &[u8], salt: Option<&[u8]>, info: &[&[u8]]) -> Key32 {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand_multi_info(info, &mut *out).expect("hkdf length");
    out
}

fn sanitize_place(place: &str) -> Result<String> {
    let p: String = place
        .chars()
        .map(|c| if c.is_whitespace() { '_' } else { c })
        .collect();
    if p.is_empty() {
        return Err(kerr("escrow place must not be empty"));
    }
    Ok(p)
}

fn ct_eq(a: &str, b: &str) -> bool {
    bool::from(subtle::ConstantTimeEq::ct_eq(a.trim().as_bytes(), b.trim().as_bytes()))
}

// ------------------------------------------------------------------------------------------ master

pub struct MasterV2 {
    root: Key32,
    /// KEK generation for new objects.
    pub active: u32,
    /// Confirmed offline copies of the root (and the legacy keys).
    pub escrows: Vec<EscrowRecord>,
    /// The v1 keyring this one replaced (read-only: v1 objects are migrated with it).
    pub legacy: Option<Keyring>,
}

impl std::fmt::Debug for MasterV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterV2")
            .field("active", &self.active)
            .field("escrows", &self.escrows.len())
            .field("legacy", &self.legacy)
            .finish()
    }
}

impl MasterV2 {
    /// A fresh master keyring with a random root. With `legacy`, the v1 keys are carried along.
    pub fn generate(legacy: Option<Keyring>) -> Self {
        MasterV2 {
            root: random_key(),
            active: 1,
            escrows: Vec::new(),
            legacy,
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut lines = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'));
        if lines.next() != Some(MASTER_V2) {
            return Err(kerr("missing 's3vault-keyring v2' header"));
        }
        let mut root = None;
        let mut active = 1;
        let mut escrows = Vec::new();
        let mut legacy_lines = Vec::new();
        for line in lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            match parts.as_slice() {
                ["root", b64] => root = Some(b64_key(b64, "root")?),
                ["active", n] => {
                    active = n
                        .parse::<u32>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or_else(|| kerr("bad active"))?
                }
                ["escrow", digest, at, place] => escrows.push(EscrowRecord {
                    max_kid: 0,
                    digest: digest.to_string(),
                    at: at.parse().map_err(|_| kerr("bad escrow time"))?,
                    place: place.to_string(),
                }),
                ["legacy-name", kid] => legacy_lines.push(format!("name {kid}")),
                ["legacy-active", kid] => legacy_lines.push(format!("active {kid}")),
                ["legacy-key", kid, b64] => legacy_lines.push(format!("key {kid} {b64}")),
                _ => return Err(kerr("unrecognised line")),
            }
        }
        let legacy = if legacy_lines.is_empty() {
            None
        } else {
            let t = Zeroizing::new(format!("s3vault-keyring v1\n{}\n", legacy_lines.join("\n")));
            legacy_lines.iter_mut().for_each(|l| l.zeroize());
            Some(Keyring::parse(&t)?)
        };
        Ok(MasterV2 {
            root: root.ok_or_else(|| kerr("missing 'root'"))?,
            active,
            escrows,
            legacy,
        })
    }

    /// Serialise. Holds key material: keep it in the returned `Zeroizing`, never log it.
    pub fn to_text(&self) -> Zeroizing<String> {
        let mut s = String::new();
        s.push_str(MASTER_V2);
        s.push('\n');
        s.push_str(
            "# Master keyring (format v2). Losing every copy makes all data unrecoverable.\n",
        );
        s.push_str(&format!("root {}\nactive {}\n", BASE64.encode(&self.root[..]), self.active));
        for r in &self.escrows {
            s.push_str(&format!("escrow {} {} {}\n", r.digest, r.at, r.place));
        }
        if let Some(l) = &self.legacy {
            let lt = l.to_text();
            for line in lt.lines() {
                let p: Vec<&str> = line.split_whitespace().collect();
                match p.as_slice() {
                    ["name", k] => s.push_str(&format!("legacy-name {k}\n")),
                    ["active", k] => s.push_str(&format!("legacy-active {k}\n")),
                    ["key", k, b] => s.push_str(&format!("legacy-key {k} {b}\n")),
                    _ => {}
                }
            }
        }
        Zeroizing::new(s)
    }

    /// The v1 keyring text served to v1 clients (rollback to a v1 proxy binary), if legacy keys exist.
    pub fn legacy_text(&self) -> Option<Zeroizing<String>> {
        self.legacy.as_ref().map(|l| l.to_text())
    }

    fn sub(&self, label: &[u8]) -> Key32 {
        hkdf(&self.root[..], None, &[label])
    }

    /// Deterministic key-encryption key of generation `n`.
    pub fn kek(&self, n: u32) -> Key32 {
        hkdf(&self.root[..], None, &[b"s3vault/v2/kek", &n.to_be_bytes()])
    }

    pub fn tenant_box_key(&self) -> Key32 {
        self.sub(b"s3vault/v2/tenant-box")
    }

    pub fn system_db_key(&self) -> Key32 {
        self.sub(b"s3vault/v2/system-db")
    }

    pub fn escrow_key(&self) -> Key32 {
        self.sub(b"s3vault/v2/tenant-escrow")
    }

    fn name_root(&self) -> Key32 {
        self.sub(b"s3vault/v2/name")
    }

    /// The store prefix of a tenant (non-secret to the store, opaque without the root).
    pub fn tenant_tag(&self, id: &[u8; 16]) -> String {
        let k = self.sub(b"s3vault/v2/tenant-tag");
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&k[..]).expect("hmac");
        m.update(id);
        let t = data_encoding::BASE32_NOPAD
            .encode(&m.finalize().into_bytes())
            .to_ascii_lowercase();
        t[..16].to_string()
    }

    /// Short non-secret fingerprint for status and logs.
    pub fn fingerprint(&self) -> String {
        hex::encode(&self.sub(b"s3vault/v2/fingerprint")[..8])
    }

    /// Non-secret digest of the root and legacy keys (what an escrow copy proves).
    pub fn escrow_digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"s3vault/escrow-digest/v2");
        h.update(&self.root[..]);
        if let Some(l) = &self.legacy {
            h.update(l.escrow_digest().as_bytes());
        }
        hex::encode(&h.finalize()[..16])
    }

    pub fn confirm_escrow(&mut self, digest: &str, place: &str, at: u64) -> Result<()> {
        let want = self.escrow_digest();
        if !ct_eq(&want, digest) {
            return Err(kerr(
                "escrow digest does not match this keyring (the copy is stale or different)",
            ));
        }
        self.escrows.push(EscrowRecord {
            max_kid: 0,
            digest: want,
            at,
            place: sanitize_place(place)?,
        });
        Ok(())
    }

    /// Whether a confirmed escrow copy holds this root (the proxy refuses to write before that).
    pub fn is_escrowed(&self) -> bool {
        let want = self.escrow_digest();
        self.escrows.iter().any(|r| r.digest == want)
    }

    pub fn escrow_places(&self) -> Vec<String> {
        let want = self.escrow_digest();
        let mut v: Vec<String> = self
            .escrows
            .iter()
            .filter(|r| r.digest == want)
            .map(|r| r.place.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// KEK rotation: the next generation becomes active. Deterministic, so the escrowed root covers it.
    pub fn rotate(&mut self) -> u32 {
        self.active += 1;
        self.active
    }

    /// Per-tenant keys for an active tenant.
    pub fn tenant_keys(self: &Arc<Self>, t: &TenantEntry) -> Result<TenantKeys> {
        let k_t = t
            .k_t
            .as_ref()
            .ok_or_else(|| kerr(format!("tenant {} has no key (erased)", t.name)))?;
        let id = t.id;
        let mut nm_ikm = Zeroizing::new([0u8; 64]);
        nm_ikm[..32].copy_from_slice(&self.name_root()[..]);
        nm_ikm[32..].copy_from_slice(&k_t[..]);
        Ok(TenantKeys {
            name: t.name.clone(),
            id,
            tag: self.tenant_tag(&id),
            name_key: hkdf(&nm_ikm[..], None, &[b"s3vault/v2/name", &id]),
            index_key: hkdf(&k_t[..], None, &[b"s3vault/v2/index", &id]),
            staging_key: hkdf(&k_t[..], None, &[b"s3vault/v2/staging", &id]),
            fingerprint: hex::encode(&hkdf(&k_t[..], None, &[b"s3vault/v2/tenant-fp", &id])[..8]),
            k_t: k_t.clone(),
            master: self.clone(),
        })
    }
}

/// The keys of one tenant, derived in the proxy's RAM. Dropping it zeroizes them.
pub struct TenantKeys {
    pub name: String,
    pub id: [u8; 16],
    /// Store prefix component (`<prefix><tag>/`).
    pub tag: String,
    pub name_key: Key32,
    /// SQLCipher key of the tenant's index partition.
    pub index_key: Key32,
    /// Key of the tenant's multipart staging files.
    pub staging_key: Key32,
    /// Non-secret fingerprint of `K_t` (erasure proofs).
    pub fingerprint: String,
    k_t: Key32,
    pub master: Arc<MasterV2>,
}

impl std::fmt::Debug for TenantKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TenantKeys({} {})", self.name, hex::encode(self.id))
    }
}

impl TenantKeys {
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }

    /// Per-object content key.
    pub fn object_key(&self, kid: u32, salt: &[u8; 32]) -> Key32 {
        let mut ikm = Zeroizing::new([0u8; 64]);
        ikm[..32].copy_from_slice(&self.master.kek(kid)[..]);
        ikm[32..].copy_from_slice(&self.k_t[..]);
        hkdf(&ikm[..], Some(salt), &[b"s3vault/v2/object", &self.id])
    }

    /// KEK generation for new objects.
    pub fn write_kid(&self) -> u32 {
        self.master.active
    }
}

// ------------------------------------------------------------------------------------------ tenants

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantStatus {
    /// Created, but no escrow copy holding it is confirmed yet: not served for writes.
    Pending,
    Active,
    /// `K_t` destroyed.
    Erased,
}

impl TenantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TenantStatus::Pending => "pending",
            TenantStatus::Active => "active",
            TenantStatus::Erased => "erased",
        }
    }
}

#[derive(Clone)]
pub struct TenantEntry {
    pub name: String,
    pub id: [u8; 16],
    pub status: TenantStatus,
    pub created: u64,
    pub erased_at: Option<u64>,
    pub k_t: Option<Key32>,
}

impl std::fmt::Debug for TenantEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Tenant({} {} {})",
            self.name,
            hex::encode(self.id),
            self.status.as_str()
        )
    }
}

impl TenantEntry {
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }
}

pub fn valid_tenant_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

#[derive(Debug, Clone, Default)]
pub struct TenantKeyring {
    pub tenants: BTreeMap<String, TenantEntry>,
    /// Confirmed escrow copies (digest of the sealed copy file).
    pub escrows: Vec<EscrowRecord>,
}

impl TenantKeyring {
    pub fn parse(text: &str) -> Result<Self> {
        let mut lines = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'));
        if lines.next() != Some(TENANTS_V1) {
            return Err(kerr("missing 's3vault-tenants v1' header"));
        }
        let mut out = TenantKeyring::default();
        for line in lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            match parts.as_slice() {
                ["tenant", name, id, status, created, erased, key] => {
                    if !valid_tenant_name(name) {
                        return Err(kerr("bad tenant name"));
                    }
                    let mut idb = [0u8; 16];
                    hex::decode_to_slice(id, &mut idb).map_err(|_| kerr("bad tenant id"))?;
                    let status = match *status {
                        "pending" => TenantStatus::Pending,
                        "active" => TenantStatus::Active,
                        "erased" => TenantStatus::Erased,
                        _ => return Err(kerr("bad tenant status")),
                    };
                    let k_t = match *key {
                        "-" => None,
                        k => Some(b64_key(k, "tenant key")?),
                    };
                    if (status == TenantStatus::Erased) != k_t.is_none() {
                        return Err(kerr(format!(
                            "tenant {name}: an erased tenant has no key, every other one has"
                        )));
                    }
                    let e = TenantEntry {
                        name: name.to_string(),
                        id: idb,
                        status,
                        created: created.parse().map_err(|_| kerr("bad created"))?,
                        erased_at: match *erased {
                            "-" => None,
                            t => Some(t.parse().map_err(|_| kerr("bad erased time"))?),
                        },
                        k_t,
                    };
                    if out.tenants.insert(name.to_string(), e).is_some() {
                        return Err(kerr(format!("tenant {name} defined twice")));
                    }
                }
                ["escrow", digest, at, place] => out.escrows.push(EscrowRecord {
                    max_kid: 0,
                    digest: digest.to_string(),
                    at: at.parse().map_err(|_| kerr("bad escrow time"))?,
                    place: place.to_string(),
                }),
                _ => return Err(kerr("unrecognised tenant line")),
            }
        }
        Ok(out)
    }

    pub fn to_text(&self) -> Zeroizing<String> {
        let mut s = String::new();
        s.push_str(TENANTS_V1);
        s.push('\n');
        s.push_str("# Tenant keyring. Erasing a tenant removes its key here and in every escrow copy.\n");
        for t in self.tenants.values() {
            s.push_str(&format!(
                "tenant {} {} {} {} {} {}\n",
                t.name,
                t.id_hex(),
                t.status.as_str(),
                t.created,
                t.erased_at.map(|e| e.to_string()).unwrap_or_else(|| "-".into()),
                t.k_t
                    .as_ref()
                    .map(|k| BASE64.encode(&k[..]))
                    .unwrap_or_else(|| "-".into())
            ));
        }
        for r in &self.escrows {
            s.push_str(&format!("escrow {} {} {}\n", r.digest, r.at, r.place));
        }
        Zeroizing::new(s)
    }

    /// A new tenant with a random id and key, **pending** until an escrow copy holding it is confirmed.
    pub fn create(&mut self, name: &str, now: u64) -> Result<&TenantEntry> {
        if !valid_tenant_name(name) {
            return Err(kerr("tenant names are 1-64 of [a-z0-9_-]"));
        }
        if self.tenants.contains_key(name) {
            return Err(kerr(format!("tenant {name} exists (names are never reused)")));
        }
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        self.tenants.insert(
            name.to_string(),
            TenantEntry {
                name: name.to_string(),
                id,
                status: TenantStatus::Pending,
                created: now,
                erased_at: None,
                k_t: Some(random_key()),
            },
        );
        Ok(&self.tenants[name])
    }

    /// Destroy a tenant's key. The entry stays (erased, no key) so the name and id are never reused.
    pub fn erase(&mut self, name: &str, now: u64) -> Result<&TenantEntry> {
        let t = self
            .tenants
            .get_mut(name)
            .ok_or_else(|| kerr(format!("no tenant {name}")))?;
        if t.status == TenantStatus::Erased {
            return Err(kerr(format!("tenant {name} is already erased")));
        }
        t.status = TenantStatus::Erased;
        t.erased_at = Some(now);
        t.k_t = None; // Zeroizing wipes the key
        Ok(t)
    }

    /// Record a confirmed escrow copy (`digest` of the sealed file, as computed where the copy is) and
    /// activate the pending tenants it holds.
    pub fn confirm_escrow(
        &mut self,
        copy: &TenantKeyring,
        digest: &str,
        place: &str,
        at: u64,
    ) -> Result<Vec<String>> {
        let mut activated = Vec::new();
        for (name, t) in self.tenants.iter_mut() {
            if t.status != TenantStatus::Pending {
                continue;
            }
            let held = copy.tenants.get(name).is_some_and(|c| {
                c.id == t.id
                    && match (&c.k_t, &t.k_t) {
                        (Some(a), Some(b)) => a[..] == b[..],
                        _ => false,
                    }
            });
            if held {
                t.status = TenantStatus::Active;
                activated.push(name.clone());
            }
        }
        self.escrows.push(EscrowRecord {
            max_kid: 0,
            digest: digest.trim().to_string(),
            at,
            place: sanitize_place(place)?,
        });
        Ok(activated)
    }
}

// ------------------------------------------------------------------------------------------ escrow copies

/// Sealed escrow copy of the tenant keyring:
/// `"S3VTESC1" || issued unix u64 BE || nonce[24] || XChaCha20-Poly1305(K_esc, AD = first 16 bytes, text)`.
/// File name `tenants-<issued>.sealed`. Its digest is the first 16 bytes of SHA-256(file), in hex.
pub const ESCROW_MAGIC: &[u8; 8] = b"S3VTESC1";

pub fn seal_tenant_escrow(master: &MasterV2, tk: &TenantKeyring, issued: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ESCROW_MAGIC);
    out.extend_from_slice(&issued.to_be_bytes());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let aead = XChaCha20Poly1305::new((&*master.escrow_key()).into());
    let text = tk.to_text();
    let ct = aead
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: text.as_bytes(),
                aad: &out[..16],
            },
        )
        .expect("encrypt");
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Open a sealed escrow copy with the master keyring. Returns (issued time, tenant keyring).
pub fn open_tenant_escrow(master: &MasterV2, bytes: &[u8]) -> Result<(u64, TenantKeyring)> {
    if bytes.len() < 16 + 24 + 16 || &bytes[..8] != ESCROW_MAGIC {
        return Err(FormatError::Malformed("not a tenant escrow copy"));
    }
    let issued = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    let aead = XChaCha20Poly1305::new((&*master.escrow_key()).into());
    let plain = Zeroizing::new(
        aead.decrypt(
            XNonce::from_slice(&bytes[16..40]),
            Payload {
                msg: &bytes[40..],
                aad: &bytes[..16],
            },
        )
        .map_err(|_| FormatError::Auth)?,
    );
    let text = std::str::from_utf8(&plain).map_err(|_| FormatError::Malformed("utf-8"))?;
    Ok((issued, TenantKeyring::parse(text)?))
}

pub fn escrow_file_digest(bytes: &[u8]) -> String {
    hex::encode(&Sha256::digest(bytes)[..16])
}

pub fn escrow_file_name(issued: u64) -> String {
    format!("tenants-{issued:010}.sealed")
}

/// Issue time from an escrow file name (`tenants-<unix>.sealed`).
pub fn escrow_file_time(name: &str) -> Option<u64> {
    name.strip_prefix("tenants-")?
        .strip_suffix(".sealed")?
        .parse()
        .ok()
}

/// Escrow retention (decision D3): of the copies in a directory, delete every copy issued more than
/// `max_age_secs` ago **except the newest** (which never holds an erased tenant's key: every erasure
/// issues a new copy). Returns the deleted file names. Used on the key host and on the owner's device.
pub fn prune_escrow_dir(dir: &std::path::Path, now: u64, max_age_secs: u64) -> std::io::Result<Vec<String>> {
    let mut copies: Vec<(u64, std::path::PathBuf, String)> = std::fs::read_dir(dir)?
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            escrow_file_time(&n).map(|t| (t, e.path(), n))
        })
        .collect();
    copies.sort();
    let newest = copies.last().map(|c| c.0);
    let mut deleted = Vec::new();
    for (t, p, n) in copies {
        if Some(t) != newest && now.saturating_sub(t) > max_age_secs {
            std::fs::remove_file(&p)?;
            deleted.push(n);
        }
    }
    Ok(deleted)
}

// ------------------------------------------------------------------------------------------ bundle

/// What the key service sends a v2 proxy: the master keyring, the tenant keyring and the erasure ledger.
///
/// ```text
/// %master
/// <master keyring text>
/// %tenants
/// <tenant keyring text>
/// %ledger
/// <ledger JSON lines>
/// ```
pub struct Bundle {
    pub master: MasterV2,
    pub tenants: TenantKeyring,
    pub ledger: crate::ledger::Ledger,
}

impl Bundle {
    pub fn to_text(&self) -> Zeroizing<String> {
        let mut s = String::from("%master\n");
        s.push_str(&self.master.to_text());
        s.push_str("%tenants\n");
        s.push_str(&self.tenants.to_text());
        s.push_str("%ledger\n");
        s.push_str(&self.ledger.to_text());
        Zeroizing::new(s)
    }

    pub fn parse(text: &str) -> Result<Bundle> {
        let mut sections: BTreeMap<&str, String> = BTreeMap::new();
        let mut cur: Option<&str> = None;
        for line in text.lines() {
            if let Some(name) = line.strip_prefix('%') {
                cur = Some(match name.trim() {
                    "master" => "master",
                    "tenants" => "tenants",
                    "ledger" => "ledger",
                    _ => return Err(kerr("unknown bundle section")),
                });
                sections.entry(cur.unwrap()).or_default();
                continue;
            }
            let c = cur.ok_or_else(|| kerr("bundle without a section header"))?;
            let e = sections.get_mut(c).unwrap();
            e.push_str(line);
            e.push('\n');
        }
        let master = MasterV2::parse(sections.get("master").ok_or_else(|| kerr("bundle without master"))?)?;
        let tenants = match sections.get("tenants") {
            Some(t) if !t.trim().is_empty() => TenantKeyring::parse(t)?,
            _ => TenantKeyring::default(),
        };
        let ledger = crate::ledger::Ledger::parse(sections.get("ledger").map(|s| s.as_str()).unwrap_or(""))?;
        for s in sections.values_mut() {
            s.zeroize();
        }
        Ok(Bundle {
            master,
            tenants,
            ledger,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_roundtrip_deterministic_rotation_and_escrow() {
        let legacy = Keyring::generate();
        let lfp = legacy.fingerprint();
        let mut m = MasterV2::generate(Some(legacy));
        let fp = m.fingerprint();
        let k1 = m.kek(1);
        assert!(!m.is_escrowed());
        assert!(m.confirm_escrow("00", "mac", 1).is_err());
        let copy = MasterV2::parse(&m.to_text()).unwrap();
        m.confirm_escrow(&copy.escrow_digest(), "owner mac", 2).unwrap();
        assert!(m.is_escrowed());
        // rotation adds no secret: the escrowed root still covers every generation
        assert_eq!(m.rotate(), 2);
        assert!(m.is_escrowed());
        let back = MasterV2::parse(&m.to_text()).unwrap();
        assert_eq!(back.fingerprint(), fp);
        assert_eq!(back.active, 2);
        assert_eq!(&back.kek(1)[..], &k1[..]);
        assert_eq!(&copy.kek(2)[..], &back.kek(2)[..], "the old copy derives the new KEK");
        assert!(back.is_escrowed());
        assert_eq!(back.legacy.as_ref().unwrap().fingerprint(), lfp);
        assert_eq!(
            Keyring::parse(&back.legacy_text().unwrap()).unwrap().fingerprint(),
            lfp
        );
        assert!(!format!("{back:?}").contains(&BASE64.encode(&back.root[..])));
    }

    #[test]
    fn tenants_create_escrow_erase() {
        let m = Arc::new(MasterV2::generate(None));
        let mut tk = TenantKeyring::default();
        let id = tk.create("ana", 10).unwrap().id;
        assert!(tk.create("ana", 11).is_err());
        assert!(tk.create("Bad Name", 11).is_err());
        assert_eq!(tk.tenants["ana"].status, TenantStatus::Pending);
        // escrow copy: sealed under the master, opened with it, activates the tenant
        let sealed = seal_tenant_escrow(&m, &tk, 100);
        let (issued, copy) = open_tenant_escrow(&m, &sealed).unwrap();
        assert_eq!(issued, 100);
        assert!(open_tenant_escrow(&MasterV2::generate(None), &sealed).is_err());
        let act = tk
            .confirm_escrow(&copy, &escrow_file_digest(&sealed), "mac", 101)
            .unwrap();
        assert_eq!(act, ["ana"]);
        let back = TenantKeyring::parse(&tk.to_text()).unwrap();
        assert_eq!(back.tenants["ana"].status, TenantStatus::Active);
        let keys = m.tenant_keys(&back.tenants["ana"]).unwrap();
        assert_eq!(keys.id, id);
        assert_eq!(keys.tag.len(), 16);
        // a different tenant secret gives different keys even with the same id
        let mut other = back.tenants["ana"].clone();
        other.k_t = Some(random_key());
        let k2 = m.tenant_keys(&other).unwrap();
        assert_ne!(&keys.name_key[..], &k2.name_key[..]);
        assert_ne!(&keys.object_key(1, &[0; 32])[..], &k2.object_key(1, &[0; 32])[..]);
        assert_eq!(keys.tag, k2.tag, "the tag depends on the id and root only");
        // erase: the key is gone from the keyring text
        let ktext = BASE64.encode(&back.tenants["ana"].k_t.as_ref().unwrap()[..]);
        tk.erase("ana", 200).unwrap();
        let text = tk.to_text();
        assert!(!text.contains(&ktext));
        let e = TenantKeyring::parse(&text).unwrap();
        assert_eq!(e.tenants["ana"].status, TenantStatus::Erased);
        assert!(m.tenant_keys(&e.tenants["ana"]).is_err());
        assert!(tk.create("ana", 300).is_err(), "names are never reused");
    }

    #[test]
    fn escrow_prune_keeps_newest_and_young() {
        let d = std::env::temp_dir().join(format!("s3v-esc-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&d).unwrap();
        let day = 86_400;
        let now = 100 * day;
        for t in [now - 60 * day, now - 31 * day, now - 29 * day, now - day] {
            std::fs::write(d.join(escrow_file_name(t)), b"x").unwrap();
        }
        std::fs::write(d.join("unrelated.txt"), b"x").unwrap();
        let del = prune_escrow_dir(&d, now, 30 * day).unwrap();
        assert_eq!(del.len(), 2);
        let mut left: Vec<String> = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        left.sort();
        assert_eq!(left.len(), 3);
        // only an old newest copy: it stays
        let d2 = d.join("solo");
        std::fs::create_dir_all(&d2).unwrap();
        std::fs::write(d2.join(escrow_file_name(now - 90 * day)), b"x").unwrap();
        assert!(prune_escrow_dir(&d2, now, 30 * day).unwrap().is_empty());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn bundle_roundtrip() {
        let m = MasterV2::generate(None);
        let fp = m.fingerprint();
        let mut t = TenantKeyring::default();
        t.create("x", 1).unwrap();
        let mut l = crate::ledger::Ledger::default();
        l.append(crate::ledger::TENANT_ERASED, "aa", "tt", serde_json::json!({}), 3);
        let b = Bundle { master: m, tenants: t, ledger: l };
        let back = Bundle::parse(&b.to_text()).unwrap();
        assert_eq!(back.master.fingerprint(), fp);
        assert_eq!(back.tenants.tenants.len(), 1);
        assert_eq!(back.ledger.entries.len(), 1);
        let empty = Bundle::parse(&format!("%master\n{}", MasterV2::generate(None).to_text().as_str())).unwrap();
        assert!(empty.tenants.tenants.is_empty() && empty.ledger.entries.is_empty());
    }
}
