//! The keystore (key hierarchy, section 3.4): the data keys (master text, every tenant key `K_t`, the erasure
//! ledger) sealed under a random master unlock key (MUK) with per-tenant unlock keys (TUK), opened through
//! revocable HPKE slots. One file per epoch, written create-only under a lock.
//!
//! ```text
//! public part (plain, authenticated):
//!   "S3VKS001" | keystore id [16] | epoch u64 | issued unix u64 | previous epoch file SHA-256 [32] | nonce [24]
//!   u16 n_slots, per slot: slot id [8] | KEM u16 | target u8 (0 master, 1 tenant) | tenant ref [16]
//!                          | u16 len, HPKE enc | u16 len, HPKE ciphertext of the unlock key (MUK or TUK)
//!     HPKE info = "s3vault/keystore/v1/slot" | keystore id | epoch | slot id | target | tenant ref
//! tenant blocks: u16 n, per block: ref [16] | nonce [24] | u32 len, XChaCha20-Poly1305(TUK_t,
//!   AD = SHA-256("s3vault/keystore/v1/block" | public part) | ref) over: id_t [16] | write gen u32 | u16 n | K_t[0..n]
//! sealed part: u32 len, XChaCha20-Poly1305(MUK, nonce, AD = SHA-256("s3vault/keystore/v1/sealed" | everything
//!   before it)) over TLV sections (u8 tag, u32 len, bytes):
//!   1 master keyring text (verbatim)    2 tenant keyring text, each K_t replaced by "@<ref hex>"
//!   3 TUKs (ref [16] | TUK [32])*       4 ledger (JSON lines, verbatim)
//!   5 slot table (JSON, non-secret)     6 policy (TOML)       7 change log (JSON)
//! ```
//!
//! Every epoch re-wraps the unlock keys to every slot (the info string binds the epoch). The bundle that
//! s3vault-keyd serves is rebuilt with the same `to_text` code as from the plain files, so it is byte-identical
//! (KH1): `bundle_text()`.

use crate::hpke::{self, Kem, SlotSecret};
use crate::keyring::Key32;
use crate::keys2::{Bundle, MasterV2, TenantEntry, TenantKeyring, TenantStatus};
use crate::ledger::{self, Ledger};
use crate::slots::{PubTarget, SlotPub, slot_id};
use crate::{FormatError, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

pub const KS_MAGIC: &[u8; 8] = b"S3VKS001";
const HEADER_LEN: usize = 8 + 16 + 8 + 8 + 32 + 24;

fn kerr(m: impl Into<String>) -> FormatError {
    FormatError::Keyring(format!("keystore: {}", m.into()))
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// Hex SHA-256 of a keystore file: the digest recorded in `keys/places` and checked by every copy.
pub fn file_digest(bytes: &[u8]) -> String {
    hex::encode(sha256(bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Master,
    Tenant([u8; 16]),
}

impl Target {
    fn kind(&self) -> u8 {
        match self {
            Target::Master => 0,
            Target::Tenant(_) => 1,
        }
    }
    fn reference(&self) -> [u8; 16] {
        match self {
            Target::Master => [0; 16],
            Target::Tenant(r) => *r,
        }
    }
}

/// One slot (non-secret): kept in the sealed slot table; the public part carries only id, KEM, target, wraps.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlotEntry {
    pub id: String,
    pub kem: String,
    /// "master" or "tenant:<ref hex>"
    pub target: String,
    pub pk: String,
    pub kind: String,
    pub label: String,
    pub holder: String,
    pub backend: String,
    pub created: u64,
    pub created_by: String,
}

impl SlotEntry {
    fn target(&self) -> Result<Target> {
        if self.target == "master" {
            return Ok(Target::Master);
        }
        let h = self.target.strip_prefix("tenant:").ok_or_else(|| kerr("bad slot target"))?;
        let mut r = [0u8; 16];
        hex::decode_to_slice(h, &mut r).map_err(|_| kerr("bad slot target ref"))?;
        Ok(Target::Tenant(r))
    }
    fn kem(&self) -> Result<Kem> {
        Kem::from_name(&self.kem)
    }
    fn pk(&self) -> Result<Vec<u8>> {
        BASE64.decode(self.pk.as_bytes()).map_err(|_| kerr("bad slot pk"))
    }
    fn id_bytes(&self) -> Result<[u8; 8]> {
        let mut r = [0u8; 8];
        hex::decode_to_slice(&self.id, &mut r).map_err(|_| kerr("bad slot id"))?;
        Ok(r)
    }
    /// Short non-secret fingerprint of the public key (slot audits).
    pub fn pk_fingerprint(&self) -> String {
        hex::encode(&sha256(self.pk.as_bytes())[..8])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Change {
    pub epoch: u64,
    pub at: u64,
    pub op: String,
    pub detail: String,
}

/// `keys/policy.toml` (principle 7: retention and slot rules are config).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub retention_days: u64,
    pub activate_requires: Vec<String>,
    pub min_master_slots: usize,
    pub warn_after_days: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            retention_days: 30,
            activate_requires: vec!["b2-mirror".into(), "bitwarden".into()],
            min_master_slots: 3,
            warn_after_days: 25,
        }
    }
}

impl Policy {
    pub fn parse(text: &str) -> Result<Policy> {
        if text.trim().is_empty() {
            return Ok(Policy::default());
        }
        toml::from_str(text).map_err(|e| kerr(format!("policy: {e}")))
    }
    pub fn default_text() -> String {
        "# s3vault keystore policy (key hierarchy 3.4)\nretention_days = 30\nactivate_requires = [\"b2-mirror\", \"bitwarden\"]\nmin_master_slots = 3\nwarn_after_days = 25\n".into()
    }
}

/// The non-secret public part of a keystore file (readable without a slot: mirror, drills, audits).
#[derive(Debug, Clone)]
pub struct PublicInfo {
    pub keystore_id: [u8; 16],
    pub epoch: u64,
    pub issued: u64,
    pub prev_hash: [u8; 32],
    pub slots: Vec<PublicSlot>,
    pub blocks: usize,
}

#[derive(Debug, Clone)]
pub struct PublicSlot {
    pub id: [u8; 8],
    pub kem: Kem,
    pub target: Target,
    enc: Vec<u8>,
    wrapped: Vec<u8>,
}

struct RawBlock {
    reference: [u8; 16],
    nonce: [u8; 24],
    ct: Vec<u8>,
}

struct Parsed {
    info: PublicInfo,
    nonce: [u8; 24],
    pub_end: usize,
    blocks: Vec<RawBlock>,
    blocks_end: usize,
    sealed: Vec<u8>,
}

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.b.len() - self.p < n {
            return Err(FormatError::Malformed("keystore truncated"));
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
}

fn parse_file(bytes: &[u8]) -> Result<Parsed> {
    if bytes.len() < HEADER_LEN || &bytes[..8] != KS_MAGIC {
        return Err(FormatError::Malformed("not an s3vault keystore (magic)"));
    }
    let mut r = Rd { b: bytes, p: 8 };
    let keystore_id = r.arr::<16>()?;
    let epoch = r.u64()?;
    let issued = r.u64()?;
    let prev_hash = r.arr::<32>()?;
    let nonce = r.arr::<24>()?;
    let n = r.u16()?;
    let mut slots = Vec::new();
    for _ in 0..n {
        let id = r.arr::<8>()?;
        let kem = Kem::from_id(r.u16()?)?;
        let tkind = r.take(1)?[0];
        let tref = r.arr::<16>()?;
        let target = match tkind {
            0 => Target::Master,
            1 => Target::Tenant(tref),
            _ => return Err(FormatError::Malformed("keystore slot target")),
        };
        let el = r.u16()? as usize;
        let enc = r.take(el)?.to_vec();
        let wl = r.u16()? as usize;
        let wrapped = r.take(wl)?.to_vec();
        slots.push(PublicSlot { id, kem, target, enc, wrapped });
    }
    let pub_end = r.p;
    let nb = r.u16()?;
    let mut blocks = Vec::new();
    for _ in 0..nb {
        let reference = r.arr::<16>()?;
        let nonce = r.arr::<24>()?;
        let l = r.u32()? as usize;
        let ct = r.take(l)?.to_vec();
        blocks.push(RawBlock { reference, nonce, ct });
    }
    let blocks_end = r.p;
    let sl = r.u32()? as usize;
    let sealed = r.take(sl)?.to_vec();
    if r.p != bytes.len() {
        return Err(FormatError::Malformed("keystore: trailing bytes"));
    }
    Ok(Parsed {
        info: PublicInfo { keystore_id, epoch, issued, prev_hash, slots, blocks: blocks.len() },
        nonce,
        pub_end,
        blocks,
        blocks_end,
        sealed,
    })
}

impl PublicInfo {
    pub fn parse(bytes: &[u8]) -> Result<PublicInfo> {
        Ok(parse_file(bytes)?.info)
    }
}

fn wrap_info(ks_id: &[u8; 16], epoch: u64, slot: &[u8; 8], target: Target) -> Vec<u8> {
    let mut v = b"s3vault/keystore/v1/slot".to_vec();
    v.extend_from_slice(ks_id);
    v.extend_from_slice(&epoch.to_be_bytes());
    v.extend_from_slice(slot);
    v.push(target.kind());
    v.extend_from_slice(&target.reference());
    v
}

fn block_ad(public: &[u8], reference: &[u8; 16]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"s3vault/keystore/v1/block");
    h.update(public);
    let mut v = h.finalize().to_vec();
    v.extend_from_slice(reference);
    v
}

fn sealed_ad(before: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"s3vault/keystore/v1/sealed");
    h.update(before);
    h.finalize().to_vec()
}

fn tlv(out: &mut Vec<u8>, tag: u8, v: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&(v.len() as u32).to_be_bytes());
    out.extend_from_slice(v);
}

/// The opened keystore of one epoch. Holds key material; never logged (Debug prints no secret).
pub struct Keystore {
    pub id: [u8; 16],
    pub epoch: u64,
    pub issued: u64,
    pub prev_hash: [u8; 32],
    muk: Key32,
    /// The master keyring text, verbatim.
    pub master_text: Zeroizing<String>,
    /// The tenant keyring with every `K_t`.
    pub tenants: TenantKeyring,
    refs: BTreeMap<String, [u8; 16]>,
    tuks: BTreeMap<[u8; 16], Key32>,
    /// Later generations `K_t[1..]` (KH9, next release; always empty now) and the write generation.
    gens: BTreeMap<[u8; 16], (u32, Vec<Key32>)>,
    pub ledger: Ledger,
    pub slots: Vec<SlotEntry>,
    pub policy_text: String,
    pub changes: Vec<Change>,
}

impl std::fmt::Debug for Keystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keystore({} epoch {} slots {})", hex::encode(self.id), self.epoch, self.slots.len())
    }
}

fn random_key() -> Key32 {
    Zeroizing::new(hpke::random::<32>())
}

fn redact(tk: &TenantKeyring, refs: &BTreeMap<String, [u8; 16]>) -> Result<String> {
    let text = tk.to_text();
    let mut out = String::new();
    for line in text.lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() == 7 && p[0] == "tenant" && p[6] != "-" {
            let r = refs.get(p[1]).ok_or_else(|| kerr(format!("tenant {} has no block", p[1])))?;
            out.push_str(&p[..6].join(" "));
            out.push_str(&format!(" @{}\n", hex::encode(r)));
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    Ok(out)
}

/// The tenant keyring text with each `@ref` replaced by `K_t[0]` of its block; and the name -> ref map.
fn unredact(
    text: &str,
    keys: &BTreeMap<[u8; 16], ([u8; 16], Key32)>,
) -> Result<(TenantKeyring, BTreeMap<String, [u8; 16]>)> {
    let mut full = Zeroizing::new(String::new());
    let mut refs = BTreeMap::new();
    for line in text.lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() == 7 && p[0] == "tenant" && p[6].starts_with('@') {
            let mut r = [0u8; 16];
            hex::decode_to_slice(&p[6][1..], &mut r).map_err(|_| kerr("bad tenant ref"))?;
            let (id, k) = keys.get(&r).ok_or_else(|| kerr(format!("tenant {}: block missing", p[1])))?;
            if hex::encode(id) != p[2] {
                return Err(kerr(format!("tenant {}: block id does not match the keyring", p[1])));
            }
            full.push_str(&p[..6].join(" "));
            full.push(' ');
            full.push_str(&BASE64.encode(&k[..]));
            full.push('\n');
            refs.insert(p[1].to_string(), r);
        } else {
            full.push_str(line);
            full.push('\n');
        }
    }
    let tk = TenantKeyring::parse(&full)?;
    Ok((tk, refs))
}

impl Keystore {
    /// Epoch 1 from the plain files (`kh-init`). The tenant keyring must hold no pending tenant (freeze rule).
    pub fn init(
        master_text: &str,
        tenants_text: &str,
        ledger_text: &str,
        policy_text: &str,
        slots: &[SlotPub],
        by: &str,
        now: u64,
    ) -> Result<Keystore> {
        let master = MasterV2::parse(master_text)?;
        if !master.is_escrowed() {
            return Err(kerr("the master root has no confirmed escrow record; refusing"));
        }
        let tenants = if tenants_text.trim().is_empty() {
            TenantKeyring::default()
        } else {
            TenantKeyring::parse(tenants_text)?
        };
        if let Some(t) = tenants.tenants.values().find(|t| t.status == TenantStatus::Pending) {
            return Err(kerr(format!("tenant {} is pending: confirm or wait before kh-init (freeze rule)", t.name)));
        }
        let ledger = Ledger::parse(ledger_text)?;
        Policy::parse(policy_text)?;
        let mut ks = Keystore {
            id: hpke::random::<16>(),
            epoch: 1,
            issued: now,
            prev_hash: [0; 32],
            muk: random_key(),
            master_text: Zeroizing::new(master_text.to_string()),
            tenants: TenantKeyring::default(),
            refs: BTreeMap::new(),
            tuks: BTreeMap::new(),
            gens: BTreeMap::new(),
            ledger,
            slots: Vec::new(),
            policy_text: policy_text.to_string(),
            changes: Vec::new(),
        };
        for t in tenants.tenants.values() {
            if t.k_t.is_some() {
                let r = hpke::random::<16>();
                ks.refs.insert(t.name.clone(), r);
                ks.tuks.insert(r, random_key());
                ks.gens.insert(r, (0, Vec::new()));
            }
        }
        ks.tenants = tenants;
        for s in slots {
            ks.push_slot(s, by, now)?;
        }
        if !ks.slots.iter().any(|s| s.target == "master") {
            return Err(kerr("at least one master slot is needed"));
        }
        ks.changes.push(Change { epoch: 1, at: now, op: "init".into(), detail: format!("{} slots", ks.slots.len()) });
        Ok(ks)
    }

    pub fn policy(&self) -> Policy {
        Policy::parse(&self.policy_text).unwrap_or_default()
    }

    pub fn master(&self) -> Result<MasterV2> {
        MasterV2::parse(&self.master_text)
    }

    /// The bundle text s3vault-keyd serves (same code path as from the plain files).
    pub fn bundle_text(&self) -> Result<Zeroizing<String>> {
        let b = Bundle { master: self.master()?, tenants: self.tenants.clone(), ledger: self.ledger.clone() };
        Ok(b.to_text())
    }

    /// The tenant keyring text exactly as the plain file would hold it (dual write, drills).
    pub fn tenants_text(&self) -> Zeroizing<String> {
        self.tenants.to_text()
    }

    pub fn master_slots(&self) -> usize {
        self.slots.iter().filter(|s| s.target == "master").count()
    }

    fn push_slot(&mut self, s: &SlotPub, by: &str, now: u64) -> Result<String> {
        let id = hex::encode(s.id());
        if self.slots.iter().any(|e| e.id == id) {
            return Err(kerr(format!("slot {id} exists (same public key)")));
        }
        let target = match &s.target {
            PubTarget::Master => "master".to_string(),
            PubTarget::Tenant(n) => {
                let r = self.refs.get(n).ok_or_else(|| kerr(format!("no live tenant {n} for a tenant slot")))?;
                format!("tenant:{}", hex::encode(r))
            }
        };
        self.slots.push(SlotEntry {
            id: id.clone(),
            kem: s.kem.name().into(),
            target,
            pk: BASE64.encode(&s.pk),
            kind: s.kind.clone(),
            label: s.label.clone(),
            holder: s.holder.clone(),
            backend: s.backend.clone(),
            created: now,
            created_by: by.to_string(),
        });
        Ok(id)
    }

    fn bump(&mut self, op: &str, detail: String, now: u64) {
        self.epoch += 1;
        self.issued = now;
        self.changes.push(Change { epoch: self.epoch, at: now, op: op.into(), detail });
    }

    /// Start the next epoch from this one (`file` = the bytes this epoch was read from: the hash chain).
    pub fn chain_from(&mut self, file: &[u8]) {
        self.prev_hash = sha256(file);
    }

    pub fn add_slot(&mut self, s: &SlotPub, by: &str, now: u64) -> Result<String> {
        let id = self.push_slot(s, by, now)?;
        self.bump("slot-add", format!("{id} {} {} {}", s.kind, s.label, s.backend), now);
        Ok(id)
    }

    /// Revoke a slot: delete it and rotate the unlock key it opened (MUK or the tenant's TUK).
    pub fn revoke_slot(&mut self, id: &str, now: u64) -> Result<SlotEntry> {
        let i = self.slots.iter().position(|s| s.id == id).ok_or_else(|| kerr(format!("no slot {id}")))?;
        let t = self.slots[i].target()?;
        if t == Target::Master && self.master_slots() <= 1 {
            return Err(kerr("refusing to revoke the last master slot"));
        }
        let e = self.slots.remove(i);
        match t {
            Target::Master => self.muk = random_key(),
            Target::Tenant(r) => {
                self.tuks.insert(r, random_key());
            }
        }
        self.bump("slot-revoke", format!("{id} {} {}", e.kind, e.label), now);
        Ok(e)
    }

    /// New MUK without a slot change (e.g. after a suspected leak of an unwrapped MUK).
    pub fn rotate_muk(&mut self, now: u64) {
        self.muk = random_key();
        self.bump("muk-rotate", String::new(), now);
    }

    pub fn tenant_rewrap(&mut self, name: &str, now: u64) -> Result<()> {
        let r = *self.refs.get(name).ok_or_else(|| kerr(format!("no live tenant {name}")))?;
        self.tuks.insert(r, random_key());
        self.bump("tenant-rewrap", name.into(), now);
        Ok(())
    }

    /// A new tenant (pending until the epoch holding it is confirmed at every required place, KH15).
    pub fn tenant_create(&mut self, name: &str, now: u64) -> Result<TenantEntry> {
        let e = self.tenants.create(name, now)?.clone();
        let r = hpke::random::<16>();
        self.refs.insert(name.into(), r);
        self.tuks.insert(r, random_key());
        self.gens.insert(r, (0, Vec::new()));
        self.bump("tenant-create", name.into(), now);
        Ok(e)
    }

    /// Erase a tenant: ledger entry first (same entry as `s3vault-keyd tenant-erase`), then the key, its block,
    /// its TUK and its tenant slots go.
    pub fn tenant_erase(&mut self, name: &str, now: u64) -> Result<ledger::Entry> {
        let before = self.tenants.tenants.get(name).cloned().ok_or_else(|| kerr(format!("no tenant {name}")))?;
        let m = Arc::new(self.master()?);
        let fp = m.tenant_keys(&before).map(|k| k.fingerprint.clone()).ok();
        let e = self.tenants.erase(name, now)?.clone();
        let tag = m.tenant_tag(&e.id);
        let entry = self
            .ledger
            .append(
                ledger::TENANT_ERASED,
                &e.id_hex(),
                &tag,
                serde_json::json!({"k_t_fingerprint": fp, "erased_at": now, "created": e.created}),
                now,
            )
            .clone();
        if let Some(r) = self.refs.remove(name) {
            self.tuks.remove(&r);
            self.gens.remove(&r);
            let t = format!("tenant:{}", hex::encode(r));
            self.slots.retain(|s| s.target != t);
        }
        self.bump("tenant-erase", name.into(), now);
        Ok(entry)
    }

    /// Activate pending tenants held by a confirmed copy (`copy` = the tenant keyring of the confirmed epoch,
    /// `digest` its file digest, `place` the places that hold it). The same `confirm_escrow` call as the plain
    /// path, so a dual write gives the same keyring text.
    pub fn tenant_activate(&mut self, copy: &TenantKeyring, digest: &str, place: &str, now: u64) -> Result<Vec<String>> {
        let act = self.tenants.confirm_escrow(copy, digest, place, now)?;
        self.bump("tenant-activate", format!("{act:?} at {place}"), now);
        Ok(act)
    }

    /// Import a proxy outbox (object erasures, proofs), as `s3vault-keyd ledger-import`.
    pub fn ledger_import(&mut self, outbox: &Ledger, now: u64) -> Result<usize> {
        let n = import_outbox(&mut self.ledger, outbox)?;
        if n > 0 {
            self.bump("ledger-import", format!("{n} entries"), now);
        }
        Ok(n)
    }

    /// Replace the master text (7.8 step 4: the escrow places). The root, the legacy keys and the active KEK
    /// generation must not change, and the root must stay escrowed.
    pub fn replace_master_text(&mut self, text: &str, now: u64) -> Result<()> {
        let old = self.master()?;
        let new = MasterV2::parse(text)?;
        if old.fingerprint() != new.fingerprint()
            || old.escrow_digest() != new.escrow_digest()
            || old.active != new.active
            || !new.is_escrowed()
        {
            return Err(kerr("the new master text changes key material or loses the escrow record; refusing"));
        }
        self.master_text = Zeroizing::new(text.to_string());
        self.bump("master-escrow-replace", new.escrow_places().join(","), now);
        Ok(())
    }

    /// Serialise this epoch. Every slot gets a fresh HPKE wrap of its unlock key.
    pub fn seal(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(KS_MAGIC);
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.issued.to_be_bytes());
        out.extend_from_slice(&self.prev_hash);
        let nonce = hpke::random::<24>();
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&(self.slots.len() as u16).to_be_bytes());
        for s in &self.slots {
            let id = s.id_bytes()?;
            let kem = s.kem()?;
            let t = s.target()?;
            let key: &Key32 = match t {
                Target::Master => &self.muk,
                Target::Tenant(r) => self.tuks.get(&r).ok_or_else(|| kerr("tenant slot without a TUK"))?,
            };
            let (enc, ct) = hpke::seal(kem, &s.pk()?, &wrap_info(&self.id, self.epoch, &id, t), b"", &key[..])?;
            out.extend_from_slice(&id);
            out.extend_from_slice(&kem.id().to_be_bytes());
            out.push(t.kind());
            out.extend_from_slice(&t.reference());
            out.extend_from_slice(&(enc.len() as u16).to_be_bytes());
            out.extend_from_slice(&enc);
            out.extend_from_slice(&(ct.len() as u16).to_be_bytes());
            out.extend_from_slice(&ct);
        }
        let public_end = out.len();
        out.extend_from_slice(&(self.refs.len() as u16).to_be_bytes());
        for (name, r) in &self.refs {
            let t = &self.tenants.tenants[name];
            let k = t.k_t.as_ref().ok_or_else(|| kerr("live tenant without a key"))?;
            let (wg, extra) = self.gens.get(r).cloned().unwrap_or((0, Vec::new()));
            let mut pt = Zeroizing::new(Vec::new());
            pt.extend_from_slice(&t.id);
            pt.extend_from_slice(&wg.to_be_bytes());
            pt.extend_from_slice(&((1 + extra.len()) as u16).to_be_bytes());
            pt.extend_from_slice(&k[..]);
            for x in &extra {
                pt.extend_from_slice(&x[..]);
            }
            let bn = hpke::random::<24>();
            let tuk = self.tuks.get(r).ok_or_else(|| kerr("tenant block without a TUK"))?;
            let ct = XChaCha20Poly1305::new((&**tuk).into())
                .encrypt(&XNonce::from(bn), Payload { msg: &pt, aad: &block_ad(&out[..public_end], r) })
                .map_err(|_| FormatError::Auth)?;
            out.extend_from_slice(r);
            out.extend_from_slice(&bn);
            out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
            out.extend_from_slice(&ct);
        }
        let mut pt = Zeroizing::new(Vec::new());
        tlv(&mut pt, 1, self.master_text.as_bytes());
        tlv(&mut pt, 2, redact(&self.tenants, &self.refs)?.as_bytes());
        let mut tuks = Zeroizing::new(Vec::new());
        for (r, k) in &self.tuks {
            tuks.extend_from_slice(r);
            tuks.extend_from_slice(&k[..]);
        }
        tlv(&mut pt, 3, &tuks);
        tlv(&mut pt, 4, self.ledger.to_text().as_bytes());
        tlv(&mut pt, 5, &serde_json::to_vec(&self.slots).expect("json"));
        tlv(&mut pt, 6, self.policy_text.as_bytes());
        tlv(&mut pt, 7, &serde_json::to_vec(&self.changes).expect("json"));
        let ct = XChaCha20Poly1305::new((&*self.muk).into())
            .encrypt(&XNonce::from(nonce), Payload { msg: &pt, aad: &sealed_ad(&out) })
            .map_err(|_| FormatError::Auth)?;
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open a keystore file through a master slot.
    pub fn open(bytes: &[u8], secret: &dyn SlotSecret) -> Result<Keystore> {
        let p = parse_file(bytes)?;
        let want = slot_id(secret.kem(), &secret.public_key());
        let s = p
            .info
            .slots
            .iter()
            .find(|s| s.id == want)
            .ok_or_else(|| kerr(format!("no slot for this key (slot id {}) in epoch {}", hex::encode(want), p.info.epoch)))?;
        if s.target != Target::Master {
            return Err(kerr("this is a tenant slot; it opens only its tenant block"));
        }
        let muk = hpke::open(secret, &s.enc, &wrap_info(&p.info.keystore_id, p.info.epoch, &s.id, s.target), b"", &s.wrapped)?;
        if muk.len() != 32 {
            return Err(FormatError::Malformed("keystore: unlock key length"));
        }
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&muk);
        Self::open_with_muk(bytes, &p, k)
    }

    fn open_with_muk(bytes: &[u8], p: &Parsed, muk: Key32) -> Result<Keystore> {
        let pt = Zeroizing::new(
            XChaCha20Poly1305::new((&*muk).into())
                .decrypt(&XNonce::from(p.nonce), Payload { msg: &p.sealed, aad: &sealed_ad(&bytes[..p.blocks_end]) })
                .map_err(|_| FormatError::Auth)?,
        );
        let mut sec: BTreeMap<u8, &[u8]> = BTreeMap::new();
        let mut r = Rd { b: &pt, p: 0 };
        while r.p < pt.len() {
            let tag = r.take(1)?[0];
            let l = r.u32()? as usize;
            sec.insert(tag, r.take(l)?);
        }
        let text = |t: u8| -> Result<&str> {
            std::str::from_utf8(sec.get(&t).copied().unwrap_or(b"")).map_err(|_| FormatError::Malformed("keystore utf-8"))
        };
        let master_text = Zeroizing::new(text(1)?.to_string());
        let mut tuks = BTreeMap::new();
        for c in sec.get(&3).copied().unwrap_or(b"").chunks(48) {
            if c.len() != 48 {
                return Err(FormatError::Malformed("keystore TUK table"));
            }
            let mut k = Zeroizing::new([0u8; 32]);
            k.copy_from_slice(&c[16..]);
            tuks.insert(<[u8; 16]>::try_from(&c[..16]).unwrap(), k);
        }
        let mut keys = BTreeMap::new();
        let mut gens = BTreeMap::new();
        for b in &p.blocks {
            let tuk = tuks.get(&b.reference).ok_or_else(|| kerr("tenant block without a TUK"))?;
            let bp = open_block(&bytes[..p.pub_end], b, tuk)?;
            keys.insert(b.reference, (bp.0, bp.2));
            gens.insert(b.reference, (bp.1, bp.3));
        }
        let (tenants, refs) = unredact(text(2)?, &keys)?;
        if refs.len() != keys.len() {
            return Err(kerr("tenant blocks and keyring entries differ"));
        }
        let ledger = Ledger::parse(text(4)?)?;
        let slots: Vec<SlotEntry> =
            serde_json::from_slice(sec.get(&5).copied().unwrap_or(b"[]")).map_err(|_| kerr("slot table"))?;
        // the slot table must describe exactly the slots in the public part
        if slots.len() != p.info.slots.len()
            || !p.info.slots.iter().all(|ps| {
                slots.iter().any(|s| {
                    s.id_bytes().ok() == Some(ps.id) && s.kem().ok() == Some(ps.kem) && s.target().ok() == Some(ps.target)
                })
            })
        {
            return Err(kerr("slot table does not match the public slots"));
        }
        let changes: Vec<Change> =
            serde_json::from_slice(sec.get(&7).copied().unwrap_or(b"[]")).map_err(|_| kerr("change log"))?;
        Ok(Keystore {
            id: p.info.keystore_id,
            epoch: p.info.epoch,
            issued: p.info.issued,
            prev_hash: p.info.prev_hash,
            muk,
            master_text,
            tenants,
            refs,
            tuks,
            gens,
            ledger,
            slots,
            policy_text: text(6)?.to_string(),
            changes,
        })
    }

    /// Open one tenant block through a tenant slot: (tenant id, `K_t[0..]`).
    pub fn open_tenant(bytes: &[u8], secret: &dyn SlotSecret) -> Result<([u8; 16], Vec<Key32>)> {
        let p = parse_file(bytes)?;
        let want = slot_id(secret.kem(), &secret.public_key());
        let s = p.info.slots.iter().find(|s| s.id == want).ok_or_else(|| kerr("no slot for this key"))?;
        let Target::Tenant(r) = s.target else { return Err(kerr("not a tenant slot")) };
        let tuk = hpke::open(secret, &s.enc, &wrap_info(&p.info.keystore_id, p.info.epoch, &s.id, s.target), b"", &s.wrapped)?;
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&tuk[..32]);
        let b = p.blocks.iter().find(|b| b.reference == r).ok_or_else(|| kerr("tenant block missing"))?;
        let (id, _, k0, mut rest) = open_block(&bytes[..p.pub_end], b, &k)?;
        rest.insert(0, k0);
        Ok((id, rest))
    }

    pub fn tenant_ref(&self, name: &str) -> Option<String> {
        self.refs.get(name).map(hex::encode)
    }
}

type BlockPlain = ([u8; 16], u32, Key32, Vec<Key32>);

fn open_block(public: &[u8], b: &RawBlock, tuk: &Key32) -> Result<BlockPlain> {
    let pt = Zeroizing::new(
        XChaCha20Poly1305::new((&**tuk).into())
            .decrypt(&XNonce::from(b.nonce), Payload { msg: &b.ct, aad: &block_ad(public, &b.reference) })
            .map_err(|_| FormatError::Auth)?,
    );
    if pt.len() < 16 + 4 + 2 + 32 {
        return Err(FormatError::Malformed("tenant block"));
    }
    let id: [u8; 16] = pt[..16].try_into().unwrap();
    let wg = u32::from_be_bytes(pt[16..20].try_into().unwrap());
    let n = u16::from_be_bytes(pt[20..22].try_into().unwrap()) as usize;
    if n == 0 || pt.len() != 22 + 32 * n {
        return Err(FormatError::Malformed("tenant block keys"));
    }
    let mut ks: Vec<Key32> = pt[22..]
        .chunks(32)
        .map(|c| {
            let mut k = Zeroizing::new([0u8; 32]);
            k.copy_from_slice(c);
            k
        })
        .collect();
    let k0 = ks.remove(0);
    Ok((id, wg, k0, ks))
}

/// Import a proxy outbox into a ledger (object erasures and proofs only), as `s3vault-keyd ledger-import`.
pub fn import_outbox(l: &mut Ledger, outbox: &Ledger) -> Result<usize> {
    let mut n = 0;
    for e in &outbox.entries {
        if e.kind != ledger::OBJECT_ERASED && e.kind != ledger::ERASURE_PROOF {
            return Err(kerr(format!("outbox entry {} has kind {}: refused", e.seq, e.kind)));
        }
        if l.has_source(&e.hash) {
            continue;
        }
        let mut detail = e.detail.clone();
        if let Some(o) = detail.as_object_mut() {
            o.insert("src_hash".into(), e.hash.clone().into());
            o.insert("src_seq".into(), e.seq.into());
        }
        l.append(&e.kind, &e.tenant_id, &e.tenant_tag, detail, e.at);
        n += 1;
    }
    Ok(n)
}

// ------------------------------------------------------------------------------------------ epoch directory

/// `keys/keystore/`: one file per epoch, `ks-<epoch>.s3vks`, written create-only under `.lock`.
pub struct KeystoreDir {
    pub dir: PathBuf,
}

pub fn epoch_file_name(epoch: u64) -> String {
    format!("ks-{epoch:010}.s3vks")
}

pub fn epoch_of(name: &str) -> Option<u64> {
    name.strip_prefix("ks-")?.strip_suffix(".s3vks")?.parse().ok()
}

/// Test hook: with the `fault-injection` feature, `S3VAULT_CRASH_AT=<point>` aborts the process there.
pub fn crash_point(_point: &str) {
    #[cfg(feature = "fault-injection")]
    if std::env::var("S3VAULT_CRASH_AT").ok().as_deref() == Some(_point) {
        eprintln!("fault injection: abort at {_point}");
        std::process::abort();
    }
}

pub struct DirLock {
    _f: fs::File,
}

impl KeystoreDir {
    pub fn new(dir: impl Into<PathBuf>) -> KeystoreDir {
        KeystoreDir { dir: dir.into() }
    }

    pub fn epochs(&self) -> std::io::Result<Vec<(u64, PathBuf)>> {
        let mut v: Vec<(u64, PathBuf)> = match fs::read_dir(&self.dir) {
            Ok(d) => d
                .flatten()
                .filter_map(|e| epoch_of(&e.file_name().to_string_lossy()).map(|n| (n, e.path())))
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        v.sort();
        Ok(v)
    }

    pub fn newest(&self) -> std::io::Result<Option<(u64, PathBuf)>> {
        Ok(self.epochs()?.pop())
    }

    /// Read the newest epoch: (epoch, bytes).
    pub fn read_newest(&self) -> Result<(u64, Vec<u8>)> {
        let (n, p) = self
            .newest()
            .map_err(|e| kerr(format!("list {}: {e}", self.dir.display())))?
            .ok_or_else(|| kerr(format!("no keystore epoch in {}", self.dir.display())))?;
        let b = fs::read(&p).map_err(|e| kerr(format!("read {}: {e}", p.display())))?;
        Ok((n, b))
    }

    pub fn lock(&self) -> Result<DirLock> {
        fs::create_dir_all(&self.dir).map_err(|e| kerr(format!("create {}: {e}", self.dir.display())))?;
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.dir.join(".lock"))
            .map_err(|e| kerr(format!("lock file: {e}")))?;
        f.lock().map_err(|e| kerr(format!("lock: {e}")))?;
        // a crashed writer leaves only a partial file, never a final one: remove it
        if let Ok(d) = fs::read_dir(&self.dir) {
            for e in d.flatten() {
                if e.file_name().to_string_lossy().ends_with(".partial") {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
        Ok(DirLock { _f: f })
    }

    /// Write epoch `epoch` (create-only). `expect_prev` is the newest epoch the caller read: if another
    /// writer got there first, this fails and the caller retries on the new epoch (review R8).
    pub fn write_epoch(&self, _lock: &DirLock, expect_prev: Option<u64>, epoch: u64, bytes: &[u8]) -> Result<PathBuf> {
        let newest = self.newest().map_err(|e| kerr(e.to_string()))?.map(|x| x.0);
        if newest != expect_prev {
            return Err(kerr(format!("the keystore changed underneath (newest {newest:?}, expected {expect_prev:?}); retry")));
        }
        if epoch != expect_prev.unwrap_or(0) + 1 {
            return Err(kerr("epochs grow by one"));
        }
        let name = epoch_file_name(epoch);
        let partial = self.dir.join(format!(".{name}.partial"));
        let fin = self.dir.join(&name);
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&partial)
                .map_err(|e| kerr(format!("create {}: {e}", partial.display())))?;
            let half = bytes.len() / 2;
            f.write_all(&bytes[..half]).map_err(|e| kerr(e.to_string()))?;
            crash_point("ks-write-half");
            f.write_all(&bytes[half..]).map_err(|e| kerr(e.to_string()))?;
            f.sync_all().map_err(|e| kerr(e.to_string()))?;
        }
        crash_point("ks-before-link");
        // link() refuses an existing name: create-only even against a writer that ignores the lock
        fs::hard_link(&partial, &fin).map_err(|e| kerr(format!("create {}: {e}", fin.display())))?;
        let _ = fs::remove_file(&partial);
        if let Ok(d) = fs::File::open(&self.dir) {
            let _ = d.sync_all();
        }
        crash_point("ks-after-link");
        Ok(fin)
    }

    /// Retention (KH8): delete epochs issued more than `max_age_secs` ago, except the newest. `purge`
    /// deletes every epoch but the newest at once (after a revoke). Returns the deleted names.
    pub fn prune(&self, _lock: &DirLock, now: u64, max_age_secs: u64, purge: bool) -> Result<Vec<String>> {
        let mut v = self.epochs().map_err(|e| kerr(e.to_string()))?;
        v.pop();
        let mut del = Vec::new();
        for (_, p) in v {
            let b = fs::read(&p).map_err(|e| kerr(e.to_string()))?;
            let issued = PublicInfo::parse(&b).map(|i| i.issued).unwrap_or(0);
            if purge || now.saturating_sub(issued) > max_age_secs {
                fs::remove_file(&p).map_err(|e| kerr(e.to_string()))?;
                del.push(p.file_name().unwrap().to_string_lossy().to_string());
            }
        }
        Ok(del)
    }
}

/// Check the hash chain of a set of keystore files (any order): each epoch's `prev_hash` must equal the
/// SHA-256 of the file of the epoch before it, where both are present. Returns the newest epoch and digest.
pub fn check_chain(files: &[Vec<u8>]) -> Result<(u64, String)> {
    let mut by: BTreeMap<u64, &Vec<u8>> = BTreeMap::new();
    let mut id = None;
    for f in files {
        let i = PublicInfo::parse(f)?;
        if *id.get_or_insert(i.keystore_id) != i.keystore_id {
            return Err(kerr("copies of different keystores"));
        }
        if let Some(prev) = by.insert(i.epoch, f) {
            if prev != f {
                return Err(kerr(format!("two different files for epoch {} (fork or tampering)", i.epoch)));
            }
        }
    }
    for (e, f) in &by {
        if let Some(p) = by.get(&(e - 1)) {
            if PublicInfo::parse(f)?.prev_hash != sha256(p) {
                return Err(kerr(format!("hash chain broken between epochs {} and {e}", e - 1)));
            }
        }
    }
    let (e, f) = by.iter().next_back().ok_or_else(|| kerr("no copy"))?;
    Ok((*e, file_digest(f)))
}

// ------------------------------------------------------------------------------------------ places

/// `keys/places`: where each epoch is confirmed (non-secret): `place <epoch> <sha256> <place> <unix>`.
#[derive(Debug, Clone, Default)]
pub struct Places {
    pub rows: Vec<(u64, String, String, u64)>,
}

impl Places {
    pub fn load(path: &Path) -> Result<Places> {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(kerr(format!("read places: {e}"))),
        };
        let mut rows = Vec::new();
        for l in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let p: Vec<&str> = l.split_whitespace().collect();
            match p.as_slice() {
                ["place", e, d, pl, at] => rows.push((
                    e.parse().map_err(|_| kerr("places: epoch"))?,
                    d.to_string(),
                    pl.to_string(),
                    at.parse().map_err(|_| kerr("places: time"))?,
                )),
                _ => return Err(kerr("places: unrecognised line")),
            }
        }
        Ok(Places { rows })
    }

    /// Append one confirmation (fsync'd append; the file is only ever appended to).
    pub fn append(path: &Path, epoch: u64, digest: &str, place: &str, at: u64) -> Result<()> {
        if place.is_empty() || !place.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(kerr("place must be one word"));
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| kerr(format!("open places: {e}")))?;
        writeln!(f, "place {epoch} {digest} {place} {at}").map_err(|e| kerr(e.to_string()))?;
        f.sync_all().map_err(|e| kerr(e.to_string()))
    }

    pub fn places_for(&self, epoch: u64, digest: &str) -> Vec<String> {
        let mut v: Vec<String> =
            self.rows.iter().filter(|r| r.0 == epoch && r.1 == digest).map(|r| r.2.clone()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// Newest confirmed epoch per place: place -> (epoch, at).
    pub fn latest(&self) -> BTreeMap<String, (u64, u64)> {
        let mut m: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for (e, _, p, at) in &self.rows {
            let x = m.entry(p.clone()).or_insert((*e, *at));
            if *e > x.0 {
                *x = (*e, *at);
            }
        }
        m
    }
}

// ------------------------------------------------------------------------------------------ baseline

/// The frozen, non-secret baseline of step 7.2 and the comparison of `kh-verify --compare` (review R14: it
/// compares against this record, never against files the keystore code wrote).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Baseline {
    pub master_fingerprint: String,
    pub root_escrow_digest: String,
    pub root_escrowed: bool,
    pub legacy_fingerprint: String,
    pub active: u32,
    pub bundle_sha256: String,
    pub ledger_len: usize,
    pub ledger_head: String,
    /// name -> (id, status, K_t fingerprint or "-")
    pub tenants: BTreeMap<String, (String, String, String)>,
    pub extra: Vec<String>,
}

pub fn tenant_fp(m: &Arc<MasterV2>, t: &TenantEntry) -> String {
    m.tenant_keys(t).map(|k| k.fingerprint.clone()).unwrap_or_else(|_| "-".into())
}

impl Baseline {
    pub fn from_bundle(text: &str) -> Result<Baseline> {
        let b = Bundle::parse(text)?;
        let m = Arc::new(b.master);
        let mut tenants = BTreeMap::new();
        for t in b.tenants.tenants.values() {
            tenants.insert(t.name.clone(), (t.id_hex(), t.status.as_str().to_string(), tenant_fp(&m, t)));
        }
        Ok(Baseline {
            master_fingerprint: m.fingerprint(),
            root_escrow_digest: m.escrow_digest(),
            root_escrowed: m.is_escrowed(),
            legacy_fingerprint: m.legacy.as_ref().map(|l| l.fingerprint()).unwrap_or_else(|| "none".into()),
            active: m.active,
            bundle_sha256: hex::encode(sha256(text.as_bytes())),
            ledger_len: b.ledger.entries.len(),
            ledger_head: b.ledger.head().1.to_string(),
            tenants,
            extra: Vec::new(),
        })
    }

    pub fn to_text(&self) -> String {
        let mut s = format!(
            "s3vault-kh-baseline v1\nmaster_fingerprint {}\nroot_escrow_digest {}\nroot_escrowed {}\nlegacy_fingerprint {}\nactive {}\nbundle_sha256 {}\nledger {} {}\n",
            self.master_fingerprint,
            self.root_escrow_digest,
            self.root_escrowed,
            self.legacy_fingerprint,
            self.active,
            self.bundle_sha256,
            self.ledger_len,
            self.ledger_head
        );
        for (n, (id, st, fp)) in &self.tenants {
            s.push_str(&format!("tenant {n} {id} {st} {fp}\n"));
        }
        for e in &self.extra {
            s.push_str(e);
            s.push('\n');
        }
        s
    }

    pub fn parse(text: &str) -> Result<Baseline> {
        let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'));
        if lines.next() != Some("s3vault-kh-baseline v1") {
            return Err(kerr("not a baseline file"));
        }
        let mut b = Baseline::default();
        for l in lines {
            let p: Vec<&str> = l.split_whitespace().collect();
            match p.as_slice() {
                ["master_fingerprint", v] => b.master_fingerprint = v.to_string(),
                ["root_escrow_digest", v] => b.root_escrow_digest = v.to_string(),
                ["root_escrowed", v] => b.root_escrowed = *v == "true",
                ["legacy_fingerprint", v] => b.legacy_fingerprint = v.to_string(),
                ["active", v] => b.active = v.parse().map_err(|_| kerr("baseline active"))?,
                ["bundle_sha256", v] => b.bundle_sha256 = v.to_string(),
                ["ledger", n, h] => {
                    b.ledger_len = n.parse().map_err(|_| kerr("baseline ledger"))?;
                    b.ledger_head = h.to_string();
                }
                ["tenant", n, id, st, fp] => {
                    b.tenants.insert(n.to_string(), (id.to_string(), st.to_string(), fp.to_string()));
                }
                _ => b.extra.push(l.to_string()),
            }
        }
        Ok(b)
    }
}

/// Recorded changes since the baseline (`keys/baseline.changes`): `tenant-create N`, `tenant-erase N`,
/// `tenant-activate N`, `master-escrow-replace`. Anything else that differs is a failure.
pub fn parse_changes(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut p = l.splitn(2, ' ');
            (p.next().unwrap_or("").to_string(), p.next().unwrap_or("").trim().to_string())
        })
        .collect()
}

fn ct_eq(a: &str, b: &str) -> bool {
    bool::from(subtle::ConstantTimeEq::ct_eq(a.as_bytes(), b.as_bytes()))
}

/// Compare a bundle (from a keystore, a keyd or the plain files) with the baseline plus recorded changes.
/// Returns the report lines and whether everything is equal or explained.
pub fn compare(base: &Baseline, bundle_text: &str, changes: &[(String, String)]) -> Result<(Vec<String>, bool)> {
    let now = Baseline::from_bundle(bundle_text)?;
    let b = Bundle::parse(bundle_text)?;
    let mut rep = Vec::new();
    let mut ok = true;
    let mut check = |name: &str, good: bool, detail: String| {
        rep.push(format!("{} {name}{}", if good { "equal" } else { "DIFFERS" }, detail));
        if !good {
            ok = false;
        }
    };
    let has = |op: &str, arg: &str| changes.iter().any(|(o, a)| o == op && a == arg);
    check("master_fingerprint", ct_eq(&base.master_fingerprint, &now.master_fingerprint), String::new());
    check("root_escrow_digest", ct_eq(&base.root_escrow_digest, &now.root_escrow_digest), String::new());
    check("root_escrowed", now.root_escrowed, String::new());
    check("legacy_fingerprint", ct_eq(&base.legacy_fingerprint, &now.legacy_fingerprint), String::new());
    check("active_generation", base.active == now.active, String::new());
    for (n, (id, st, fp)) in &base.tenants {
        match now.tenants.get(n) {
            None => check(&format!("tenant {n}"), false, ": missing".into()),
            Some((id2, st2, fp2)) => {
                let id_ok = ct_eq(id, id2);
                let same = id_ok && st == st2 && ct_eq(fp, fp2);
                let erased_ok = id_ok
                    && st2 == "erased"
                    && st != "erased"
                    && has("tenant-erase", n)
                    && b.ledger.erased_tenants().contains(id.as_str());
                let activated_ok = id_ok && st == "pending" && st2 == "active" && ct_eq(fp, fp2) && has("tenant-activate", n);
                let detail = if same {
                    String::new()
                } else if erased_ok {
                    ": erased since the baseline (recorded, ledger entry present)".into()
                } else if activated_ok {
                    ": activated since the baseline (recorded)".into()
                } else {
                    format!(": baseline {st}, now {st2}; id {} K_t fingerprint {}", if id_ok { "equal" } else { "DIFFERS" }, if ct_eq(fp, fp2) { "equal" } else { "DIFFERS" })
                };
                check(&format!("tenant {n}"), same || erased_ok || activated_ok, detail);
            }
        }
    }
    for n in now.tenants.keys().filter(|n| !base.tenants.contains_key(*n)) {
        check(&format!("tenant {n}"), has("tenant-create", n), ": created since the baseline".into());
    }
    let prefix_ok = b.ledger.entries.len() >= base.ledger_len
        && (base.ledger_len == 0 || b.ledger.entries[base.ledger_len - 1].hash == base.ledger_head);
    check(
        "ledger",
        prefix_ok,
        format!(": baseline {} entries is a prefix; now {}", base.ledger_len, b.ledger.entries.len()),
    );
    let bundle_eq = ct_eq(&base.bundle_sha256, &now.bundle_sha256);
    let explained = !changes.is_empty() || b.ledger.entries.len() > base.ledger_len;
    check(
        "bundle_sha256",
        bundle_eq || explained,
        if bundle_eq { String::new() } else { " (differs, explained by the recorded changes above)".into() },
    );
    Ok((rep, ok))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpke::SoftSecret;
    use crate::keyring::Keyring;

    fn master_text() -> String {
        let mut m = MasterV2::generate(Some(Keyring::generate()));
        let d = m.escrow_digest();
        m.confirm_escrow(&d, "owner-mac", 5).unwrap();
        m.to_text().to_string()
    }

    fn slot(kem: Kem, kind: &str, label: &str) -> (SoftSecret, SlotPub) {
        let sk = SoftSecret::generate(kem);
        let p = SlotPub {
            kem,
            pk: sk.public_key(),
            kind: kind.into(),
            label: label.into(),
            holder: "owner".into(),
            backend: "file".into(),
            target: PubTarget::Master,
        };
        (sk, p)
    }

    fn sample() -> (String, String, String) {
        let mt = master_text();
        let m = Arc::new(MasterV2::parse(&mt).unwrap());
        let mut tk = TenantKeyring::default();
        for n in ["owner", "alice", "drill", "spare"] {
            tk.create(n, 10).unwrap();
        }
        let copy = tk.clone();
        tk.confirm_escrow(&copy, "abcd", "owner-mac", 11).unwrap();
        let mut l = Ledger::default();
        let e = tk.erase("drill", 12).unwrap().clone();
        l.append(ledger::TENANT_ERASED, &e.id_hex(), &m.tenant_tag(&e.id), serde_json::json!({}), 12);
        (mt, tk.to_text().to_string(), l.to_text())
    }

    fn plain_bundle(mt: &str, tt: &str, lt: &str) -> String {
        Bundle {
            master: MasterV2::parse(mt).unwrap(),
            tenants: TenantKeyring::parse(tt).unwrap(),
            ledger: Ledger::parse(lt).unwrap(),
        }
        .to_text()
        .to_string()
    }

    #[test]
    fn init_seal_open_bundle_identical_through_every_slot() {
        let (mt, tt, lt) = sample();
        let (hs, hp) = slot(Kem::X25519, "host", "d-host");
        let (ds, dp) = slot(Kem::P256, "device", "a-se");
        let (rs, rp) = slot(Kem::X25519, "recovery", "bitwarden");
        let ks = Keystore::init(&mt, &tt, &lt, &Policy::default_text(), &[hp, dp, rp], "test", 100).unwrap();
        let file = ks.seal().unwrap();
        let want = plain_bundle(&mt, &tt, &lt);
        for s in [&hs as &dyn SlotSecret, &ds, &rs] {
            let o = Keystore::open(&file, s).unwrap();
            assert_eq!(o.bundle_text().unwrap().as_str(), want, "KH1: byte-identical bundle");
            assert_eq!(o.epoch, 1);
            assert_eq!(o.slots.len(), 3);
        }
        let stranger = SoftSecret::generate(Kem::X25519);
        assert!(Keystore::open(&file, &stranger).is_err());
        // tamper anywhere: fails
        for i in [9, 60, 100, file.len() / 2, file.len() - 1] {
            let mut t = file.clone();
            t[i] ^= 1;
            assert!(Keystore::open(&t, &hs).is_err(), "tamper at {i}");
        }
        assert!(Keystore::open(&file[..file.len() - 1], &hs).is_err());
        // no secret in the public bytes: the root and every K_t are absent in plain
        let m = MasterV2::parse(&mt).unwrap();
        let tk = TenantKeyring::parse(&tt).unwrap();
        let needle = |k: &[u8]| file.windows(k.len()).any(|w| w == k);
        assert!(!needle(m.escrow_key().as_slice()));
        for t in tk.tenants.values() {
            if let Some(k) = &t.k_t {
                assert!(!needle(&k[..]));
                assert!(!needle(BASE64.encode(&k[..]).as_bytes()));
            }
            assert!(!needle(t.name.as_bytes()) || t.name.len() < 4, "tenant names are sealed");
        }
    }

    #[test]
    fn revoke_rotates_muk_and_old_secret_opens_only_old_epochs() {
        let (mt, tt, lt) = sample();
        let (hs, hp) = slot(Kem::X25519, "host", "d-host");
        let (ds, dp) = slot(Kem::P256, "device", "a-se");
        let (rs, rp) = slot(Kem::X25519, "recovery", "bitwarden");
        let mut ks = Keystore::init(&mt, &tt, &lt, "", &[hp, dp.clone(), rp], "t", 1).unwrap();
        let e1 = ks.seal().unwrap();
        let muk1 = ks.muk.clone();
        ks.chain_from(&e1);
        ks.revoke_slot(&hex::encode(dp.id()), 2).unwrap();
        assert_ne!(&muk1[..], &ks.muk[..], "MUK rotated");
        let e2 = ks.seal().unwrap();
        assert!(Keystore::open(&e2, &ds).is_err(), "revoked slot opens nothing new");
        assert!(Keystore::open(&e1, &ds).is_ok(), "old copies still open (4.2, the honest limit)");
        let o = Keystore::open(&e2, &rs).unwrap();
        assert_eq!(o.epoch, 2);
        assert_eq!(o.bundle_text().unwrap().as_str(), plain_bundle(&mt, &tt, &lt));
        assert_eq!(check_chain(&[e2.clone(), e1.clone()]).unwrap().0, 2);
        // cannot revoke the last master slot
        let mut o = Keystore::open(&e2, &hs).unwrap();
        o.revoke_slot(&hex::encode(slot_id(Kem::X25519, &rs.public_key())), 3).unwrap();
        assert!(o.revoke_slot(&hex::encode(slot_id(Kem::X25519, &hs.public_key())), 4).is_err());
    }

    #[test]
    fn tenant_lifecycle_matches_plain_code_path() {
        let (mt, tt, lt) = sample();
        let (hs, hp) = slot(Kem::X25519, "host", "d-host");
        let mut ks = Keystore::init(&mt, &tt, &lt, "", &[hp], "t", 1).unwrap();
        let f1 = ks.seal().unwrap();
        ks.chain_from(&f1);
        let e = ks.tenant_create("newbie", 50).unwrap();
        assert_eq!(e.status, TenantStatus::Pending);
        let f2 = ks.seal().unwrap();
        let mut o = Keystore::open(&f2, &hs).unwrap();
        assert_eq!(o.tenants.tenants["newbie"].status, TenantStatus::Pending);
        // the plain path: same entry inserted by the old code gives the same text
        let mut plain = TenantKeyring::parse(&tt).unwrap();
        plain.tenants.insert("newbie".into(), o.tenants.tenants["newbie"].clone());
        assert_eq!(plain.to_text().as_str(), o.tenants_text().as_str());
        // activation from a confirmed copy, both paths
        let copy = o.tenants.clone();
        o.chain_from(&f2);
        let act = o.tenant_activate(&copy, "dd", "b2-mirror+bitwarden", 60).unwrap();
        plain.confirm_escrow(&copy, "dd", "b2-mirror+bitwarden", 60).unwrap();
        assert_eq!(act, ["newbie"]);
        assert_eq!(plain.to_text().as_str(), o.tenants_text().as_str());
        // erase: ledger entry, key gone from the file
        let k = BASE64.encode(&o.tenants.tenants["owner"].k_t.as_ref().unwrap()[..]);
        let f3 = o.seal().unwrap();
        o.chain_from(&f3);
        o.tenant_erase("owner", 70).unwrap();
        let f4 = o.seal().unwrap();
        let o4 = Keystore::open(&f4, &hs).unwrap();
        assert_eq!(o4.tenants.tenants["owner"].status, TenantStatus::Erased);
        assert!(!o4.bundle_text().unwrap().contains(&k));
        assert_eq!(o4.ledger.entries.len(), 2);
        assert_eq!(PublicInfo::parse(&f4).unwrap().blocks, PublicInfo::parse(&f3).unwrap().blocks - 1);
        assert_eq!(check_chain(&[f1, f2, f3, f4]).unwrap().0, 4);
    }

    #[test]
    fn tenant_slot_opens_only_its_block_and_rewrap() {
        let (mt, tt, lt) = sample();
        let (_hs, hp) = slot(Kem::X25519, "host", "d-host");
        let mut ks = Keystore::init(&mt, &tt, &lt, "", &[hp], "t", 1).unwrap();
        let ts = SoftSecret::generate(Kem::X25519);
        let tp = SlotPub {
            kem: Kem::X25519,
            pk: ts.public_key(),
            kind: "tenant-device".into(),
            label: "alice-phone".into(),
            holder: "alice".into(),
            backend: "file".into(),
            target: PubTarget::Tenant("alice".into()),
        };
        ks.add_slot(&tp, "t", 2).unwrap();
        let f = ks.seal().unwrap();
        let (id, keys) = Keystore::open_tenant(&f, &ts).unwrap();
        assert_eq!(id, ks.tenants.tenants["alice"].id);
        assert_eq!(&keys[0][..], &ks.tenants.tenants["alice"].k_t.as_ref().unwrap()[..]);
        assert!(Keystore::open(&f, &ts).is_err(), "a tenant slot does not open MUK");
        ks.tenant_rewrap("alice", 3).unwrap();
        let f2 = ks.seal().unwrap();
        assert!(Keystore::open_tenant(&f2, &ts).is_ok(), "re-wrapped to the remaining tenant slot");
        ks.revoke_slot(&hex::encode(tp.id()), 4).unwrap();
        assert!(Keystore::open_tenant(&ks.seal().unwrap(), &ts).is_err());
    }

    #[test]
    fn init_refuses_pending_and_unescrowed() {
        let (mt, _, _) = sample();
        let mut tk = TenantKeyring::default();
        tk.create("p", 1).unwrap();
        let (_s, p) = slot(Kem::X25519, "host", "h");
        assert!(Keystore::init(&mt, &tk.to_text(), "", "", &[p.clone()], "t", 1).is_err());
        let m = MasterV2::generate(None);
        assert!(Keystore::init(&m.to_text(), "", "", "", &[p], "t", 1).is_err());
    }

    #[test]
    fn dir_create_only_lock_and_prune() {
        let d = std::env::temp_dir().join(format!("ks-dir-{}", rand::random::<u64>()));
        let kd = KeystoreDir::new(&d);
        let l = kd.lock().unwrap();
        kd.write_epoch(&l, None, 1, b"one").unwrap();
        assert!(kd.write_epoch(&l, None, 1, b"x").is_err(), "lost update refused");
        assert!(kd.write_epoch(&l, Some(1), 3, b"x").is_err());
        fs::write(d.join(".ks-0000000002.s3vks.partial"), b"half").unwrap();
        drop(l);
        let l = kd.lock().unwrap();
        assert!(!d.join(".ks-0000000002.s3vks.partial").exists(), "partial removed");
        kd.write_epoch(&l, Some(1), 2, b"two").unwrap();
        assert_eq!(kd.newest().unwrap().unwrap().0, 2);
        // prune on garbage files keeps the newest; unparsable epochs count as issued at 0
        let del = kd.prune(&l, 10_000_000, 30 * 86_400, false).unwrap();
        assert_eq!(del, [epoch_file_name(1)]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn baseline_compare() {
        let (mt, tt, lt) = sample();
        let text = plain_bundle(&mt, &tt, &lt);
        let base = Baseline::from_bundle(&text).unwrap();
        let back = Baseline::parse(&base.to_text()).unwrap();
        assert_eq!(back, base);
        let (rep, ok) = compare(&base, &text, &[]).unwrap();
        assert!(ok, "{rep:?}");
        // erase without a recorded change fails; with it passes
        let (hs, hp) = slot(Kem::X25519, "host", "h");
        let mut ks = Keystore::init(&mt, &tt, &lt, "", &[hp], "t", 1).unwrap();
        ks.tenant_erase("alice", 9).unwrap();
        let t2 = ks.bundle_text().unwrap();
        assert!(!compare(&base, &t2, &[]).unwrap().1);
        assert!(compare(&base, &t2, &[("tenant-erase".into(), "alice".into())]).unwrap().1);
        // a changed K_t is never explained
        let mut tk = TenantKeyring::parse(&tt).unwrap();
        tk.tenants.get_mut("owner").unwrap().k_t = Some(random_key());
        let bad = plain_bundle(&mt, &tk.to_text(), &lt);
        let (rep, ok) = compare(&base, &bad, &[("tenant-create".into(), "x".into())]).unwrap();
        assert!(!ok);
        assert!(rep.iter().any(|l| l.starts_with("DIFFERS tenant owner")));
        let _ = hs;
    }
}
