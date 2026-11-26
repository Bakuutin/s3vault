//! The erasure ledger (decision D4): a hash-chained JSON-lines record of erased tenants and objects, and
//! of the proof of each erasure. It holds opaque ids only (tenant ids and tags, store names), no personal
//! data, so copies can be kept anywhere: next to the key service (authoritative), on the proxy, and with
//! the owner. Every restore (index rebuild, follower copy, store or snapshot restore) replays it before the
//! restored data is served again, so no restore can bring an erased tenant or object back.
//!
//! ```text
//! entry = {"seq":n,"prev":"<hash of entry n-1, or 64 zeros>","at":unix,"kind":"...","tenant_id":"...",
//!          "tenant_tag":"...","detail":{...},"hash":"<hex SHA-256 over the entry without hash>"}
//! kinds: tenant-erased   (key service: K_t destroyed)
//!        object-erased   (proxy: one object deleted on request; detail.store_name, detail.generation)
//!        erasure-proof   (proxy: the proof record of a tenant erasure; detail = the proof)
//! ```
//!
//! A copy that is a strict prefix of another is a rollback (an old backup); [`Ledger::merge`] keeps the
//! longer chain and refuses two chains that diverge.

use crate::{FormatError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub const TENANT_ERASED: &str = "tenant-erased";
pub const OBJECT_ERASED: &str = "object-erased";
pub const ERASURE_PROOF: &str = "erasure-proof";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub prev: String,
    pub at: u64,
    pub kind: String,
    pub tenant_id: String,
    #[serde(default)]
    pub tenant_tag: String,
    #[serde(default)]
    pub detail: serde_json::Value,
    pub hash: String,
}

#[derive(Serialize)]
struct Unhashed<'a> {
    seq: u64,
    prev: &'a str,
    at: u64,
    kind: &'a str,
    tenant_id: &'a str,
    tenant_tag: &'a str,
    detail: &'a serde_json::Value,
}

impl Entry {
    fn compute_hash(&self) -> String {
        let u = Unhashed {
            seq: self.seq,
            prev: &self.prev,
            at: self.at,
            kind: &self.kind,
            tenant_id: &self.tenant_id,
            tenant_tag: &self.tenant_tag,
            detail: &self.detail,
        };
        let mut h = Sha256::new();
        h.update(b"s3vault/ledger/v1");
        h.update(serde_json::to_vec(&u).expect("json"));
        hex::encode(h.finalize())
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Ledger {
    pub entries: Vec<Entry>,
}

fn lerr(m: impl Into<String>) -> FormatError {
    FormatError::Keyring(format!("ledger: {}", m.into()))
}

impl Ledger {
    /// Parse and verify the whole chain.
    pub fn parse(text: &str) -> Result<Ledger> {
        let mut l = Ledger::default();
        for (i, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
            let e: Entry =
                serde_json::from_str(line).map_err(|e| lerr(format!("line {}: {e}", i + 1)))?;
            l.push_verified(e)?;
        }
        Ok(l)
    }

    fn push_verified(&mut self, e: Entry) -> Result<()> {
        let (want_seq, want_prev) = self.next_link();
        if e.seq != want_seq || e.prev != want_prev {
            return Err(lerr(format!("entry {} does not continue the chain", e.seq)));
        }
        if e.compute_hash() != e.hash {
            return Err(lerr(format!("entry {} was altered (hash mismatch)", e.seq)));
        }
        self.entries.push(e);
        Ok(())
    }

    fn next_link(&self) -> (u64, String) {
        match self.entries.last() {
            None => (1, GENESIS.to_string()),
            Some(l) => (l.seq + 1, l.hash.clone()),
        }
    }

    pub fn to_text(&self) -> String {
        let mut s = String::new();
        for e in &self.entries {
            s.push_str(&serde_json::to_string(e).expect("json"));
            s.push('\n');
        }
        s
    }

    /// Append a new entry; returns it.
    pub fn append(
        &mut self,
        kind: &str,
        tenant_id: &str,
        tenant_tag: &str,
        detail: serde_json::Value,
        at: u64,
    ) -> &Entry {
        let (seq, prev) = self.next_link();
        let mut e = Entry {
            seq,
            prev,
            at,
            kind: kind.to_string(),
            tenant_id: tenant_id.to_string(),
            tenant_tag: tenant_tag.to_string(),
            detail,
            hash: String::new(),
        };
        e.hash = e.compute_hash();
        self.entries.push(e);
        self.entries.last().unwrap()
    }

    pub fn head(&self) -> (u64, &str) {
        match self.entries.last() {
            None => (0, GENESIS),
            Some(e) => (e.seq, e.hash.as_str()),
        }
    }

    /// Keep the longer of two verified chains when one extends the other. Returns whether `self` changed.
    /// Diverging chains are an error (someone rewrote history): keep both copies and investigate.
    pub fn merge(&mut self, other: &Ledger) -> Result<bool> {
        let n = self.entries.len().min(other.entries.len());
        if self.entries[..n] != other.entries[..n] {
            return Err(lerr("two copies of the ledger diverge; refusing to merge"));
        }
        if other.entries.len() > self.entries.len() {
            self.entries = other.entries.clone();
            return Ok(true);
        }
        Ok(false)
    }

    /// Tenant ids erased so far.
    pub fn erased_tenants(&self) -> std::collections::BTreeSet<String> {
        self.entries
            .iter()
            .filter(|e| e.kind == TENANT_ERASED)
            .map(|e| e.tenant_id.clone())
            .collect()
    }

    /// Whether an entry with this kind and source hash (`detail.src_hash`) is already recorded (imports
    /// from the proxy are idempotent).
    pub fn has_source(&self, src_hash: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.detail.get("src_hash").and_then(|v| v.as_str()) == Some(src_hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn chain_append_verify_tamper_merge() {
        let mut l = Ledger::default();
        l.append(TENANT_ERASED, "aa", "tag1", json!({"k_t_fingerprint": "f"}), 10);
        l.append(OBJECT_ERASED, "bb", "tag2", json!({"store_name": "o/tag2/x"}), 11);
        let text = l.to_text();
        let back = Ledger::parse(&text).unwrap();
        assert_eq!(back, l);
        assert_eq!(back.head().0, 2);
        assert_eq!(back.erased_tenants().into_iter().collect::<Vec<_>>(), ["aa"]);
        // an edited entry, a dropped entry or a reordering are detected
        assert!(Ledger::parse(&text.replace("\"aa\"", "\"ab\"")).is_err());
        let lines: Vec<&str> = text.lines().collect();
        assert!(Ledger::parse(lines[1]).is_err());
        assert!(Ledger::parse(&format!("{}\n{}\n", lines[1], lines[0])).is_err());
        // merge: a prefix (an old backup) never shortens the chain; a longer copy extends it
        let mut old = Ledger::parse(lines[0]).unwrap();
        let mut cur = back.clone();
        assert!(!cur.merge(&old).unwrap());
        assert_eq!(cur.entries.len(), 2);
        assert!(old.merge(&cur).unwrap());
        assert_eq!(old, cur);
        // diverging histories are refused
        let mut fork = Ledger::parse(lines[0]).unwrap();
        fork.append(TENANT_ERASED, "cc", "t", json!({}), 12);
        assert!(cur.merge(&fork).is_err());
    }
}
