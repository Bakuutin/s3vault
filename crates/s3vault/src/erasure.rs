//! Erasure (decisions D1 and D4): tenant erasure with a proof record, object erasure, and the replay of
//! the erasure ledger after any restore.
//!
//! * A **tenant erasure** is cryptographic: the key service destroys `K_t` first (`s3vault-keyd
//!   tenant-erase`, which also writes the `tenant-erased` ledger entry and a new escrow copy). Then the
//!   proxy ([`erase_tenant`]) freezes the tenant, writes the name manifest, drops the keys from RAM, deletes
//!   the index partition and the staging files, purges the store by manifest and by prefix (hygiene: the
//!   data is already unreadable everywhere), and writes a proof record.
//! * An **object erasure** ([`erase_object`]) deletes one object on request (a third party's recording)
//!   and records an `object-erased` entry with the hash of the object's head, so a replay can remove that
//!   exact version from a restored store or follower without any key.
//! * Entries originating on the proxy go to its **outbox** (`data_dir/outbox.jsonl`, hash-chained), which
//!   the operator imports into the key service's ledger (`s3vault-keyd ledger-import`).
//! * [`replay`] applies the ledger to a store or a follower directory: everything under an erased tenant's
//!   tag is deleted, and every erased object version whose head hash matches is deleted.

use crate::remote::{Remote, RemoteError};
use crate::vault::{TenantRt, Vault, VaultError, now_ms};
use anyhow::{Context, Result, anyhow, bail};
use futures::StreamExt;
use s3vault_format::keys2::{Bundle, TenantStatus};
use s3vault_format::ledger::{self, Entry, Ledger};
use s3vault_format::object::{self, HEAD_PROBE_LEN};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

static OUTBOX: Mutex<()> = Mutex::new(());

fn unix_now() -> u64 {
    (now_ms() / 1000).max(0) as u64
}

pub fn outbox_path(vault: &Vault) -> PathBuf {
    vault.cfg.server.data_dir.join("outbox.jsonl")
}

/// The proxy's outbox: entries it originated (object erasures, erasure proofs), hash-chained.
pub fn read_outbox(vault: &Vault) -> Result<Ledger> {
    match std::fs::read_to_string(outbox_path(vault)) {
        Ok(t) => Ok(Ledger::parse(&t).context("outbox")?),
        Err(_) => Ok(Ledger::default()),
    }
}

fn append_outbox(vault: &Vault, kind: &str, tenant_id: &str, tag: &str, detail: Value) -> Result<Entry> {
    let _g = OUTBOX.lock().unwrap();
    let mut l = read_outbox(vault)?;
    let e = l.append(kind, tenant_id, tag, detail, unix_now()).clone();
    let path = outbox_path(vault);
    let tmp = path.with_extension("jsonl.new");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(l.to_text().as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, &path)?;
    Ok(e)
}

/// Every entry to honour: the merged ledger plus outbox entries not yet imported into it.
pub fn all_entries(vault: &Vault) -> Result<Vec<Entry>> {
    let u = vault.unlocked()?;
    let l = u.ledger.lock().unwrap().clone();
    let out = read_outbox(vault)?;
    let mut v = l.entries.clone();
    for e in out.entries {
        if !l.has_source(&e.hash) {
            v.push(e);
        }
    }
    Ok(v)
}

fn hex_sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// Distinct stores holding a tenant's objects (its buckets' stores and its snapshot store).
fn tenant_stores(vault: &Vault, tenant: &str) -> Vec<Arc<Remote>> {
    let mut m: BTreeMap<String, Arc<Remote>> = BTreeMap::new();
    for b in vault.buckets.values().filter(|b| b.tenant == tenant) {
        m.insert(b.store.label.clone(), b.store.clone());
    }
    m.into_values().collect()
}

async fn delete_prefix(store: &Remote, prefix: &str, dry_run: bool) -> Result<(u64, u64)> {
    let (mut found, mut deleted) = (0u64, 0u64);
    loop {
        // Re-list from the start each round: deletes shift continuation tokens on some stores.
        let page = store
            .list(prefix, None, None, 1000)
            .await
            .map_err(|e| anyhow!("list {prefix}: {e}"))?;
        if page.items.is_empty() {
            break;
        }
        found += page.items.len() as u64;
        if dry_run {
            if page.next_token.is_none() {
                break;
            }
            // count the rest without deleting
            let mut token = page.next_token;
            while let Some(t) = token {
                let p = store
                    .list(prefix, None, Some(&t), 1000)
                    .await
                    .map_err(|e| anyhow!("list {prefix}: {e}"))?;
                found += p.items.len() as u64;
                token = p.next_token;
            }
            break;
        }
        let store_arc = store;
        let results: Vec<bool> = futures::stream::iter(page.items.into_iter().map(|i| i.key))
            .map(|k| async move { store_arc.delete(&k).await.is_ok() })
            .buffer_unordered(16)
            .collect()
            .await;
        let ok = results.iter().filter(|r| **r).count() as u64;
        deleted += ok;
        if ok == 0 {
            bail!("could not delete under {prefix}");
        }
    }
    Ok((found, deleted))
}

async fn count_prefix(store: &Remote, prefix: &str) -> Result<u64> {
    Ok(delete_prefix(store, prefix, true).await?.0)
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct PurgeCounts {
    pub manifest_deleted: u64,
    pub manifest_errors: u64,
    pub prefix_found: u64,
    pub prefix_deleted: u64,
    pub remaining_after: u64,
}

/// Erase a tenant on the proxy after the key service destroyed its key (see the module docs). `bundle`
/// is a fresh fetch from the key service. Returns the proof record (also appended to the outbox).
pub async fn erase_tenant(vault: &Vault, name: &str, bundle: &Bundle) -> Result<Value> {
    let u = vault.unlocked()?;
    let t: Arc<TenantRt> = u
        .tenant_loaded(name)
        .with_context(|| format!("tenant {name} is not loaded on this proxy"))?;
    let id = t.keys.id_hex();
    let tag = t.keys.tag.clone();
    let entry = bundle
        .tenants
        .tenants
        .get(name)
        .with_context(|| format!("the key service does not know tenant {name}"))?;
    if entry.id_hex() != id {
        bail!("the key service's tenant {name} has another id");
    }
    if entry.status != TenantStatus::Erased {
        bail!(
            "tenant {name} is still {} at the key service: run `s3vault-keyd tenant-erase --name {name}` first",
            entry.status.as_str()
        );
    }
    let keyd_entry = bundle
        .ledger
        .entries
        .iter()
        .find(|e| e.kind == ledger::TENANT_ERASED && e.tenant_id == id)
        .context("the key service's ledger has no tenant-erased entry for this tenant")?
        .clone();
    // 1. Freeze: the tenant's buckets answer 403 from here on.
    vault.set_frozen(&t, true)?;
    // 2. Manifest of every store name of the tenant (opaque names only) and the counts.
    let dir = vault.cfg.server.data_dir.join("erasures").join(&id);
    std::fs::create_dir_all(&dir)?;
    let mut manifest = Vec::new();
    let (mut live, mut tomb, mut bytes) = (0u64, 0u64, 0u64);
    let snap_store = vault.cfg.tenant_store(name).map(|s| vault.stores[s].clone());
    let (mut ab, mut ak) = (String::new(), String::new());
    loop {
        let page = t.index.page_rows(&ab, &ak, 5000)?;
        let Some(last) = page.last() else { break };
        (ab, ak) = (last.bucket.clone(), last.key.clone());
        for r in &page {
            let store = match vault.buckets.get(&r.bucket) {
                Some(b) => b.store.clone(),
                None if r.bucket == crate::config::META_BUCKET => match &snap_store {
                    Some(s) => s.clone(),
                    None => continue,
                },
                None => continue,
            };
            if r.state == crate::index::LIVE {
                live += 1;
                bytes += r.size;
            } else {
                tomb += 1;
            }
            let n = vault.store_name(&t, &store, &r.bucket, &r.key);
            manifest.push((store, n));
        }
    }
    let manifest_text: String = manifest
        .iter()
        .map(|(s, n)| format!("{} {n}\n", s.label))
        .collect();
    std::fs::write(dir.join("manifest.txt"), &manifest_text)?;
    let manifest_sha = hex_sha(manifest_text.as_bytes());
    let fingerprint = t.keys.fingerprint.clone();
    // 3. Drop the keys from RAM and the tenant's local state from disk.
    u.drop_tenant(name);
    {
        let mut l = u.ledger.lock().unwrap();
        if let Err(e) = l.merge(&bundle.ledger) {
            warn!("ledger merge during erasure: {e}");
        }
    }
    let idx_path = vault.tenant_index_path(&id);
    drop(t);
    let mut index_removed = true;
    for suffix in ["", "-wal", "-shm"] {
        let p = PathBuf::from(format!("{}{suffix}", idx_path.display()));
        if p.exists() && std::fs::remove_file(&p).is_err() {
            index_removed = false;
        }
    }
    let staging = vault.staging_dir.join(&id);
    let staging_removed = !staging.exists() || std::fs::remove_dir_all(&staging).is_ok();
    // 4. Purge (hygiene): by manifest, then everything left under the tenant's prefix.
    let mut purge = PurgeCounts::default();
    let results: Vec<bool> = futures::stream::iter(manifest.clone())
        .map(|(s, n)| async move { s.delete(&n).await.is_ok() })
        .buffer_unordered(16)
        .collect()
        .await;
    purge.manifest_deleted = results.iter().filter(|r| **r).count() as u64;
    purge.manifest_errors = results.len() as u64 - purge.manifest_deleted;
    for s in tenant_stores(vault, name) {
        let prefix = format!("{}{tag}/", s.prefix);
        let (f, d) = delete_prefix(&s, &prefix, false).await?;
        purge.prefix_found += f;
        purge.prefix_deleted += d;
        purge.remaining_after += count_prefix(&s, &prefix).await?;
    }
    let proof = json!({
        "kind": "tenant-erasure",
        "tenant_id": id,
        "tenant_tag": tag,
        "k_t_fingerprint": fingerprint,
        "keyd_erased_at": entry.erased_at,
        "keyd_ledger_entry": keyd_entry.hash,
        "proxy_erased_at": unix_now(),
        "crypto_erasure": "K_t destroyed at the key service and dropped from the proxy's RAM: every copy (store versions, follower, snapshots, staging) is unreadable",
        "manifest_sha256": manifest_sha,
        "manifest_names": manifest.len(),
        "index_rows": {"live": live, "tombstones": tomb, "live_bytes": bytes},
        "index_partition_removed": index_removed,
        "staging_removed": staging_removed,
        "purge": purge,
        "pending": [
            "store object versions: deleted by the store lifecycle within D days (B2: 7); verify after D+1 days with GET /tenant/verify-erasure",
            "follower copy: purge the tenant prefix (s3vault ledger-replay --dir) or by manifest",
            "escrow copies of the tenant keyring issued before the erasure: destroyed within R_tk = 30 days (s3vault-keyd escrow-prune; s3vault escrow-prune on the owner's device)",
            "import this proof into the key service's ledger (s3vault-keyd ledger-import)"
        ],
    });
    let e = append_outbox(vault, ledger::ERASURE_PROOF, &id, &tag, proof.clone())?;
    std::fs::write(dir.join("proof.json"), serde_json::to_vec_pretty(&proof)?)?;
    info!(tenant = %name, id = %id, "tenant erased on the proxy");
    Ok(json!({"proof": proof, "outbox_entry": e.hash, "outbox_seq": e.seq}))
}

/// After the store lifecycle window: what is left under an erased tenant's prefix (0 expected), from the
/// ledger's tag.
pub async fn verify_tenant_erasure(vault: &Vault, tenant_id: &str) -> Result<Value> {
    let entries = all_entries(vault)?;
    let e = entries
        .iter()
        .find(|e| e.kind == ledger::TENANT_ERASED && e.tenant_id == tenant_id)
        .context("no tenant-erased entry for this id in the ledger")?;
    let mut per_store = BTreeMap::new();
    for (label, s) in &vault.stores {
        let prefix = format!("{}{}/", s.prefix, e.tenant_tag);
        per_store.insert(label.clone(), count_prefix(s, &prefix).await?);
    }
    let index_present = vault.tenant_index_path(tenant_id).exists();
    let proofs: Vec<&Entry> = entries
        .iter()
        .filter(|x| x.kind == ledger::ERASURE_PROOF && x.tenant_id == tenant_id)
        .collect();
    Ok(json!({
        "tenant_id": tenant_id,
        "tenant_tag": e.tenant_tag,
        "erased_at": e.at,
        "ledger_entry": e.hash,
        "objects_remaining_per_store": per_store,
        "index_partition_present": index_present,
        "proofs": proofs,
    }))
}

/// Erase one object (a third party's recording, for example): delete it (a tombstone in buckets with a
/// fallback, so it is never read through again) and record an `object-erased` entry in the outbox.
pub async fn erase_object(vault: &Vault, bucket: &str, key: &str) -> Result<Entry, VaultError> {
    let u = vault.unlocked()?;
    let (b, t) = vault.tenant_of(&u, bucket)?;
    let row = match t.index.get(bucket, key)? {
        Some(r) if r.state == crate::index::LIVE => r,
        _ => return Err(VaultError::NoSuchKey),
    };
    let name = vault.store_name(&t, &b.store, bucket, key);
    vault.delete(bucket, key).await?;
    let detail = json!({
        "store": b.store.label,
        "store_name": name,
        "head_sha256": hex::encode(row.ad),
        "generation": row.generation,
        "erased_at": unix_now(),
    });
    Ok(append_outbox(vault, ledger::OBJECT_ERASED, &t.keys.id_hex(), &t.keys.tag, detail)?)
}

#[derive(Debug, Default, Serialize)]
pub struct ReplayReport {
    pub dry_run: bool,
    pub tenants_erased: u64,
    pub tenant_objects_found: u64,
    pub tenant_objects_deleted: u64,
    pub objects_erased: u64,
    pub object_versions_found: u64,
    pub object_versions_deleted: u64,
    pub index_partitions_removed: u64,
}

/// Where a replay applies the ledger.
pub enum ReplayTarget {
    /// A store of record (restored, or B2 after re-promoting versions).
    Store(Arc<Remote>),
    /// A follower copy as a directory (`<dir>/<prefix><tag>/<name>`, as `rclone copy` writes it).
    Dir { dir: PathBuf, prefix: String },
}

fn head_hash(bytes: &[u8]) -> Option<String> {
    let need = object::needed_head_len(bytes).ok()?;
    (bytes.len() >= need).then(|| hex_sha(&bytes[..need]))
}

/// Apply the erasure ledger to a store or a follower directory. Needs no key: erased tenants are matched
/// by their tag (a folder), erased objects by store name and the hash of their head.
pub async fn replay(entries: &[Entry], target: &ReplayTarget, dry_run: bool) -> Result<ReplayReport> {
    let mut rep = ReplayReport {
        dry_run,
        ..Default::default()
    };
    for e in entries {
        match e.kind.as_str() {
            ledger::TENANT_ERASED if !e.tenant_tag.is_empty() => {
                rep.tenants_erased += 1;
                match target {
                    ReplayTarget::Store(s) => {
                        let prefix = format!("{}{}/", s.prefix, e.tenant_tag);
                        let (f, d) = delete_prefix(s, &prefix, dry_run).await?;
                        rep.tenant_objects_found += f;
                        rep.tenant_objects_deleted += d;
                    }
                    ReplayTarget::Dir { dir, prefix } => {
                        let p = dir.join(format!("{prefix}{}", e.tenant_tag));
                        if p.is_dir() {
                            let n = count_files(&p);
                            rep.tenant_objects_found += n;
                            if !dry_run {
                                std::fs::remove_dir_all(&p)?;
                                rep.tenant_objects_deleted += n;
                            }
                        }
                    }
                }
            }
            ledger::OBJECT_ERASED => {
                rep.objects_erased += 1;
                let Some(name) = e.detail.get("store_name").and_then(|v| v.as_str()) else {
                    continue;
                };
                let want = e.detail.get("head_sha256").and_then(|v| v.as_str()).unwrap_or("");
                match target {
                    ReplayTarget::Store(s) => {
                        let bytes = match s.get_bytes(name, Some((0, HEAD_PROBE_LEN as u64 - 1))).await {
                            Ok((_, b)) => b,
                            Err(RemoteError::NotFound) => continue,
                            Err(e) => bail!("replay: {e}"),
                        };
                        if head_hash(&bytes).as_deref() == Some(want) {
                            rep.object_versions_found += 1;
                            if !dry_run {
                                s.delete(name).await.map_err(|e| anyhow!("{e}"))?;
                                rep.object_versions_deleted += 1;
                            }
                        }
                    }
                    ReplayTarget::Dir { dir, .. } => {
                        let p = dir.join(name);
                        let Ok(mut f) = std::fs::File::open(&p) else { continue };
                        let mut buf = vec![0u8; HEAD_PROBE_LEN];
                        let n = std::io::Read::read(&mut f, &mut buf)?;
                        if head_hash(&buf[..n]).as_deref() == Some(want) {
                            rep.object_versions_found += 1;
                            if !dry_run {
                                std::fs::remove_file(&p)?;
                                rep.object_versions_deleted += 1;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(rep)
}

fn count_files(p: &Path) -> u64 {
    let mut n = 0;
    let mut stack = vec![p.to_path_buf()];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                if e.path().is_dir() {
                    stack.push(e.path());
                } else {
                    n += 1;
                }
            }
        }
    }
    n
}

/// Replay on every configured store and remove the local index partitions of erased tenants (the live
/// proxy after a store restore, or before serving a restored data directory).
pub async fn replay_all(vault: &Vault, entries: &[Entry], dry_run: bool) -> Result<ReplayReport> {
    let mut total = ReplayReport {
        dry_run,
        ..Default::default()
    };
    for s in vault.stores.values() {
        let r = replay(entries, &ReplayTarget::Store(s.clone()), dry_run).await?;
        total.tenants_erased = r.tenants_erased;
        total.objects_erased = r.objects_erased;
        total.tenant_objects_found += r.tenant_objects_found;
        total.tenant_objects_deleted += r.tenant_objects_deleted;
        total.object_versions_found += r.object_versions_found;
        total.object_versions_deleted += r.object_versions_deleted;
    }
    for e in entries.iter().filter(|e| e.kind == ledger::TENANT_ERASED) {
        let p = vault.tenant_index_path(&e.tenant_id);
        if p.exists() {
            total.index_partitions_removed += 1;
            if !dry_run {
                for suffix in ["", "-wal", "-shm"] {
                    let _ = std::fs::remove_file(format!("{}{suffix}", p.display()));
                }
            }
        }
    }
    Ok(total)
}
