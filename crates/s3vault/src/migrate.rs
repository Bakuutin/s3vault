//! Migration of format v1 objects to format v2 (decision D1): every row of a v1 index is read with the
//! legacy keys, checked against its recorded SHA-256, and written again as a v2 object of its bucket's
//! tenant, keeping the ETag, metadata, Last-Modified, generation and origin. Idempotent: rows already in
//! the tenant index with the same or a newer generation are skipped, so it can run again with
//! `--delete-v1` after the pass checks to remove the v1 objects.

use crate::config::META_BUCKET;
use crate::index::{Index, LIVE, ObjRow};
use crate::spool::spool_stream;
use crate::streams::decrypt_stream;
use crate::vault::{ObjInfo, Vault};
use anyhow::{Context, Result, bail};
use s3vault_format::keyring::Keyring;
use s3vault_format::object::{self, Layout};
use serde::Serialize;
use tracing::{info, warn};

#[derive(Debug, Default, Serialize)]
pub struct MigrateReport {
    pub rows: u64,
    pub migrated_live: u64,
    pub migrated_tombstones: u64,
    pub bytes: u64,
    pub already_v2: u64,
    pub v1_deleted: u64,
    pub sha_mismatch: u64,
    pub errors: u64,
    pub fill_cursors: u64,
    pub open_uploads_dropped: u64,
    pub elapsed_ms: u64,
}

async fn read_v1(vault: &Vault, legacy: &Keyring, store: &crate::remote::Remote, name: &str, r: &ObjRow) -> Result<crate::spool::Spool> {
    let layout = Layout {
        header_sealed_len: r.hlen as u64,
        size: r.size,
    };
    let seal = object::SealInfo {
        kid: r.kid,
        salt: r.salt,
        header_sealed_len: r.hlen,
        ad: r.ad,
    };
    let cipher = object::body_cipher(legacy, &seal)?;
    let u = vault.unlocked()?;
    if r.size == 0 {
        return Ok(spool_stream(Box::pin(futures::stream::empty()), vault.new_spool(&u)).await?);
    }
    let last = layout.n_chunks() - 1;
    let span = layout.ciphertext_span(0, last);
    let (_, ct) = store
        .get_stream(name, Some(span))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let plain = decrypt_stream(ct, cipher, layout, 0, last, 0, r.size);
    Ok(spool_stream(plain, vault.new_spool(&u)).await?)
}

pub async fn migrate_v2(vault: &Vault, legacy: &Keyring, old: &Index, delete_v1: bool) -> Result<MigrateReport> {
    let t0 = std::time::Instant::now();
    let u = vault.unlocked()?;
    let mut rep = MigrateReport::default();
    let name_key = legacy.name_key();
    let mut buckets: Vec<_> = vault.buckets.values().cloned().collect();
    buckets.sort_by(|a, b| a.name.cmp(&b.name));
    for b in &buckets {
        let t = u
            .tenant(&b.tenant)
            .map_err(|e| anyhow::anyhow!("bucket {}: tenant {}: {e}", b.name, b.tenant))?;
        let mut after = String::new();
        loop {
            let rows = old.list(&b.name, "", &after, 500)?;
            let Some(last) = rows.last() else { break };
            after = last.key.clone();
            for r in rows {
                rep.rows += 1;
                let v1_name = format!("{}{}", b.store.prefix, object::store_name(&name_key, &r.bucket, &r.key));
                if t.index.get(&r.bucket, &r.key)?.is_some_and(|x| x.generation >= r.generation) {
                    rep.already_v2 += 1;
                } else {
                    let res: Result<()> = async {
                        let meta = serde_json::from_str(&r.meta).unwrap_or_default();
                        if r.state == LIVE {
                            let spool = read_v1(vault, legacy, &b.store, &v1_name, &r)
                                .await
                                .with_context(|| format!("read v1 {}/{}", r.bucket, r.key))?;
                            if spool.sha256_hex() != r.sha256 || spool.size != r.size {
                                rep.sha_mismatch += 1;
                                bail!("v1 object {}/{} does not match its recorded SHA-256", r.bucket, r.key);
                            }
                            let info = ObjInfo {
                                size: r.size,
                                etag: r.etag.clone(),
                                content_type: r.content_type.clone(),
                                meta,
                                mtime_ms: r.mtime_ms,
                            };
                            vault
                                .write_object(&t, &b.store, &r.bucket, &r.key, spool.stream(), &info, r.sha256.clone(), r.generation, false, r.origin)
                                .await?;
                            rep.migrated_live += 1;
                            rep.bytes += r.size;
                        } else {
                            let info = ObjInfo {
                                size: 0,
                                etag: String::new(),
                                content_type: None,
                                meta,
                                mtime_ms: r.mtime_ms,
                            };
                            vault
                                .write_object(&t, &b.store, &r.bucket, &r.key, Box::pin(futures::stream::empty()), &info, r.sha256.clone(), r.generation, true, r.origin)
                                .await?;
                            rep.migrated_tombstones += 1;
                        }
                        Ok(())
                    }
                    .await;
                    if let Err(e) = res {
                        rep.errors += 1;
                        warn!("migrate: {e:#}");
                        continue;
                    }
                }
                if delete_v1 {
                    b.store.delete(&v1_name).await.map_err(|e| anyhow::anyhow!("delete v1: {e}"))?;
                    rep.v1_deleted += 1;
                }
            }
        }
        let f = old.fill_get(&b.name)?;
        if !f.cursor.is_empty() || f.copied > 0 {
            t.index.fill_put(&f)?;
            rep.fill_cursors += 1;
        }
        rep.open_uploads_dropped += old.list_uploads(&b.name, "", 100_000)?.len() as u64;
    }
    if delete_v1 {
        // the v1 index snapshot object
        let meta_store = vault.stores.values().next().context("store")?;
        let snap = format!("{}{}", meta_store.prefix, object::store_name(&name_key, META_BUCKET, crate::background::SNAPSHOT_KEY));
        let _ = meta_store.delete(&snap).await;
    }
    rep.elapsed_ms = t0.elapsed().as_millis() as u64;
    info!(?rep, "migration to format v2 done");
    Ok(rep)
}
