//! The local index (sqlite, encrypted with SQLCipher under a key derived from the keyring).
//!
//! It is a cache: every stored object carries its own encrypted header, so `s3vault rebuild` recreates
//! the index from the store and the keyring alone. Multipart staging state and fill cursors also live here.

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

pub const LIVE: i64 = 1;
pub const TOMBSTONE: i64 = 2;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObjRow {
    pub bucket: String,
    pub key: String,
    pub state: i64,
    pub size: u64,
    pub etag: String,
    pub sha256: String,
    pub content_type: Option<String>,
    /// JSON object of stored metadata.
    pub meta: String,
    pub generation: u64,
    pub kid: u32,
    pub salt: [u8; 32],
    pub hlen: u32,
    pub ad: [u8; 32],
    pub mtime_ms: i64,
    /// 0 = client write, 1 = filled from a fallback, 2 = rebuilt from the store.
    pub origin: i64,
}

#[derive(Debug, Clone)]
pub struct UploadRow {
    pub upload_id: String,
    pub bucket: String,
    pub key: String,
    pub content_type: Option<String>,
    pub meta: String,
    pub created_ms: i64,
}

#[derive(Debug, Clone)]
pub struct PartRow {
    pub part_number: i64,
    pub size: u64,
    pub etag: String,
    pub mtime_ms: i64,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FillRow {
    pub bucket: String,
    pub cursor: String,
    pub copied: u64,
    pub bytes: u64,
    pub skipped: u64,
    pub errors: u64,
    pub finished: bool,
}

pub struct Index {
    conn: Mutex<Connection>,
    /// Bumped on every object change; the snapshot task compares it with the last snapshot.
    pub changes: AtomicU64,
}

const COLS: &str = "bucket, key, state, size, etag, sha256, content_type, meta, generation, kid, salt, hlen, ad, mtime_ms, origin";

fn row_to_obj(r: &rusqlite::Row<'_>) -> rusqlite::Result<ObjRow> {
    let salt: Vec<u8> = r.get(10)?;
    let ad: Vec<u8> = r.get(12)?;
    Ok(ObjRow {
        bucket: r.get(0)?,
        key: r.get(1)?,
        state: r.get(2)?,
        size: r.get::<_, i64>(3)? as u64,
        etag: r.get(4)?,
        sha256: r.get(5)?,
        content_type: r.get(6)?,
        meta: r.get(7)?,
        generation: r.get::<_, i64>(8)? as u64,
        kid: r.get::<_, i64>(9)? as u32,
        salt: salt.try_into().unwrap_or([0; 32]),
        hlen: r.get::<_, i64>(11)? as u32,
        ad: ad.try_into().unwrap_or([0; 32]),
        mtime_ms: r.get(13)?,
        origin: r.get(14)?,
    })
}

/// Upper bound for keys starting with `prefix` (byte order).
fn prefix_end(prefix: &str) -> Option<String> {
    if prefix.is_empty() {
        None
    } else {
        Some(format!("{prefix}{}", char::MAX))
    }
}

pub fn open_connection(path: &Path, key: Option<&[u8; 32]>) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("open index {}", path.display()))?;
    if let Some(k) = key {
        #[cfg(feature = "sqlcipher")]
        {
            let hexkey = zeroize::Zeroizing::new(format!("x'{}'", hex::encode(k)));
            conn.pragma_update(None, "key", hexkey.as_str())?;
        }
        #[cfg(not(feature = "sqlcipher"))]
        let _ = k;
    }
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    // Fails here if the key is wrong.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .context("index database unreadable (wrong key or corrupt)")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    Ok(conn)
}

impl Index {
    pub fn open(path: &Path, key: Option<&[u8; 32]>) -> Result<Index> {
        let conn = open_connection(path, key)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS objects (
                bucket TEXT NOT NULL, key TEXT NOT NULL, state INTEGER NOT NULL, size INTEGER NOT NULL,
                etag TEXT NOT NULL, sha256 TEXT NOT NULL, content_type TEXT, meta TEXT NOT NULL,
                generation INTEGER NOT NULL, kid INTEGER NOT NULL, salt BLOB NOT NULL, hlen INTEGER NOT NULL,
                ad BLOB NOT NULL, mtime_ms INTEGER NOT NULL, origin INTEGER NOT NULL,
                PRIMARY KEY (bucket, key)) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS uploads (
                upload_id TEXT PRIMARY KEY, bucket TEXT NOT NULL, key TEXT NOT NULL, content_type TEXT,
                meta TEXT NOT NULL, created_ms INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS parts (
                upload_id TEXT NOT NULL, part_number INTEGER NOT NULL, size INTEGER NOT NULL, etag TEXT NOT NULL,
                mtime_ms INTEGER NOT NULL, PRIMARY KEY (upload_id, part_number)) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS fill (
                bucket TEXT PRIMARY KEY, cursor TEXT NOT NULL, copied INTEGER NOT NULL, bytes INTEGER NOT NULL,
                skipped INTEGER NOT NULL, errors INTEGER NOT NULL, finished INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);",
        )?;
        Ok(Index {
            conn: Mutex::new(conn),
            changes: AtomicU64::new(1),
        })
    }

    fn c(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn get(&self, bucket: &str, key: &str) -> Result<Option<ObjRow>> {
        let c = self.c();
        let mut st = c.prepare_cached(&format!(
            "SELECT {COLS} FROM objects WHERE bucket = ?1 AND key = ?2"
        ))?;
        Ok(st.query_row(params![bucket, key], row_to_obj).optional()?)
    }

    pub fn upsert(&self, r: &ObjRow) -> Result<()> {
        let c = self.c();
        let mut st = c.prepare_cached(&format!(
            "INSERT OR REPLACE INTO objects ({COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)"
        ))?;
        st.execute(params![
            r.bucket,
            r.key,
            r.state,
            r.size as i64,
            r.etag,
            r.sha256,
            r.content_type,
            r.meta,
            r.generation as i64,
            r.kid as i64,
            &r.salt[..],
            r.hlen as i64,
            &r.ad[..],
            r.mtime_ms,
            r.origin
        ])?;
        self.changes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Insert only if absent or older (used by rebuild).
    pub fn upsert_if_newer(&self, r: &ObjRow) -> Result<bool> {
        if let Some(old) = self.get(&r.bucket, &r.key)?
            && old.generation >= r.generation
        {
            return Ok(false);
        }
        self.upsert(r)?;
        Ok(true)
    }

    pub fn remove(&self, bucket: &str, key: &str) -> Result<()> {
        self.c().execute(
            "DELETE FROM objects WHERE bucket = ?1 AND key = ?2",
            params![bucket, key],
        )?;
        self.changes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Rows (live and tombstones) with `key > after`, starting with `prefix`, in key order.
    pub fn list(
        &self,
        bucket: &str,
        prefix: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<ObjRow>> {
        let c = self.c();
        let lower = if after >= prefix { after } else { prefix };
        let incl = lower == prefix && after < prefix;
        let op = if incl { ">=" } else { ">" };
        let rows = match prefix_end(prefix) {
            Some(end) => {
                let mut st = c.prepare_cached(&format!(
                    "SELECT {COLS} FROM objects WHERE bucket = ?1 AND key {op} ?2 AND key < ?3 ORDER BY key LIMIT ?4"
                ))?;
                st.query_map(params![bucket, lower, end, limit as i64], row_to_obj)?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            }
            None => {
                let mut st = c.prepare_cached(&format!(
                    "SELECT {COLS} FROM objects WHERE bucket = ?1 AND key {op} ?2 ORDER BY key LIMIT ?3"
                ))?;
                st.query_map(params![bucket, lower, limit as i64], row_to_obj)?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            }
        };
        Ok(rows
            .into_iter()
            .filter(|r| r.key.starts_with(prefix))
            .collect())
    }

    /// Rows by origin, for verification (`origin` = 1 for filled objects).
    pub fn sample(&self, bucket: &str, origin: Option<i64>, limit: usize) -> Result<Vec<ObjRow>> {
        let c = self.c();
        let mut st = c.prepare_cached(&format!(
            "SELECT {COLS} FROM objects WHERE bucket = ?1 AND state = 1 AND (?2 IS NULL OR origin = ?2) ORDER BY key LIMIT ?3"
        ))?;
        Ok(st
            .query_map(params![bucket, origin, limit as i64], row_to_obj)?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn counts(&self, bucket: &str) -> Result<(u64, u64, u64)> {
        let c = self.c();
        let (live, tomb, bytes): (i64, i64, i64) = c.query_row(
            "SELECT coalesce(sum(state = 1), 0), coalesce(sum(state = 2), 0), coalesce(sum(CASE WHEN state = 1 THEN size ELSE 0 END), 0)
             FROM objects WHERE bucket = ?1",
            params![bucket],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        Ok((live as u64, tomb as u64, bytes as u64))
    }

    /// One page of all object rows after `(bucket, key)`, in (bucket, key) order (snapshots).
    pub fn page_rows(
        &self,
        after_bucket: &str,
        after_key: &str,
        limit: usize,
    ) -> Result<Vec<ObjRow>> {
        let c = self.c();
        let mut st = c.prepare_cached(&format!(
            "SELECT {COLS} FROM objects WHERE (bucket, key) > (?1, ?2) ORDER BY bucket, key LIMIT ?3"
        ))?;
        Ok(st
            .query_map(params![after_bucket, after_key, limit as i64], row_to_obj)?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // ---- multipart uploads ----

    pub fn insert_upload(&self, u: &UploadRow) -> Result<()> {
        self.c().execute(
            "INSERT INTO uploads (upload_id, bucket, key, content_type, meta, created_ms) VALUES (?1,?2,?3,?4,?5,?6)",
            params![u.upload_id, u.bucket, u.key, u.content_type, u.meta, u.created_ms],
        )?;
        Ok(())
    }

    pub fn get_upload(&self, upload_id: &str) -> Result<Option<UploadRow>> {
        let c = self.c();
        let mut st = c.prepare_cached(
            "SELECT upload_id, bucket, key, content_type, meta, created_ms FROM uploads WHERE upload_id = ?1",
        )?;
        Ok(st
            .query_row(params![upload_id], |r| {
                Ok(UploadRow {
                    upload_id: r.get(0)?,
                    bucket: r.get(1)?,
                    key: r.get(2)?,
                    content_type: r.get(3)?,
                    meta: r.get(4)?,
                    created_ms: r.get(5)?,
                })
            })
            .optional()?)
    }

    pub fn list_uploads(&self, bucket: &str, prefix: &str, limit: usize) -> Result<Vec<UploadRow>> {
        let c = self.c();
        let mut st = c.prepare_cached(
            "SELECT upload_id, bucket, key, content_type, meta, created_ms FROM uploads
             WHERE bucket = ?1 AND substr(key, 1, length(?2)) = ?2 ORDER BY key, created_ms LIMIT ?3",
        )?;
        Ok(st
            .query_map(params![bucket, prefix, limit as i64], |r| {
                Ok(UploadRow {
                    upload_id: r.get(0)?,
                    bucket: r.get(1)?,
                    key: r.get(2)?,
                    content_type: r.get(3)?,
                    meta: r.get(4)?,
                    created_ms: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn expired_uploads(&self, before_ms: i64) -> Result<Vec<String>> {
        let c = self.c();
        let mut st = c.prepare_cached("SELECT upload_id FROM uploads WHERE created_ms < ?1")?;
        Ok(st
            .query_map(params![before_ms], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?)
    }

    pub fn delete_upload(&self, upload_id: &str) -> Result<()> {
        let c = self.c();
        c.execute("DELETE FROM parts WHERE upload_id = ?1", params![upload_id])?;
        c.execute(
            "DELETE FROM uploads WHERE upload_id = ?1",
            params![upload_id],
        )?;
        Ok(())
    }

    pub fn upsert_part(&self, upload_id: &str, p: &PartRow) -> Result<()> {
        self.c().execute(
            "INSERT OR REPLACE INTO parts (upload_id, part_number, size, etag, mtime_ms) VALUES (?1,?2,?3,?4,?5)",
            params![upload_id, p.part_number, p.size as i64, p.etag, p.mtime_ms],
        )?;
        Ok(())
    }

    pub fn parts(&self, upload_id: &str) -> Result<Vec<PartRow>> {
        let c = self.c();
        let mut st = c.prepare_cached(
            "SELECT part_number, size, etag, mtime_ms FROM parts WHERE upload_id = ?1 ORDER BY part_number",
        )?;
        Ok(st
            .query_map(params![upload_id], |r| {
                Ok(PartRow {
                    part_number: r.get(0)?,
                    size: r.get::<_, i64>(1)? as u64,
                    etag: r.get(2)?,
                    mtime_ms: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // ---- fill state ----

    pub fn fill_get(&self, bucket: &str) -> Result<FillRow> {
        let c = self.c();
        let mut st = c.prepare_cached(
            "SELECT cursor, copied, bytes, skipped, errors, finished FROM fill WHERE bucket = ?1",
        )?;
        Ok(st
            .query_row(params![bucket], |r| {
                Ok(FillRow {
                    bucket: bucket.to_string(),
                    cursor: r.get(0)?,
                    copied: r.get::<_, i64>(1)? as u64,
                    bytes: r.get::<_, i64>(2)? as u64,
                    skipped: r.get::<_, i64>(3)? as u64,
                    errors: r.get::<_, i64>(4)? as u64,
                    finished: r.get::<_, i64>(5)? != 0,
                })
            })
            .optional()?
            .unwrap_or(FillRow {
                bucket: bucket.to_string(),
                ..Default::default()
            }))
    }

    pub fn fill_put(&self, f: &FillRow) -> Result<()> {
        self.c().execute(
            "INSERT OR REPLACE INTO fill (bucket, cursor, copied, bytes, skipped, errors, finished) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![f.bucket, f.cursor, f.copied as i64, f.bytes as i64, f.skipped as i64, f.errors as i64, f.finished as i64],
        )?;
        Ok(())
    }

    pub fn meta_get(&self, k: &str) -> Result<Option<String>> {
        Ok(self
            .c()
            .query_row("SELECT v FROM meta WHERE k = ?1", params![k], |r| r.get(0))
            .optional()?)
    }

    pub fn meta_set(&self, k: &str, v: &str) -> Result<()> {
        self.c().execute(
            "INSERT OR REPLACE INTO meta (k, v) VALUES (?1, ?2)",
            params![k, v],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(key: &str, state: i64) -> ObjRow {
        ObjRow {
            bucket: "b".into(),
            key: key.into(),
            state,
            size: 1,
            etag: "e".into(),
            sha256: "s".into(),
            content_type: None,
            meta: "{}".into(),
            generation: 1,
            kid: 1,
            salt: [1; 32],
            hlen: 1040,
            ad: [2; 32],
            mtime_ms: 0,
            origin: 0,
        }
    }

    #[test]
    fn list_prefix_and_after() {
        let d = tempfile::tempdir().unwrap();
        let idx = Index::open(&d.path().join("i.db"), Some(&[5; 32])).unwrap();
        for k in ["a/1", "a/2", "a/3", "b/1", "a"] {
            idx.upsert(&row(k, LIVE)).unwrap();
        }
        let keys = |v: Vec<ObjRow>| v.into_iter().map(|r| r.key).collect::<Vec<_>>();
        assert_eq!(
            keys(idx.list("b", "a/", "", 10).unwrap()),
            ["a/1", "a/2", "a/3"]
        );
        assert_eq!(
            keys(idx.list("b", "a/", "a/1", 10).unwrap()),
            ["a/2", "a/3"]
        );
        assert_eq!(keys(idx.list("b", "", "a/3", 10).unwrap()), ["b/1"]);
        assert_eq!(keys(idx.list("b", "a", "", 2).unwrap()), ["a", "a/1"]);
        drop(idx);
        #[cfg(feature = "sqlcipher")]
        assert!(
            Index::open(&d.path().join("i.db"), Some(&[6; 32])).is_err(),
            "wrong key must fail"
        );
    }
}
