//! Background work: key fetch and unlock, the fill from a fallback, verification, index snapshots,
//! multipart expiry, and the offline rebuild of the index from the store plus the keyring.

use crate::config::{KeySource, KeysCfg, META_BUCKET};
use crate::index::{FillRow, Index, LIVE, ObjRow, TOMBSTONE};
use crate::remote::{ListItem, Remote};
use crate::spool::spool_stream;
use crate::vault::{FillOutcome, ObjInfo, Vault, VaultError, now_ms};
use anyhow::{Context, Result, anyhow, bail};
use futures::StreamExt;
use s3vault_format::keyproto;
use s3vault_format::keyring::Keyring;
use s3vault_format::object::{self, HEAD_PROBE_LEN, Layout};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

pub const SNAPSHOT_KEY: &str = "index/snapshot.jsonl";

// ------------------------------------------------------------------ process hardening and keys

/// No core dumps, not ptrace-able by other users' processes, and all memory locked (never swapped).
pub fn harden_process() {
    unsafe {
        let rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &rl);
        #[cfg(target_os = "linux")]
        {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
                warn!(
                    "mlockall failed ({}); raise LimitMEMLOCK, and keep swap off",
                    std::io::Error::last_os_error()
                );
            } else {
                info!("memory locked (mlockall)");
            }
        }
    }
}

pub fn fetch_keyring(cfg: &KeysCfg) -> Result<Keyring> {
    match cfg.source {
        KeySource::File => {
            let path = cfg.file.as_ref().context("keys.file")?;
            let text = Zeroizing::new(
                std::fs::read_to_string(path)
                    .with_context(|| format!("read {}", path.display()))?,
            );
            Ok(Keyring::parse(&text)?)
        }
        KeySource::Keyd => {
            let addr = cfg.keyd_addr.as_ref().context("keys.keyd_addr")?;
            let psk_path = cfg.psk_file.as_ref().context("keys.psk_file")?;
            let psk_text = Zeroizing::new(
                std::fs::read_to_string(psk_path)
                    .with_context(|| format!("read {}", psk_path.display()))?,
            );
            let psk = keyproto::parse_psk(&psk_text)?;
            let sa = addr
                .to_socket_addrs()?
                .next()
                .context("resolve keyd_addr")?;
            let mut s = TcpStream::connect_timeout(&sa, Duration::from_secs(5))
                .with_context(|| format!("connect {addr}"))?;
            s.set_read_timeout(Some(Duration::from_secs(10)))?;
            s.set_write_timeout(Some(Duration::from_secs(10)))?;
            let text =
                keyproto::client_fetch(&mut s, &psk).map_err(|e| anyhow!("key service: {e}"))?;
            let text = std::str::from_utf8(&text).map_err(|_| anyhow!("keyring is not UTF-8"))?;
            Ok(Keyring::parse(text)?)
        }
    }
}

/// Retry until the keyring arrives and the index opens. Until then every S3 request gets 503.
pub async fn unlock_loop(vault: Arc<Vault>, wake: Arc<Notify>) {
    let mut attempt = 0u32;
    while vault.is_locked() {
        attempt += 1;
        let cfg = vault.cfg.keys.clone();
        let res = tokio::task::spawn_blocking(move || fetch_keyring(&cfg)).await;
        let err = match res {
            Ok(Ok(kr)) => match vault.unlock(kr) {
                Ok(()) => {
                    *vault.last_unlock_error.write().unwrap() = None;
                    return;
                }
                Err(e) => format!("{e:#}"),
            },
            Ok(Err(e)) => format!("{e:#}"),
            Err(e) => e.to_string(),
        };
        if attempt == 1 || attempt % 30 == 0 {
            warn!(attempt, "vault locked: {err}");
        }
        *vault.last_unlock_error.write().unwrap() = Some(err);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(vault.cfg.keys.retry_secs.max(1))) => {}
            _ = wake.notified() => {}
        }
    }
}

// ------------------------------------------------------------------ fill

#[derive(Debug, Clone, Default, Serialize)]
pub struct FillStatus {
    pub bucket: String,
    pub running: bool,
    pub max_objects: Option<u64>,
    pub rate_bytes_per_sec: u64,
    pub concurrency: usize,
    pub started_ms: i64,
    pub elapsed_ms: i64,
    pub session_copied: u64,
    pub session_bytes: u64,
    pub session_skipped: u64,
    pub session_errors: u64,
    pub live_pauses: u64,
    pub last_error: Option<String>,
    pub failed_keys: Vec<String>,
    pub total: FillRow,
}

pub struct FillHandle {
    pub stop: AtomicBool,
    pub status: Mutex<FillStatus>,
}

#[derive(Default)]
pub struct Fills {
    map: Mutex<HashMap<String, Arc<FillHandle>>>,
}

struct RateLimiter {
    rate: f64,
    state: tokio::sync::Mutex<(f64, Instant)>,
}

impl RateLimiter {
    fn new(rate: u64) -> Self {
        RateLimiter {
            rate: rate.max(1) as f64,
            state: tokio::sync::Mutex::new((rate as f64, Instant::now())),
        }
    }
    async fn acquire(&self, n: u64) {
        loop {
            let wait = {
                let mut st = self.state.lock().await;
                let now = Instant::now();
                st.0 = (st.0 + now.duration_since(st.1).as_secs_f64() * self.rate).min(self.rate);
                st.1 = now;
                let need = (n as f64).min(self.rate);
                if st.0 >= need {
                    st.0 -= n as f64;
                    return;
                }
                (need - st.0) / self.rate
            };
            tokio::time::sleep(Duration::from_secs_f64(wait.max(0.01))).await;
        }
    }
}

impl Fills {
    pub fn statuses(&self, vault: &Vault) -> Vec<FillStatus> {
        let map = self.map.lock().unwrap();
        let mut out = Vec::new();
        for (name, b) in &vault.buckets {
            if b.fallback.is_none() {
                continue;
            }
            let mut st = map
                .get(name)
                .map(|h| h.status.lock().unwrap().clone())
                .unwrap_or_else(|| FillStatus {
                    bucket: name.clone(),
                    ..Default::default()
                });
            if st.running {
                st.elapsed_ms = now_ms() - st.started_ms;
            }
            if let Ok(t) = vault.fill_state(name) {
                st.total = t;
            }
            out.push(st);
        }
        out.sort_by(|a, b| a.bucket.cmp(&b.bucket));
        out
    }

    pub fn stop(&self, bucket: &str) -> bool {
        match self.map.lock().unwrap().get(bucket) {
            Some(h) => {
                h.stop.store(true, Ordering::SeqCst);
                true
            }
            None => false,
        }
    }

    /// Start a fill of `bucket` from its fallback. `restart` resets the cursor (a second pass; keys already
    /// in the store are skipped cheaply).
    pub fn start(
        self: &Arc<Self>,
        vault: Arc<Vault>,
        bucket: &str,
        max_objects: Option<u64>,
        rate: u64,
        concurrency: usize,
        restart: bool,
    ) -> std::result::Result<(), String> {
        let u = vault.unlocked().map_err(|e| e.to_string())?;
        let b = vault.bucket(bucket).map_err(|e| e.to_string())?;
        if b.fallback.is_none() {
            return Err(format!("bucket {bucket} has no fallback"));
        }
        let mut map = self.map.lock().unwrap();
        if let Some(h) = map.get(bucket)
            && h.status.lock().unwrap().running
        {
            return Err(format!("fill of {bucket} is already running"));
        }
        if restart {
            let mut row = u.index.fill_get(bucket).map_err(|e| e.to_string())?;
            row.cursor.clear();
            row.finished = false;
            u.index.fill_put(&row).map_err(|e| e.to_string())?;
        }
        let h = Arc::new(FillHandle {
            stop: AtomicBool::new(false),
            status: Mutex::new(FillStatus {
                bucket: bucket.to_string(),
                running: true,
                max_objects,
                rate_bytes_per_sec: rate,
                concurrency,
                started_ms: now_ms(),
                ..Default::default()
            }),
        });
        map.insert(bucket.to_string(), h.clone());
        let bucket = bucket.to_string();
        tokio::spawn(async move {
            let res = run_fill(
                vault.clone(),
                h.clone(),
                &bucket,
                max_objects,
                rate,
                concurrency.max(1),
            )
            .await;
            let mut st = h.status.lock().unwrap();
            st.running = false;
            st.elapsed_ms = now_ms() - st.started_ms;
            if let Err(e) = res {
                error!(bucket = %bucket, "fill stopped: {e:#}");
                st.last_error = Some(format!("{e:#}"));
            }
            info!(bucket = %bucket, copied = st.session_copied, bytes = st.session_bytes, skipped = st.session_skipped,
                  errors = st.session_errors, elapsed_ms = st.elapsed_ms, "fill session ended");
        });
        Ok(())
    }
}

enum ItemResult {
    Copied(u64),
    Skipped,
    Stopped,
    Failed(String, String),
}

async fn run_fill(
    vault: Arc<Vault>,
    h: Arc<FillHandle>,
    bucket: &str,
    max_objects: Option<u64>,
    rate: u64,
    concurrency: usize,
) -> Result<()> {
    let u = vault.unlocked()?;
    let b = vault.bucket(bucket)?;
    let fb = b.fallback.clone().context("no fallback")?;
    let limiter = RateLimiter::new(rate);
    let mut row = u.index.fill_get(bucket)?;
    let mut session: u64 = 0;
    info!(bucket, cursor = %row.cursor, ?max_objects, rate, concurrency, "fill started");
    while !h.stop.load(Ordering::SeqCst) {
        let page = match fb
            .list(
                "",
                (!row.cursor.is_empty()).then_some(row.cursor.as_str()),
                None,
                1000,
            )
            .await
        {
            Ok(p) => p,
            Err(e) => {
                h.status.lock().unwrap().last_error = Some(format!("list: {e}"));
                warn!(
                    bucket,
                    "fill: listing the fallback failed: {e}; retrying in 30 s"
                );
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
        };
        if page.items.is_empty() {
            row.finished = true;
            u.index.fill_put(&row)?;
            break;
        }
        let mut items: Vec<ListItem> = page.items;
        let page_complete = page.next_token.is_none();
        let mut capped = false;
        if let Some(m) = max_objects {
            let left = m.saturating_sub(session) as usize;
            if items.len() > left {
                items.truncate(left);
                capped = true;
            }
        }
        let last_key = items.last().map(|i| i.key.clone());
        let results: Vec<ItemResult> = futures::stream::iter(items.into_iter())
            .map(|it| {
                let vault = vault.clone();
                let u = u.clone();
                let b = b.clone();
                let h = h.clone();
                let limiter = &limiter;
                async move {
                    let mut paused = false;
                    while vault.live_fetches.load(Ordering::SeqCst) > 0
                        && !h.stop.load(Ordering::SeqCst)
                    {
                        paused = true;
                        tokio::time::sleep(vault.wait_live_idle()).await;
                    }
                    if paused {
                        h.status.lock().unwrap().live_pauses += 1;
                    }
                    if h.stop.load(Ordering::SeqCst) {
                        return ItemResult::Stopped;
                    }
                    match u.index.get(&b.name, &it.key) {
                        Ok(Some(_)) => {
                            h.status.lock().unwrap().session_skipped += 1;
                            return ItemResult::Skipped;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            h.status.lock().unwrap().session_errors += 1;
                            return ItemResult::Failed(it.key, e.to_string());
                        }
                    }
                    limiter.acquire(it.size).await;
                    let r = match vault.fill_one(&u, &b, &it.key, false).await {
                        Ok(FillOutcome::Fetched { info, .. }) => ItemResult::Copied(info.size),
                        Ok(_) | Err(VaultError::NoSuchKey) => ItemResult::Skipped,
                        Err(e) => ItemResult::Failed(it.key, e.to_string()),
                    };
                    // live progress
                    let mut st = h.status.lock().unwrap();
                    match &r {
                        ItemResult::Copied(n) => {
                            st.session_copied += 1;
                            st.session_bytes += n;
                        }
                        ItemResult::Skipped => st.session_skipped += 1,
                        ItemResult::Failed(..) => st.session_errors += 1,
                        ItemResult::Stopped => {}
                    }
                    r
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;
        let mut stopped = false;
        {
            let mut st = h.status.lock().unwrap();
            for r in results {
                match r {
                    ItemResult::Copied(n) => {
                        row.copied += 1;
                        row.bytes += n;
                        session += 1;
                    }
                    ItemResult::Skipped => {
                        row.skipped += 1;
                        session += 1;
                    }
                    ItemResult::Stopped => stopped = true,
                    ItemResult::Failed(k, e) => {
                        row.errors += 1;
                        session += 1;
                        warn!(bucket, "fill: {e}");
                        st.last_error = Some(e);
                        if st.failed_keys.len() < 100 {
                            st.failed_keys.push(k);
                        }
                    }
                }
            }
        }
        if stopped {
            // Keep the cursor at the page start; a restart skips what was copied.
            u.index.fill_put(&row)?;
            break;
        }
        if let Some(k) = last_key {
            row.cursor = k;
        }
        if page_complete && !capped {
            row.finished = true;
        }
        u.index.fill_put(&row)?;
        if capped || row.finished || max_objects.is_some_and(|m| session >= m) {
            break;
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ verify

#[derive(Debug, Default, Serialize)]
pub struct VerifyReport {
    pub checked: u64,
    pub ok: u64,
    pub bytes: u64,
    pub store_mismatch: u64,
    pub fallback_mismatch: u64,
    pub fallback_missing: u64,
    pub errors: u64,
    pub elapsed_ms: u64,
    pub failures: Vec<String>,
}

/// Read up to `max` objects back through the store path (decrypt, compare the SHA-256 recorded at write
/// time) and, if asked, compare each with the fallback's copy byte for byte (via SHA-256).
pub async fn verify(
    vault: Arc<Vault>,
    bucket: &str,
    max: usize,
    origin: Option<i64>,
    against_fallback: bool,
) -> Result<VerifyReport> {
    let u = vault.unlocked()?;
    let b = vault.bucket(bucket)?;
    let rows = u.index.sample(bucket, origin, max)?;
    let t0 = Instant::now();
    let rep = Arc::new(Mutex::new(VerifyReport::default()));
    futures::stream::iter(rows)
        .for_each_concurrent(4, |r| {
            let vault = vault.clone();
            let b = b.clone();
            let rep = rep.clone();
            async move {
                let fail = |kind: &str, rep: &Mutex<VerifyReport>| {
                    let mut g = rep.lock().unwrap();
                    if g.failures.len() < 50 {
                        g.failures.push(format!("{kind}: {}", r.key));
                    }
                };
                let res = async {
                    let got = vault.get(bucket, &r.key, None).await?;
                    let mut s = got.body;
                    let mut h = Sha256::new();
                    let mut n = 0u64;
                    while let Some(c) = s.next().await {
                        let c = c?;
                        n += c.len() as u64;
                        h.update(&c);
                    }
                    Ok::<_, VaultError>((hex::encode(h.finalize()), n))
                }
                .await;
                let (sha, n) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        rep.lock().unwrap().errors += 1;
                        fail(&format!("read error {e}"), &rep);
                        return;
                    }
                };
                {
                    let mut g = rep.lock().unwrap();
                    g.checked += 1;
                    g.bytes += n;
                }
                if sha != r.sha256 || n != r.size {
                    rep.lock().unwrap().store_mismatch += 1;
                    fail("store mismatch", &rep);
                    return;
                }
                if against_fallback && let Some(fb) = &b.fallback {
                    match fb.get_bytes(&r.key, None).await {
                        Ok((_, bytes)) => {
                            if hex::encode(Sha256::digest(&bytes)) != sha {
                                rep.lock().unwrap().fallback_mismatch += 1;
                                fail("fallback mismatch", &rep);
                                return;
                            }
                        }
                        Err(crate::remote::RemoteError::NotFound) => {
                            rep.lock().unwrap().fallback_missing += 1;
                        }
                        Err(e) => {
                            rep.lock().unwrap().errors += 1;
                            fail(&format!("fallback error {e}"), &rep);
                            return;
                        }
                    }
                }
                rep.lock().unwrap().ok += 1;
            }
        })
        .await;
    let mut out = Arc::try_unwrap(rep)
        .map_err(|_| anyhow!("verify still running"))?
        .into_inner()
        .unwrap();
    out.elapsed_ms = t0.elapsed().as_millis() as u64;
    Ok(out)
}

// ------------------------------------------------------------------ reconcile

#[derive(Debug, Default, Serialize)]
pub struct ReconcileReport {
    pub checked: u64,
    pub gone_in_fallback: u64,
    pub changed_in_fallback: u64,
    pub removed: u64,
    pub dry_run: bool,
    pub elapsed_ms: u64,
    pub examples: Vec<String>,
}

/// Drop filled copies that went stale because the fallback changed after the fill (key deleted there, or
/// overwritten with another ETag). Only rows that came from the fallback (`origin` = 1) are considered; client
/// writes and tombstones are never touched. A removed row makes the next read or fill fetch the current
/// fallback object again (or 404 if it is gone). Walks the index and the fallback listing in key order.
pub async fn reconcile(vault: Arc<Vault>, bucket: &str, dry_run: bool) -> Result<ReconcileReport> {
    let u = vault.unlocked()?;
    let b = vault.bucket(bucket)?;
    let fb = b.fallback.clone().context("bucket has no fallback")?;
    let t0 = Instant::now();
    let mut rep = ReconcileReport {
        dry_run,
        ..Default::default()
    };
    let mut after = String::new();
    let mut fb_buf: std::collections::VecDeque<ListItem> = Default::default();
    let mut fb_after = String::new();
    let mut fb_done = false;
    loop {
        let rows = u.index.list(bucket, "", &after, 1000)?;
        let Some(last) = rows.last() else { break };
        let next_after = last.key.clone();
        for r in rows
            .into_iter()
            .filter(|r| r.origin == 1 && r.state == LIVE)
        {
            rep.checked += 1;
            let mut pages = 0;
            let fallback_etag: Option<String> = loop {
                while fb_buf.front().is_some_and(|i| i.key < r.key) {
                    fb_buf.pop_front();
                }
                if let Some(f) = fb_buf.front() {
                    break (f.key == r.key).then(|| f.etag.clone());
                }
                if fb_done {
                    break None;
                }
                if pages >= 3 {
                    // A long gap in the listing: ask for this key directly and jump past it.
                    let e = match fb.head(&r.key).await {
                        Ok(m) => Some(m.etag),
                        Err(crate::remote::RemoteError::NotFound) => None,
                        Err(e) => bail!("fallback: {e}"),
                    };
                    fb_after = r.key.clone();
                    fb_done = false;
                    break e;
                }
                let sa = if fb_after.is_empty() {
                    None
                } else {
                    Some(fb_after.as_str())
                };
                let page = fb
                    .list("", sa, None, 1000)
                    .await
                    .map_err(|e| anyhow!("fallback list: {e}"))?;
                pages += 1;
                fb_done = page.next_token.is_none() || page.items.is_empty();
                if let Some(l) = page.items.last() {
                    fb_after = l.key.clone();
                }
                if page.items.is_empty() {
                    fb_after = fb_after.max(r.key.clone());
                }
                fb_buf.extend(page.items);
            };
            // Some servers omit ETags in listings: ask for it.
            let fallback_etag = match fallback_etag {
                Some(e) if e.is_empty() => match fb.head(&r.key).await {
                    Ok(m) => Some(m.etag),
                    Err(crate::remote::RemoteError::NotFound) => None,
                    Err(e) => bail!("fallback: {e}"),
                },
                other => other,
            };
            let stale = match &fallback_etag {
                None => {
                    rep.gone_in_fallback += 1;
                    true
                }
                Some(e) if !e.is_empty() && *e != r.etag => {
                    rep.changed_in_fallback += 1;
                    true
                }
                Some(_) => false,
            };
            if !stale {
                continue;
            }
            if rep.examples.len() < 20 {
                rep.examples.push(r.key.clone());
            }
            if !dry_run && vault.remove_if_unchanged(&u, &b, &r).await? {
                rep.removed += 1;
            }
        }
        after = next_after;
    }
    rep.elapsed_ms = t0.elapsed().as_millis() as u64;
    info!(bucket, ?rep, "reconcile done");
    Ok(rep)
}

// ------------------------------------------------------------------ snapshots

#[derive(Debug, Serialize)]
pub struct SnapshotReport {
    pub rows: u64,
    pub plaintext_bytes: u64,
    pub elapsed_ms: u64,
}

/// Write the whole index (JSON lines, one object row each) as an encrypted object in the meta store.
pub async fn snapshot(vault: &Vault) -> Result<SnapshotReport> {
    let u = vault.unlocked()?;
    let store = vault.stores[vault.cfg.meta_store()].clone();
    let t0 = Instant::now();
    let started = now_ms();
    let mut w = vault.new_spool(&u);
    let (mut ab, mut ak) = (String::new(), String::new());
    let mut rows = 0u64;
    loop {
        let page = u.index.page_rows(&ab, &ak, 5000)?;
        let Some(last) = page.last() else { break };
        (ab, ak) = (last.bucket.clone(), last.key.clone());
        let mut buf = Vec::with_capacity(page.len() * 400);
        for r in page.iter().filter(|r| r.bucket != META_BUCKET) {
            serde_json::to_writer(&mut buf, r)?;
            buf.push(b'\n');
            rows += 1;
        }
        w.write(&buf).await?;
    }
    let spool = w.finish().await?;
    let info = ObjInfo {
        size: spool.size,
        etag: spool.md5_hex(),
        content_type: Some("application/x-ndjson".into()),
        meta: Default::default(),
        mtime_ms: started,
    };
    let prev = u
        .index
        .get(META_BUCKET, SNAPSHOT_KEY)?
        .map(|r| r.generation);
    let generation = prev.map(|g| g + 1).unwrap_or(1).max(started as u64);
    vault
        .write_object(
            &u,
            &store,
            META_BUCKET,
            SNAPSHOT_KEY,
            spool.stream(),
            &info,
            spool.sha256_hex(),
            generation,
            false,
            3,
        )
        .await?;
    let rep = SnapshotReport {
        rows,
        plaintext_bytes: spool.size,
        elapsed_ms: t0.elapsed().as_millis() as u64,
    };
    info!(rows, bytes = spool.size, "index snapshot written");
    Ok(rep)
}

/// Periodic snapshots (when the index changed) and multipart expiry.
pub async fn maintenance_loop(vault: Arc<Vault>) {
    let mut last_changes = 0u64;
    let mut last_snapshot = Instant::now();
    let mut last_expiry = Instant::now() - Duration::from_secs(3600);
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let Ok(u) = vault.unlocked() else { continue };
        if last_expiry.elapsed() >= Duration::from_secs(3600) {
            last_expiry = Instant::now();
            match vault.expire_uploads().await {
                Ok(n) if n > 0 => info!(n, "expired stale multipart uploads"),
                Ok(_) => {}
                Err(e) => warn!("multipart expiry: {e}"),
            }
        }
        let secs = vault.cfg.server.index_snapshot_secs;
        if secs == 0 {
            continue;
        }
        let changes = u.index.changes.load(Ordering::Relaxed);
        if changes != last_changes
            && (last_changes == 0 || last_snapshot.elapsed() >= Duration::from_secs(secs))
        {
            // The first pass after start only records the baseline.
            if last_changes != 0 {
                match snapshot(&vault).await {
                    Ok(_) => last_snapshot = Instant::now(),
                    Err(e) => warn!("index snapshot failed: {e:#}"),
                }
            }
            last_changes = u.index.changes.load(Ordering::Relaxed);
        }
    }
}

// ------------------------------------------------------------------ rebuild

#[derive(Debug, Default, Serialize)]
pub struct RebuildReport {
    pub snapshot_rows: u64,
    pub listed: u64,
    pub headers_read: u64,
    pub live: u64,
    pub tombstones: u64,
    pub removed_stale: u64,
    pub foreign_or_bad: u64,
    pub errors: u64,
    pub elapsed_ms: u64,
}

async fn read_header(
    store: &Remote,
    kr: &Keyring,
    name: &str,
) -> Result<(object::Header, object::SealInfo)> {
    let (_, b) = store
        .get_bytes(name, Some((0, HEAD_PROBE_LEN as u64 - 1)))
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let need = object::needed_head_len(&b)?;
    let b = if b.len() < need {
        store
            .get_bytes(name, Some((0, need as u64 - 1)))
            .await
            .map_err(|e| anyhow!("{e}"))?
            .1
    } else {
        b
    };
    Ok(object::open_head(kr, &b)?)
}

fn row_from_header(h: &object::Header, s: &object::SealInfo) -> ObjRow {
    ObjRow {
        bucket: h.bucket.clone(),
        key: h.key.clone(),
        state: if h.tombstone { TOMBSTONE } else { LIVE },
        size: h.size,
        etag: h.etag.clone(),
        sha256: h.sha256.clone(),
        content_type: h.content_type.clone(),
        meta: serde_json::to_string(&h.meta).unwrap_or_else(|_| "{}".into()),
        generation: h.generation,
        kid: s.kid,
        salt: s.salt,
        hlen: s.header_sealed_len,
        ad: s.ad,
        mtime_ms: h.mtime_ms,
        origin: 2,
    }
}

/// Load the latest index snapshot from the meta store into `index`. Returns (rows, snapshot time).
async fn load_snapshot(vault: &Vault, kr: &Keyring, index: &Index) -> Result<Option<(u64, i64)>> {
    let store = vault.stores[vault.cfg.meta_store()].clone();
    let name = format!(
        "{}{}",
        store.prefix,
        object::store_name(&kr.name_key(), META_BUCKET, SNAPSHOT_KEY)
    );
    let (_, ct) = match store.get_bytes(&name, None).await {
        Ok(v) => v,
        Err(crate::remote::RemoteError::NotFound) => return Ok(None),
        Err(e) => bail!("snapshot: {e}"),
    };
    let (h, seal) = object::open_head(kr, &ct)?;
    let layout = Layout {
        header_sealed_len: seal.header_sealed_len as u64,
        size: h.size,
    };
    let cipher = object::body_cipher(kr, &seal)?;
    let last = layout.n_chunks() - 1;
    let (s, e) = layout.ciphertext_span(0, last);
    let body = object::open_range(
        &cipher,
        &layout,
        0,
        last,
        &ct[s as usize..=e as usize],
        0,
        h.size,
    )?;
    let mut n = 0;
    for line in body.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let r: ObjRow = serde_json::from_slice(line)?;
        index.upsert_if_newer(&r)?;
        n += 1;
    }
    Ok(Some((n, h.mtime_ms)))
}

/// Rebuild the index from the store(s) and the keyring alone (every object's encrypted header names its
/// bucket, key, generation and tombstone state). With `use_snapshot`, start from the latest snapshot and
/// read only the headers of objects written since (by the store's Last-Modified) or unknown to it.
pub async fn rebuild(
    vault: Arc<Vault>,
    kr: &Keyring,
    index: &Index,
    use_snapshot: bool,
    concurrency: usize,
) -> Result<RebuildReport> {
    let t0 = Instant::now();
    let mut rep = RebuildReport::default();
    let name_key = kr.name_key();
    let mut snapshot_ms = None;
    // store name -> (bucket, key) for rows that came from the snapshot
    let mut known: HashMap<String, (String, String)> = HashMap::new();
    if use_snapshot {
        if let Some((n, t)) = load_snapshot(&vault, kr, index).await? {
            rep.snapshot_rows = n;
            snapshot_ms = Some(t);
            let (mut ab, mut ak) = (String::new(), String::new());
            loop {
                let page = index.page_rows(&ab, &ak, 5000)?;
                let Some(last) = page.last() else { break };
                (ab, ak) = (last.bucket.clone(), last.key.clone());
                for r in &page {
                    if let Some(b) = vault.buckets.get(&r.bucket) {
                        let name = format!(
                            "{}{}",
                            b.store.prefix,
                            object::store_name(&name_key, &r.bucket, &r.key)
                        );
                        known.insert(name, (r.bucket.clone(), r.key.clone()));
                    }
                }
            }
            info!(rows = n, "snapshot loaded; reading headers written since");
        } else {
            info!("no snapshot found; full header scan");
        }
    }
    let mut seen: HashSet<String> = HashSet::new();
    let mut done_stores = HashSet::new();
    for b in vault.buckets.values() {
        if !done_stores.insert(b.store.label.clone()) {
            continue;
        }
        let store = b.store.clone();
        let mut token: Option<String> = None;
        loop {
            let page = store
                .list(&store.prefix, None, token.as_deref(), 1000)
                .await
                .map_err(|e| anyhow!("list: {e}"))?;
            rep.listed += page.items.len() as u64;
            let todo: Vec<ListItem> = page
                .items
                .into_iter()
                .filter(|it| {
                    seen.insert(it.key.clone());
                    match snapshot_ms {
                        None => true,
                        Some(t) => {
                            !known.contains_key(&it.key)
                                || it.last_modified_ms.is_none_or(|lm| lm >= t - 3_600_000)
                        }
                    }
                })
                .collect();
            let results: Vec<Result<Option<ObjRow>>> = futures::stream::iter(todo)
                .map(|it| {
                    let store = store.clone();
                    let name_key = &name_key;
                    async move {
                        let (h, s) = read_header(&store, kr, &it.key).await.with_context(|| it.key.clone())?;
                        if h.bucket == META_BUCKET {
                            return Ok(None);
                        }
                        let expect = format!("{}{}", store.prefix, object::store_name(name_key, &h.bucket, &h.key));
                        if expect != it.key {
                            warn!(name = %it.key, "object header does not match its name (misplaced or foreign)");
                            return Err(anyhow!("misplaced object {}", it.key));
                        }
                        Ok(Some(row_from_header(&h, &s)))
                    }
                })
                .buffer_unordered(concurrency.max(1))
                .collect()
                .await;
            for r in results {
                match r {
                    Ok(Some(row)) => {
                        rep.headers_read += 1;
                        if row.state == LIVE {
                            rep.live += 1;
                        } else {
                            rep.tombstones += 1;
                        }
                        index.upsert_if_newer(&row)?;
                    }
                    Ok(None) => rep.headers_read += 1,
                    Err(e) => {
                        rep.errors += 1;
                        if e.to_string().contains("misplaced") {
                            rep.foreign_or_bad += 1;
                        }
                        warn!("rebuild: {e:#}");
                    }
                }
            }
            if rep.listed % 100_000 < 1000 {
                info!(
                    listed = rep.listed,
                    headers = rep.headers_read,
                    "rebuild progress"
                );
            }
            token = page.next_token;
            if token.is_none() {
                break;
            }
        }
    }
    for (name, (bucket, key)) in &known {
        if !seen.contains(name) {
            index.remove(bucket, key)?;
            rep.removed_stale += 1;
        }
    }
    rep.elapsed_ms = t0.elapsed().as_millis() as u64;
    Ok(rep)
}

/// Spool helper for tests and tools.
pub async fn read_all(
    vault: &Vault,
    bucket: &str,
    key: &str,
) -> std::result::Result<Vec<u8>, VaultError> {
    let u = vault.unlocked()?;
    let r = vault.get(bucket, key, None).await?;
    let sp = spool_stream(r.body, vault.new_spool(&u)).await?;
    let mut out = Vec::with_capacity(sp.size as usize);
    let mut s = sp.stream();
    while let Some(c) = s.next().await {
        out.extend_from_slice(&c?);
    }
    Ok(out)
}
