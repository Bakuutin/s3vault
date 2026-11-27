//! The gateway logic, independent of the S3 wire layer: encrypt on write, decrypt on read, read-through
//! from a fallback with promotion to the store (`promote`), tombstones, merged listings, copy and multipart staging.

use crate::config::{Config, META_BUCKET};
use crate::promote::{PromoteJob, Promoter, Throttle};
use crate::index::{FillRow, Index, LIVE, ObjRow, PartRow, TOMBSTONE, UploadRow};
use crate::remote::{ByteStream, ListItem, Remote, RemoteError};
use crate::spool::{Spool, SpoolWriter, spool_stream};
use crate::streams::{decrypt_stream, encrypt_stream};
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use md5::{Digest as _, Md5};
use rand::RngCore;
use s3vault_format::keyring::Key32;
use s3vault_format::keys2::{Bundle, MasterV2, TenantKeyring, TenantKeys, TenantStatus};
use s3vault_format::ledger::Ledger;
use s3vault_format::object::{self, Header, Layout};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

/// Buffer and authenticate ranged reads up to this size before answering, so an integrity failure becomes
/// a clean 500 instead of a truncated body.
const BUFFERED_READ_MAX: u64 = 8 << 20;
const LOCK_STRIPES: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault is locked: the key service has not delivered the keyring")]
    Locked,
    #[error("upstream unavailable: {0}")]
    Unavailable(String),
    #[error("no such key")]
    NoSuchKey,
    #[error("no such bucket")]
    NoSuchBucket,
    #[error("no such upload")]
    NoSuchUpload,
    #[error("precondition failed")]
    PreconditionFailed,
    #[error("invalid part: {0}")]
    InvalidPart(String),
    #[error("bad digest")]
    BadDigest,
    #[error("invalid range")]
    InvalidRange,
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("integrity failure: {0}")]
    Integrity(String),
    #[error("access denied: {0}")]
    AccessDenied(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub type VResult<T> = std::result::Result<T, VaultError>;

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Internal(e.into())
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Strictly increasing per key, and safe after an index loss: never below the wall clock.
fn next_generation(prev: Option<u64>) -> u64 {
    let now = now_ms().max(1) as u64;
    match prev {
        Some(p) => (p + 1).max(now),
        None => now,
    }
}

fn is_plain_md5(etag: &str) -> bool {
    etag.len() == 32 && etag.bytes().all(|b| b.is_ascii_hexdigit())
}

pub struct BucketRt {
    pub name: String,
    pub store: Arc<Remote>,
    pub fallback: Option<Arc<Remote>>,
    /// Fill and reconcile refuse to run against a retired fallback.
    pub fallback_retired: bool,
    /// The tenant whose key encrypts this bucket.
    pub tenant: String,
}

/// One tenant in the proxy's RAM: its keys and its index partition (`data_dir/tenants/<id>.db`).
pub struct TenantRt {
    pub keys: TenantKeys,
    pub index: Arc<Index>,
    /// A frozen tenant's buckets answer 403 (erasure step 2, restriction of processing).
    pub frozen: AtomicBool,
}

pub struct Unlocked {
    pub master: Arc<MasterV2>,
    /// The small system database: fingerprint, frozen flags.
    pub sys: Arc<Index>,
    /// Temporary spools only (random per process start).
    pub spool_key: Key32,
    tenants: RwLock<HashMap<String, Arc<TenantRt>>>,
    /// Key-service status of every configured tenant: pending, active, erased, missing.
    status: RwLock<HashMap<String, String>>,
    /// The erasure ledger (merged from the key service and the local copy).
    pub ledger: Mutex<Ledger>,
}

impl Unlocked {
    /// The tenant if it is active (served).
    pub fn tenant(&self, name: &str) -> VResult<Arc<TenantRt>> {
        let st = self.tenant_status(name);
        match st.as_str() {
            "active" => {}
            "erased" => return Err(VaultError::AccessDenied("tenant erased".into())),
            "pending" => {
                return Err(VaultError::Unavailable(
                    "tenant pending its escrow confirmation".into(),
                ));
            }
            _ => {
                return Err(VaultError::Unavailable(
                    "tenant not served by the key service".into(),
                ));
            }
        }
        self.tenants
            .read()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| VaultError::Unavailable("tenant not loaded".into()))
    }

    /// A loaded tenant regardless of its status (admin operations).
    pub fn tenant_loaded(&self, name: &str) -> Option<Arc<TenantRt>> {
        self.tenants.read().unwrap().get(name).cloned()
    }

    pub fn tenant_status(&self, name: &str) -> String {
        self.status
            .read()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_else(|| "missing".into())
    }

    pub fn loaded_tenants(&self) -> Vec<Arc<TenantRt>> {
        let mut v: Vec<_> = self.tenants.read().unwrap().values().cloned().collect();
        v.sort_by(|a, b| a.keys.name.cmp(&b.keys.name));
        v
    }

    /// Remove a tenant from RAM (its keys are zeroized when the last reference goes).
    pub fn drop_tenant(&self, name: &str) -> Option<Arc<TenantRt>> {
        self.status
            .write()
            .unwrap()
            .insert(name.to_string(), "erased".into());
        self.tenants.write().unwrap().remove(name)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjInfo {
    pub size: u64,
    pub etag: String,
    pub content_type: Option<String>,
    pub meta: BTreeMap<String, String>,
    pub mtime_ms: i64,
}

impl ObjInfo {
    fn from_row(r: &ObjRow) -> ObjInfo {
        ObjInfo {
            size: r.size,
            etag: r.etag.clone(),
            content_type: r.content_type.clone(),
            meta: serde_json::from_str(&r.meta).unwrap_or_default(),
            mtime_ms: r.mtime_ms,
        }
    }
}

pub struct GetResult {
    pub info: ObjInfo,
    /// Plaintext range served, `[start, end)`, when the request had a Range.
    pub range: Option<(u64, u64)>,
    pub body: ByteStream,
}

#[derive(Debug, Default, Clone)]
pub struct PutOpts {
    pub content_type: Option<String>,
    pub meta: BTreeMap<String, String>,
    pub create_only: bool,
    pub if_match: Option<String>,
    pub content_md5: Option<[u8; 16]>,
}

#[derive(Debug, Clone)]
pub struct ListEntry {
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub mtime_ms: i64,
}

#[derive(Debug, Clone, Default)]
pub struct ListResult {
    pub entries: Vec<ListEntry>,
    pub prefixes: Vec<String>,
    pub truncated: bool,
    /// The last key or common prefix returned (S3 `NextMarker`).
    pub next_marker: Option<String>,
    /// Where the next page starts (exclusive), used as the continuation token.
    pub next_after: Option<String>,
}

pub enum FillOutcome {
    /// Already in the store of record.
    Present(ObjRow),
    Tombstoned,
    /// Fetched from the fallback and written to the store.
    Fetched { info: ObjInfo },
}

/// What [`Vault::store_filled`] did.
pub enum StoreFilled {
    Stored,
    /// A live row exists (a client write, the fill or another promotion): left alone.
    Present,
    /// The key is deleted: never written.
    Tombstoned,
}

struct LiveGuard<'a>(&'a AtomicUsize);

impl<'a> LiveGuard<'a> {
    fn new(c: &'a AtomicUsize) -> Self {
        c.fetch_add(1, Ordering::SeqCst);
        LiveGuard(c)
    }
}

impl Drop for LiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct Vault {
    pub cfg: Config,
    pub buckets: HashMap<String, Arc<BucketRt>>,
    pub stores: BTreeMap<String, Arc<Remote>>,
    state: RwLock<Option<Arc<Unlocked>>>,
    locks: Vec<tokio::sync::Mutex<()>>,
    /// Live read-through fetches in flight; the background fill pauses while this is non-zero.
    pub live_fetches: AtomicUsize,
    pub spool_dir: PathBuf,
    pub staging_dir: PathBuf,
    pub started_ms: i64,
    pub last_unlock_error: RwLock<Option<String>>,
    /// Promote on read (see `promote`).
    pub promoter: Promoter,
    /// Byte budget per bucket with a fallback, shared by its fill and its promotions.
    throttles: HashMap<String, Arc<Throttle>>,
    me: Weak<Vault>,
}

fn map_fallback(label: &str, e: RemoteError) -> VaultError {
    match e {
        RemoteError::NotFound => VaultError::NoSuchKey,
        RemoteError::Unavailable(m) => VaultError::Unavailable(format!("fallback {label}: {m}")),
    }
}

fn map_store(label: &str, e: RemoteError) -> VaultError {
    match e {
        RemoteError::NotFound => VaultError::Integrity(format!(
            "store {label}: object listed in the index is missing"
        )),
        RemoteError::Unavailable(m) => VaultError::Unavailable(format!("store {label}: {m}")),
    }
}

impl Vault {
    pub fn new(cfg: Config) -> anyhow::Result<Arc<Vault>> {
        let mut stores = BTreeMap::new();
        for (name, sc) in &cfg.stores {
            stores.insert(
                name.clone(),
                Arc::new(Remote::from_cfg(&format!("store:{name}"), sc, None)?),
            );
        }
        let mut buckets = HashMap::new();
        for b in &cfg.buckets {
            let fallback = match &b.fallback {
                None => None,
                Some(f) => {
                    let fc = &cfg.fallbacks[&f.source];
                    Some(Arc::new(Remote::from_cfg(
                        &format!("fallback:{}", f.source),
                        fc,
                        Some(&f.bucket),
                    )?))
                }
            };
            buckets.insert(
                b.name.clone(),
                Arc::new(BucketRt {
                    name: b.name.clone(),
                    store: stores[&b.store].clone(),
                    fallback,
                    fallback_retired: b.fallback.as_ref().is_some_and(|f| f.retired),
                    tenant: b.tenant.clone(),
                }),
            );
        }
        let spool_dir = cfg.server.data_dir.join("spool");
        let staging_dir = cfg.server.data_dir.join("staging");
        std::fs::create_dir_all(&spool_dir)?;
        std::fs::create_dir_all(&staging_dir)?;
        // Leftover temp spools from a crash are unreadable without their per-file salt key context; remove.
        if let Ok(rd) = std::fs::read_dir(&spool_dir) {
            for e in rd.flatten() {
                let _ = std::fs::remove_file(e.path());
            }
        }
        let throttles = buckets
            .values()
            .filter(|b| b.fallback.is_some())
            .map(|b| {
                (
                    b.name.clone(),
                    Arc::new(Throttle::new(cfg.fill.rate_bytes_per_sec)),
                )
            })
            .collect();
        Ok(Arc::new_cyclic(|me| Vault {
            cfg,
            buckets,
            stores,
            state: RwLock::new(None),
            locks: (0..LOCK_STRIPES)
                .map(|_| tokio::sync::Mutex::new(()))
                .collect(),
            live_fetches: AtomicUsize::new(0),
            spool_dir,
            staging_dir,
            started_ms: now_ms(),
            last_unlock_error: RwLock::new(None),
            promoter: Promoter::default(),
            throttles,
            me: me.clone(),
        }))
    }

    /// The byte budget of a bucket with a fallback (fill and promotions).
    pub fn fill_throttle(&self, bucket: &str) -> Option<Arc<Throttle>> {
        self.throttles.get(bucket).cloned()
    }

    pub fn tenants_dir(&self) -> PathBuf {
        self.cfg.server.data_dir.join("tenants")
    }

    pub fn tenant_index_path(&self, id_hex: &str) -> PathBuf {
        self.tenants_dir().join(format!("{id_hex}.db"))
    }

    pub fn tenant_staging(&self, t: &TenantRt) -> PathBuf {
        self.staging_dir.join(t.keys.id_hex())
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.cfg.server.data_dir.join("ledger.jsonl")
    }

    /// Merge a ledger received from the key service into the local copy (which survives a key-service
    /// restore from an old backup). Diverging copies are refused.
    fn merge_ledger(&self, local: &mut Ledger, received: &Ledger) -> anyhow::Result<()> {
        if local.merge(received)? {
            let tmp = self.ledger_path().with_extension("jsonl.new");
            std::fs::write(&tmp, local.to_text())?;
            std::fs::rename(&tmp, self.ledger_path())?;
        } else if received.entries.len() < local.entries.len() {
            warn!(
                local = local.entries.len(),
                received = received.entries.len(),
                "the key service's erasure ledger is behind the local copy (restored from a backup?); keeping the local one"
            );
        }
        Ok(())
    }

    /// Install the keys: opens the system database and the index partition of every active configured
    /// tenant, after checking the master root is escrowed and merging the erasure ledger.
    pub fn unlock(&self, bundle: Bundle) -> anyhow::Result<()> {
        let master = Arc::new(bundle.master);
        if !master.is_escrowed() {
            anyhow::bail!(
                "the master root has no confirmed escrow copy: refusing to use it (s3vault-keyd escrow-confirm)"
            );
        }
        let fp = master.fingerprint();
        std::fs::create_dir_all(self.tenants_dir())?;
        let sys = Index::open(
            &self.cfg.server.data_dir.join("system.db"),
            Some(&master.system_db_key()),
        )
        .context("open the system database with this keyring (a different keyring cannot read it)")?;
        match sys.meta_get("keyring_fingerprint")? {
            Some(old) if old != fp => anyhow::bail!("data dir belongs to keyring {old}, got {fp}"),
            Some(_) => {}
            None => sys.meta_set("keyring_fingerprint", &fp)?,
        }
        let mut ledger = match std::fs::read_to_string(self.ledger_path()) {
            Ok(t) => Ledger::parse(&t).context("local erasure ledger")?,
            Err(_) => Ledger::default(),
        };
        self.merge_ledger(&mut ledger, &bundle.ledger)?;
        let mut spool_key = zeroize::Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *spool_key);
        let u = Unlocked {
            master,
            sys: Arc::new(sys),
            spool_key,
            tenants: RwLock::new(HashMap::new()),
            status: RwLock::new(HashMap::new()),
            ledger: Mutex::new(ledger),
        };
        self.load_tenants(&u, &bundle.tenants)?;
        *self.state.write().unwrap() = Some(Arc::new(u));
        info!(fingerprint = %fp, "vault unlocked");
        Ok(())
    }

    /// Re-read the tenant keyring and the ledger from a fresh bundle (new tenants become served once
    /// active; tenants erased at the key service stop being served).
    pub fn refresh(&self, bundle: Bundle) -> anyhow::Result<()> {
        let u = self.unlocked().map_err(|e| anyhow::anyhow!("{e}"))?;
        if bundle.master.fingerprint() != u.master.fingerprint() {
            anyhow::bail!("the key service now serves a different master keyring; restart to switch");
        }
        {
            let mut l = u.ledger.lock().unwrap();
            self.merge_ledger(&mut l, &bundle.ledger)?;
        }
        self.load_tenants(&u, &bundle.tenants)
    }

    fn load_tenants(&self, u: &Unlocked, tk: &TenantKeyring) -> anyhow::Result<()> {
        let erased = u.ledger.lock().unwrap().erased_tenants();
        let mut names: Vec<&String> = self.buckets.values().map(|b| &b.tenant).collect();
        names.sort();
        names.dedup();
        for name in names {
            let status = match tk.tenants.get(name) {
                None => "missing",
                Some(e) if e.status == TenantStatus::Erased => "erased",
                Some(e) if erased.contains(&e.id_hex()) => {
                    error!(tenant = %name, "the key service serves a tenant the erasure ledger lists as erased (restored from an old backup?): refusing it");
                    "erased"
                }
                Some(e) if e.status == TenantStatus::Pending => "pending",
                Some(e) => {
                    let loaded = u.tenants.read().unwrap().get(name).map(|t| t.keys.id);
                    match loaded {
                        Some(id) if id == e.id => {}
                        Some(_) => anyhow::bail!("tenant {name} changed its id; restart to switch"),
                        None => {
                            let keys = u.master.tenant_keys(e)?;
                            let idx = Index::open(
                                &self.tenant_index_path(&keys.id_hex()),
                                Some(&keys.index_key),
                            )
                            .with_context(|| format!("open the index of tenant {name}"))?;
                            match idx.meta_get("tenant_id")? {
                                Some(id) if id != keys.id_hex() => {
                                    anyhow::bail!("index of tenant {name} belongs to another tenant")
                                }
                                Some(_) => {}
                                None => idx.meta_set("tenant_id", &keys.id_hex())?,
                            }
                            let frozen = u.sys.meta_get(&format!("frozen:{}", keys.id_hex()))?
                                == Some("1".into());
                            u.tenants.write().unwrap().insert(
                                name.clone(),
                                Arc::new(TenantRt {
                                    keys,
                                    index: Arc::new(idx),
                                    frozen: AtomicBool::new(frozen),
                                }),
                            );
                        }
                    }
                    "active"
                }
            };
            u.status
                .write()
                .unwrap()
                .insert(name.clone(), status.to_string());
        }
        Ok(())
    }

    /// Freeze or unfreeze a tenant (persisted in the system database).
    pub fn set_frozen(&self, t: &TenantRt, frozen: bool) -> VResult<()> {
        let u = self.unlocked()?;
        u.sys
            .meta_set(&format!("frozen:{}", t.keys.id_hex()), if frozen { "1" } else { "0" })?;
        t.frozen.store(frozen, Ordering::SeqCst);
        Ok(())
    }

    /// The bucket and its tenant, for a client request.
    pub fn tenant_of(&self, u: &Unlocked, bucket: &str) -> VResult<(Arc<BucketRt>, Arc<TenantRt>)> {
        let b = self.bucket(bucket)?;
        let t = u.tenant(&b.tenant)?;
        if t.frozen.load(Ordering::SeqCst) {
            return Err(VaultError::AccessDenied("tenant frozen".into()));
        }
        Ok((b, t))
    }

    pub fn unlocked(&self) -> VResult<Arc<Unlocked>> {
        self.state.read().unwrap().clone().ok_or(VaultError::Locked)
    }

    pub fn is_locked(&self) -> bool {
        self.state.read().unwrap().is_none()
    }

    pub fn bucket(&self, name: &str) -> VResult<Arc<BucketRt>> {
        self.buckets
            .get(name)
            .cloned()
            .ok_or(VaultError::NoSuchBucket)
    }

    async fn lock_key(&self, bucket: &str, key: &str) -> tokio::sync::MutexGuard<'_, ()> {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        (bucket, key).hash(&mut h);
        self.locks[(h.finish() as usize) % LOCK_STRIPES]
            .lock()
            .await
    }

    pub fn store_name(&self, t: &TenantRt, store: &Remote, bucket: &str, key: &str) -> String {
        format!(
            "{}{}",
            store.prefix,
            object::store_name_v2(&t.keys, bucket, key)
        )
    }

    pub(crate) fn new_spool(&self, u: &Unlocked) -> SpoolWriter {
        SpoolWriter::new(
            &self.spool_dir,
            &u.spool_key,
            self.cfg.server.memory_spool_max,
        )
    }

    /// Encrypt `body` (exactly `info.size` bytes) and write it to the store; record it in the index.
    #[allow(clippy::too_many_arguments)]
    pub async fn write_object(
        &self,
        t: &TenantRt,
        store: &Remote,
        bucket: &str,
        key: &str,
        body: ByteStream,
        info: &ObjInfo,
        sha256_hex: String,
        generation: u64,
        tombstone: bool,
        origin: i64,
    ) -> VResult<ObjRow> {
        let header = Header {
            v: 2,
            bucket: bucket.to_string(),
            key: key.to_string(),
            size: info.size,
            etag: info.etag.clone(),
            sha256: sha256_hex.clone(),
            content_type: info.content_type.clone(),
            meta: info.meta.clone(),
            generation,
            mtime_ms: info.mtime_ms,
            tombstone,
        };
        let head = object::seal_head_v2_new(&t.keys, &header)
            .map_err(|e| VaultError::Internal(e.into()))?;
        let layout = Layout {
            header_sealed_len: head.info.header_sealed_len as u64,
            size: info.size,
        };
        let seal = head.info.clone();
        let ct = encrypt_stream(head.prefix, head.body, layout, body);
        let name = self.store_name(t, store, bucket, key);
        self.upload(store, &name, ct, layout.total_len()).await?;
        let row = ObjRow {
            bucket: bucket.to_string(),
            key: key.to_string(),
            state: if tombstone { TOMBSTONE } else { LIVE },
            size: info.size,
            etag: info.etag.clone(),
            sha256: sha256_hex,
            content_type: info.content_type.clone(),
            meta: serde_json::to_string(&info.meta).unwrap_or_else(|_| "{}".into()),
            generation,
            kid: seal.kid,
            salt: seal.salt,
            hlen: seal.header_sealed_len,
            ad: seal.ad,
            mtime_ms: info.mtime_ms,
            origin,
        };
        t.index.upsert(&row)?;
        Ok(row)
    }

    async fn upload(
        &self,
        store: &Remote,
        name: &str,
        mut ct: ByteStream,
        total: u64,
    ) -> VResult<()> {
        // Every request body is held in memory so that a failed attempt can be repeated (review M4):
        // objects up to one part go in one buffered PUT, larger ones as a multipart upload of parts.
        let part_size = self.cfg.server.store_multipart_part.max(5 << 20) as usize;
        if total <= self.cfg.server.store_multipart_threshold.min(part_size as u64) {
            let mut buf = BytesMut::with_capacity(total as usize);
            while let Some(c) = ct.next().await {
                buf.extend_from_slice(&c?);
            }
            return store
                .put_bytes(name, buf.freeze())
                .await
                .map_err(|e| map_store(&store.label, e));
        }
        let upload_id = store
            .mp_create(name)
            .await
            .map_err(|e| map_store(&store.label, e))?;
        let res: VResult<Vec<String>> = async {
            let mut etags = Vec::new();
            let mut buf = BytesMut::new();
            let mut n: u16 = 0;
            loop {
                let next = ct.next().await;
                let eof = next.is_none();
                if let Some(c) = next {
                    buf.extend_from_slice(&c?);
                }
                while buf.len() >= part_size || (eof && !buf.is_empty()) {
                    let take = buf.len().min(part_size);
                    let part = buf.split_to(take).freeze();
                    n = n
                        .checked_add(1)
                        .ok_or_else(|| VaultError::InvalidRequest("object too large".into()))?;
                    etags.push(
                        store
                            .mp_part(name, &upload_id, n, part)
                            .await
                            .map_err(|e| map_store(&store.label, e))?,
                    );
                }
                if eof {
                    return Ok(etags);
                }
            }
        }
        .await;
        match res {
            Ok(etags) => store
                .mp_complete(name, &upload_id, &etags, total)
                .await
                .map_err(|e| map_store(&store.label, e)),
            Err(e) => {
                let _ = store.mp_abort(name, &upload_id).await;
                Err(e)
            }
        }
    }

    // ---------------------------------------------------------------- reads

    pub async fn head(&self, bucket: &str, key: &str) -> VResult<ObjInfo> {
        let u = self.unlocked()?;
        let (b, t) = self.tenant_of(&u, bucket)?;
        match t.index.get(bucket, key)? {
            Some(r) if r.state == TOMBSTONE => Err(VaultError::NoSuchKey),
            Some(r) => Ok(ObjInfo::from_row(&r)),
            None => match &b.fallback {
                None => Err(VaultError::NoSuchKey),
                Some(fb) => {
                    let _live = LiveGuard::new(&self.live_fetches);
                    let m = fb.head(key).await.map_err(|e| map_fallback(&fb.label, e))?;
                    Ok(ObjInfo {
                        size: m.size,
                        etag: m.etag,
                        content_type: m.content_type,
                        meta: m.meta,
                        mtime_ms: m.last_modified_ms.unwrap_or(0),
                    })
                }
            },
        }
    }

    pub async fn get(
        &self,
        bucket: &str,
        key: &str,
        range: Option<s3s::dto::Range>,
    ) -> VResult<GetResult> {
        let u = self.unlocked()?;
        let (b, t) = self.tenant_of(&u, bucket)?;
        let row = match t.index.get(bucket, key)? {
            Some(r) if r.state == TOMBSTONE => return Err(VaultError::NoSuchKey),
            Some(r) => r,
            None => {
                let Some(fb) = &b.fallback else {
                    return Err(VaultError::NoSuchKey);
                };
                // Read through: the whole object (also for a ranged read), verified, into a spool. The
                // client is answered from it at once; the same spool is queued for promotion to the store,
                // which happens in the background with the fill's rules (no fallback transfer twice).
                let (spool, info) = {
                    let _live = LiveGuard::new(&self.live_fetches);
                    self.fetch_fallback(&u, fb, key).await?
                };
                let rng = check_range(range, info.size)?;
                let spool = Arc::new(spool);
                if self.cfg.fill.promote_on_read
                    && let Some(me) = self.me.upgrade()
                {
                    self.promoter.enqueue(
                        me,
                        PromoteJob {
                            bucket: b.name.clone(),
                            key: key.to_string(),
                            spool: spool.clone(),
                            info: info.clone(),
                        },
                    );
                }
                let (s, e) = rng.unwrap_or((0, info.size));
                let body = if info.size == 0 {
                    empty()
                } else {
                    spool.range_stream(s, e)
                };
                // Keep the spool (and its temp file) alive until the body is consumed.
                let body: ByteStream = Box::pin(body.chain(futures::stream::once(async move {
                    drop(spool);
                    Ok(Bytes::new())
                })));
                return Ok(GetResult {
                    info,
                    range: rng,
                    body,
                });
            }
        };
        self.read_stored(&t, &b, &row, range).await
    }

    async fn read_stored(
        &self,
        t: &TenantRt,
        b: &BucketRt,
        row: &ObjRow,
        range: Option<s3s::dto::Range>,
    ) -> VResult<GetResult> {
        let info = ObjInfo::from_row(row);
        let rng = check_range(range, row.size)?;
        if row.size == 0 {
            return Ok(GetResult {
                info,
                range: rng,
                body: empty(),
            });
        }
        let (start, end) = rng.unwrap_or((0, row.size));
        let layout = Layout {
            header_sealed_len: row.hlen as u64,
            size: row.size,
        };
        let (first, last) = layout.chunks_for(start, end);
        let span = layout.ciphertext_span(first, last);
        let seal = object::SealInfo {
            kid: row.kid,
            salt: row.salt,
            header_sealed_len: row.hlen,
            ad: row.ad,
        };
        let cipher = object::body_cipher_v2(&t.keys, &seal);
        let name = self.store_name(t, &b.store, &row.bucket, &row.key);
        let (_, ct) = b
            .store
            .get_stream(&name, Some(span))
            .await
            .map_err(|e| map_store(&b.store.label, e))?;
        let mut body = decrypt_stream(ct, cipher, layout, first, last, start, end);
        if end - start <= BUFFERED_READ_MAX {
            let mut buf = BytesMut::with_capacity((end - start) as usize);
            while let Some(c) = body.next().await {
                match c {
                    Ok(c) => buf.extend_from_slice(&c),
                    Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                        warn!(bucket = %row.bucket, key = %row.key, "integrity: {e}");
                        return Err(VaultError::Integrity(e.to_string()));
                    }
                    Err(e) => {
                        return Err(VaultError::Unavailable(format!(
                            "store {}: {e}",
                            b.store.label
                        )));
                    }
                }
            }
            let bytes = buf.freeze();
            body = Box::pin(futures::stream::once(async move { Ok(bytes) }));
        }
        Ok(GetResult {
            info,
            range: rng,
            body,
        })
    }

    /// Fetch one key from the bucket's fallback and write it to the store of record (under the key lock,
    /// create-only: an existing index row or tombstone always wins). The background fill.
    pub async fn fill_one(
        &self,
        u: &Unlocked,
        t: &TenantRt,
        b: &BucketRt,
        key: &str,
    ) -> VResult<FillOutcome> {
        let fb = b.fallback.as_ref().ok_or(VaultError::NoSuchKey)?;
        let _g = self.lock_key(&b.name, key).await;
        if let Some(r) = t.index.get(&b.name, key)? {
            return Ok(if r.state == TOMBSTONE {
                FillOutcome::Tombstoned
            } else {
                FillOutcome::Present(r)
            });
        }
        let (spool, info) = self.fetch_fallback(u, fb, key).await?;
        self.write_filled(t, b, key, &spool, &info).await?;
        Ok(FillOutcome::Fetched { info })
    }

    /// Read a whole object from the fallback into a spool and check it: the size against the fallback's
    /// answer, and the MD5 against a plain (non-multipart) ETag. Filled objects keep the fallback's ETag and
    /// Last-Modified.
    pub async fn fetch_fallback(
        &self,
        u: &Unlocked,
        fb: &Remote,
        key: &str,
    ) -> VResult<(Spool, ObjInfo)> {
        let (meta, stream) = fb
            .get_stream(key, None)
            .await
            .map_err(|e| map_fallback(&fb.label, e))?;
        let spool = spool_stream(stream, self.new_spool(u)).await.map_err(|e| {
            VaultError::Unavailable(format!("fallback {}: read failed: {e}", fb.label))
        })?;
        if meta.size != spool.size {
            return Err(VaultError::Unavailable(format!(
                "fallback {}: short read ({} of {} bytes)",
                fb.label, spool.size, meta.size
            )));
        }
        if is_plain_md5(&meta.etag) && !meta.etag.eq_ignore_ascii_case(&spool.md5_hex()) {
            return Err(VaultError::Integrity(format!(
                "fallback {}: body does not match its ETag",
                fb.label
            )));
        }
        let info = ObjInfo {
            size: spool.size,
            etag: if meta.etag.is_empty() {
                spool.md5_hex()
            } else {
                meta.etag.clone()
            },
            content_type: meta.content_type.clone(),
            meta: meta.meta.clone(),
            mtime_ms: meta.last_modified_ms.unwrap_or_else(now_ms),
        };
        Ok((spool, info))
    }

    /// Write a verified fallback object (from [`Self::fetch_fallback`]) to the store with the fill's rules:
    /// under the key lock, create-only (a live row from a client write, the fill or another promotion
    /// wins), never over a tombstone; encrypted like every write and recorded in the index (`origin` 1),
    /// so the fill skips it. Promotions use this.
    pub async fn store_filled(
        &self,
        t: &TenantRt,
        b: &BucketRt,
        key: &str,
        spool: &Spool,
        info: &ObjInfo,
    ) -> VResult<StoreFilled> {
        if spool.size != info.size {
            return Err(VaultError::Internal(anyhow::anyhow!(
                "promotion: spool holds {} bytes, expected {}",
                spool.size,
                info.size
            )));
        }
        let _g = self.lock_key(&b.name, key).await;
        match t.index.get(&b.name, key)? {
            Some(r) if r.state == TOMBSTONE => return Ok(StoreFilled::Tombstoned),
            Some(_) => return Ok(StoreFilled::Present),
            None => {}
        }
        self.write_filled(t, b, key, spool, info).await?;
        Ok(StoreFilled::Stored)
    }

    /// The write of a filled object; the caller holds the key lock and checked that no row exists.
    async fn write_filled(
        &self,
        t: &TenantRt,
        b: &BucketRt,
        key: &str,
        spool: &Spool,
        info: &ObjInfo,
    ) -> VResult<ObjRow> {
        self.write_object(
            t,
            &b.store,
            &b.name,
            key,
            spool.stream(),
            info,
            spool.sha256_hex(),
            next_generation(None),
            false,
            1,
        )
        .await
    }

    // ---------------------------------------------------------------- writes

    /// Whether the key currently exists for conditional writes, and its ETag. Consults the fallback when
    /// the index has no row (an unfilled key exists), so create-only stays correct during a transition.
    async fn current_etag(
        &self,
        b: &BucketRt,
        key: &str,
        existing: Option<&ObjRow>,
    ) -> VResult<Option<String>> {
        match existing {
            Some(r) if r.state == LIVE => Ok(Some(r.etag.clone())),
            Some(_) => Ok(None),
            None => match &b.fallback {
                None => Ok(None),
                Some(fb) => match fb.head(key).await {
                    Ok(m) => Ok(Some(m.etag)),
                    Err(RemoteError::NotFound) => Ok(None),
                    Err(e) => Err(map_fallback(&fb.label, e)),
                },
            },
        }
    }

    pub async fn put(
        &self,
        bucket: &str,
        key: &str,
        body: ByteStream,
        o: PutOpts,
    ) -> VResult<ObjInfo> {
        let u = self.unlocked()?;
        let (b, t) = self.tenant_of(&u, bucket)?;
        validate_key(key)?;
        let spool = spool_stream(body, self.new_spool(&u))
            .await
            .map_err(|e| VaultError::InvalidRequest(format!("reading the request body: {e}")))?;
        if let Some(md5) = o.content_md5
            && md5 != spool.md5
        {
            return Err(VaultError::BadDigest);
        }
        let info = ObjInfo {
            size: spool.size,
            etag: spool.md5_hex(),
            content_type: o.content_type,
            meta: o.meta,
            mtime_ms: now_ms(),
        };
        let _g = self.lock_key(bucket, key).await;
        let existing = t.index.get(bucket, key)?;
        if o.create_only || o.if_match.is_some() {
            let cur = self.current_etag(&b, key, existing.as_ref()).await?;
            if o.create_only && cur.is_some() {
                return Err(VaultError::PreconditionFailed);
            }
            if let Some(want) = &o.if_match {
                let ok = match &cur {
                    None => false,
                    Some(e) => want == "*" || want.trim_matches('"') == e,
                };
                if !ok {
                    return Err(VaultError::PreconditionFailed);
                }
            }
        }
        let generation = next_generation(existing.map(|r| r.generation));
        self.write_object(
            &t,
            &b.store,
            bucket,
            key,
            spool.stream(),
            &info,
            spool.sha256_hex(),
            generation,
            false,
            0,
        )
        .await?;
        Ok(info)
    }

    pub async fn delete(&self, bucket: &str, key: &str) -> VResult<()> {
        let u = self.unlocked()?;
        let (b, t) = self.tenant_of(&u, bucket)?;
        let _g = self.lock_key(bucket, key).await;
        let existing = t.index.get(bucket, key)?;
        if b.fallback.is_some() {
            // A tombstone object in the store (and the index): the fallback can never bring the key back,
            // and a rebuild from the store alone keeps it deleted.
            if matches!(&existing, Some(r) if r.state == TOMBSTONE) {
                return Ok(());
            }
            let empty_sha = hex::encode(<Sha256 as sha2::Digest>::digest(b""));
            let info = ObjInfo {
                size: 0,
                etag: String::new(),
                content_type: None,
                meta: BTreeMap::new(),
                mtime_ms: now_ms(),
            };
            let generation = next_generation(existing.map(|r| r.generation));
            self.write_object(
                &t,
                &b.store,
                bucket,
                key,
                empty(),
                &info,
                empty_sha,
                generation,
                true,
                0,
            )
            .await?;
        } else {
            if existing.is_none() {
                return Ok(());
            }
            let name = self.store_name(&t, &b.store, bucket, key);
            b.store
                .delete(&name)
                .await
                .map_err(|e| map_store(&b.store.label, e))?;
            t.index.remove(bucket, key)?;
        }
        Ok(())
    }

    pub async fn copy(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
        replace: Option<(Option<String>, BTreeMap<String, String>)>,
    ) -> VResult<ObjInfo> {
        let u = self.unlocked()?;
        let (b, t) = self.tenant_of(&u, dst_bucket)?;
        validate_key(dst_key)?;
        let src = self.get(src_bucket, src_key, None).await?;
        let spool = spool_stream(src.body, self.new_spool(&u))
            .await
            .map_err(|e| VaultError::Unavailable(format!("reading the copy source: {e}")))?;
        if spool.size != src.info.size {
            return Err(VaultError::Unavailable(
                "copy source changed size while reading".into(),
            ));
        }
        let (content_type, meta) =
            replace.unwrap_or((src.info.content_type.clone(), src.info.meta.clone()));
        let info = ObjInfo {
            size: spool.size,
            etag: spool.md5_hex(),
            content_type,
            meta,
            mtime_ms: now_ms(),
        };
        let _g = self.lock_key(dst_bucket, dst_key).await;
        let existing = t.index.get(dst_bucket, dst_key)?;
        let generation = next_generation(existing.map(|r| r.generation));
        self.write_object(
            &t,
            &b.store,
            dst_bucket,
            dst_key,
            spool.stream(),
            &info,
            spool.sha256_hex(),
            generation,
            false,
            0,
        )
        .await?;
        Ok(info)
    }

    /// Remove a row and its stored object if the row is still exactly `r` (reconcile of stale filled copies).
    pub async fn remove_if_unchanged(
        &self,
        t: &TenantRt,
        b: &BucketRt,
        r: &ObjRow,
    ) -> VResult<bool> {
        let _g = self.lock_key(&b.name, &r.key).await;
        match t.index.get(&b.name, &r.key)? {
            Some(cur) if cur.generation == r.generation && cur.origin == r.origin => {
                let name = self.store_name(t, &b.store, &b.name, &r.key);
                b.store
                    .delete(&name)
                    .await
                    .map_err(|e| map_store(&b.store.label, e))?;
                t.index.remove(&b.name, &r.key)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    // ---------------------------------------------------------------- listing

    pub async fn list(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: Option<&str>,
        after: &str,
        max_keys: usize,
    ) -> VResult<ListResult> {
        let u = self.unlocked()?;
        let (b, t) = self.tenant_of(&u, bucket)?;
        let mut m = Merge::new(&t.index, &b, prefix, after);
        let mut out = ListResult::default();
        let delimiter = delimiter.filter(|d| !d.is_empty());
        let mut count = 0;
        while count < max_keys {
            let Some(e) = m.next().await? else { break };
            if let Some(d) = delimiter
                && let Some(pos) = e.key[prefix.len()..].find(d)
            {
                let cp = e.key[..prefix.len() + pos + d.len()].to_string();
                let skip_to = format!("{cp}{}", char::MAX);
                m.seek(&skip_to);
                out.next_marker = Some(cp.clone());
                out.next_after = Some(skip_to);
                out.prefixes.push(cp);
                count += 1;
                continue;
            }
            out.next_marker = Some(e.key.clone());
            out.next_after = Some(e.key.clone());
            out.entries.push(e);
            count += 1;
        }
        out.truncated = max_keys > 0 && m.next().await?.is_some();
        if !out.truncated {
            out.next_after = None;
        }
        Ok(out)
    }

    // ---------------------------------------------------------------- multipart

    pub fn create_upload(
        &self,
        bucket: &str,
        key: &str,
        content_type: Option<String>,
        meta: BTreeMap<String, String>,
    ) -> VResult<String> {
        let u = self.unlocked()?;
        let (_, t) = self.tenant_of(&u, bucket)?;
        validate_key(key)?;
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        let upload_id = hex::encode(id);
        t.index.insert_upload(&UploadRow {
            upload_id: upload_id.clone(),
            bucket: bucket.to_string(),
            key: key.to_string(),
            content_type,
            meta: serde_json::to_string(&meta).unwrap_or_else(|_| "{}".into()),
            created_ms: now_ms(),
        })?;
        Ok(upload_id)
    }

    fn get_upload(
        &self,
        t: &TenantRt,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> VResult<UploadRow> {
        if !upload_id.bytes().all(|c| c.is_ascii_hexdigit()) || upload_id.len() != 32 {
            return Err(VaultError::NoSuchUpload);
        }
        match t.index.get_upload(upload_id)? {
            Some(up) if up.bucket == bucket && up.key == key => Ok(up),
            _ => Err(VaultError::NoSuchUpload),
        }
    }

    pub async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: ByteStream,
        content_md5: Option<[u8; 16]>,
    ) -> VResult<String> {
        let u = self.unlocked()?;
        let (_, t) = self.tenant_of(&u, bucket)?;
        self.get_upload(&t, bucket, key, upload_id)?;
        if !(1..=10_000).contains(&part_number) {
            return Err(VaultError::InvalidRequest(
                "part number must be 1..10000".into(),
            ));
        }
        let dir = self.tenant_staging(&t).join(upload_id);
        tokio::fs::create_dir_all(&dir).await?;
        let path = dir.join(format!("{part_number:05}"));
        let spool = spool_stream(body, SpoolWriter::persistent(&path, &t.keys.staging_key))
            .await
            .map_err(|e| VaultError::InvalidRequest(format!("reading the part body: {e}")))?;
        if let Some(md5) = content_md5
            && md5 != spool.md5
        {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(VaultError::BadDigest);
        }
        let etag = spool.md5_hex();
        t.index.upsert_part(
            upload_id,
            &PartRow {
                part_number: part_number as i64,
                size: spool.size,
                etag: etag.clone(),
                mtime_ms: now_ms(),
            },
        )?;
        Ok(etag)
    }

    pub fn list_parts(&self, bucket: &str, key: &str, upload_id: &str) -> VResult<Vec<PartRow>> {
        let u = self.unlocked()?;
        let (_, t) = self.tenant_of(&u, bucket)?;
        self.get_upload(&t, bucket, key, upload_id)?;
        Ok(t.index.parts(upload_id)?)
    }

    pub fn list_uploads(
        &self,
        bucket: &str,
        prefix: &str,
        limit: usize,
    ) -> VResult<Vec<UploadRow>> {
        let u = self.unlocked()?;
        let (_, t) = self.tenant_of(&u, bucket)?;
        Ok(t.index.list_uploads(bucket, prefix, limit)?)
    }

    pub async fn complete_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: Vec<(i32, String)>,
    ) -> VResult<ObjInfo> {
        let u = self.unlocked()?;
        let (b, t) = self.tenant_of(&u, bucket)?;
        let up = self.get_upload(&t, bucket, key, upload_id)?;
        if parts.is_empty() {
            return Err(VaultError::InvalidPart("no parts".into()));
        }
        let staged: HashMap<i64, PartRow> = t
            .index
            .parts(upload_id)?
            .into_iter()
            .map(|p| (p.part_number, p))
            .collect();
        let dir = self.tenant_staging(&t).join(upload_id);
        let mut spools = Vec::new();
        let mut md5s = Md5::new();
        let mut prev = 0;
        let mut size = 0u64;
        for (n, etag) in &parts {
            if *n <= prev {
                return Err(VaultError::InvalidPart(
                    "parts must be in ascending order".into(),
                ));
            }
            prev = *n;
            let p = staged
                .get(&(*n as i64))
                .ok_or_else(|| VaultError::InvalidPart(format!("part {n} was not uploaded")))?;
            if p.etag != etag.trim_matches('"') {
                return Err(VaultError::InvalidPart(format!("part {n}: ETag mismatch")));
            }
            md5s.update(hex::decode(&p.etag).unwrap_or_default());
            size += p.size;
            spools.push(Spool::open_file(
                &dir.join(format!("{n:05}")),
                &t.keys.staging_key,
                p.size,
            ));
        }
        // Pre-pass: the header needs the SHA-256 of the whole object before the body.
        let mut sha = <Sha256 as sha2::Digest>::new();
        let mut seen = 0u64;
        for sp in &spools {
            let mut s = sp.stream();
            while let Some(c) = s.next().await {
                let c = c.map_err(|e| {
                    VaultError::Internal(anyhow::anyhow!("staged part unreadable: {e}"))
                })?;
                seen += c.len() as u64;
                sha2::Digest::update(&mut sha, &c);
            }
        }
        if seen != size {
            return Err(VaultError::Internal(anyhow::anyhow!(
                "staged parts have the wrong size"
            )));
        }
        let sha256 = hex::encode(sha2::Digest::finalize(sha));
        let etag = format!("{}-{}", hex::encode(md5s.finalize()), parts.len());
        let info = ObjInfo {
            size,
            etag,
            content_type: up.content_type.clone(),
            meta: serde_json::from_str(&up.meta).unwrap_or_default(),
            mtime_ms: now_ms(),
        };
        let streams: Vec<ByteStream> = spools.iter().map(|s| s.stream()).collect();
        let body: ByteStream = Box::pin(futures::stream::iter(streams).flatten());
        let _g = self.lock_key(bucket, key).await;
        let existing = t.index.get(bucket, key)?;
        let generation = next_generation(existing.map(|r| r.generation));
        self.write_object(
            &t, &b.store, bucket, key, body, &info, sha256, generation, false, 0,
        )
        .await?;
        drop(spools);
        t.index.delete_upload(upload_id)?;
        let _ = tokio::fs::remove_dir_all(&dir).await;
        Ok(info)
    }

    pub async fn abort_upload(&self, bucket: &str, key: &str, upload_id: &str) -> VResult<()> {
        let u = self.unlocked()?;
        let (_, t) = self.tenant_of(&u, bucket)?;
        self.get_upload(&t, bucket, key, upload_id)?;
        t.index.delete_upload(upload_id)?;
        let _ = tokio::fs::remove_dir_all(self.tenant_staging(&t).join(upload_id)).await;
        Ok(())
    }

    /// Abort multipart uploads older than the configured TTL.
    pub async fn expire_uploads(&self) -> VResult<usize> {
        let u = self.unlocked()?;
        let cutoff = now_ms() - (self.cfg.server.upload_ttl_hours as i64) * 3_600_000;
        let mut n = 0;
        for t in u.loaded_tenants() {
            let ids = t.index.expired_uploads(cutoff)?;
            for id in &ids {
                t.index.delete_upload(id)?;
                let _ = tokio::fs::remove_dir_all(self.tenant_staging(&t).join(id)).await;
            }
            n += ids.len();
        }
        Ok(n)
    }

    // ---------------------------------------------------------------- fill state helpers

    pub fn fill_state(&self, bucket: &str) -> VResult<FillRow> {
        let u = self.unlocked()?;
        let b = self.bucket(bucket)?;
        let t = u
            .tenant_loaded(&b.tenant)
            .ok_or_else(|| VaultError::Unavailable("tenant not loaded".into()))?;
        Ok(t.index.fill_get(bucket)?)
    }

    pub fn meta_bucket_name() -> &'static str {
        META_BUCKET
    }

    pub fn wait_live_idle(&self) -> Duration {
        Duration::from_millis(self.cfg.fill.yield_ms.max(10))
    }
}

fn empty() -> ByteStream {
    Box::pin(futures::stream::empty())
}

fn validate_key(key: &str) -> VResult<()> {
    if key.is_empty() || key.len() > 1024 {
        return Err(VaultError::InvalidRequest(
            "object key must be 1..1024 bytes".into(),
        ));
    }
    Ok(())
}

fn check_range(range: Option<s3s::dto::Range>, size: u64) -> VResult<Option<(u64, u64)>> {
    match range {
        None => Ok(None),
        Some(r) => {
            let rr = r.check(size).map_err(|_| VaultError::InvalidRange)?;
            if rr.start >= rr.end {
                return Err(VaultError::InvalidRange);
            }
            Ok(Some((rr.start, rr.end)))
        }
    }
}

/// Merges the index (store of record, incl. tombstones) with the fallback listing, in key order.
struct Merge<'a> {
    index: &'a Index,
    b: &'a BucketRt,
    prefix: String,
    idx_buf: VecDeque<ObjRow>,
    idx_after: String,
    idx_done: bool,
    fb_buf: VecDeque<ListItem>,
    fb_after: String,
    fb_done: bool,
}

const PAGE: usize = 1000;

impl<'a> Merge<'a> {
    fn new(index: &'a Index, b: &'a BucketRt, prefix: &str, after: &str) -> Self {
        Merge {
            index,
            b,
            prefix: prefix.to_string(),
            idx_buf: VecDeque::new(),
            idx_after: after.to_string(),
            idx_done: false,
            fb_buf: VecDeque::new(),
            fb_after: after.to_string(),
            fb_done: b.fallback.is_none(),
        }
    }

    fn seek(&mut self, after: &str) {
        while self
            .idx_buf
            .front()
            .is_some_and(|r| r.key.as_str() <= after)
        {
            self.idx_buf.pop_front();
        }
        if self.idx_buf.is_empty() && self.idx_after.as_str() < after {
            self.idx_after = after.to_string();
        }
        while self.fb_buf.front().is_some_and(|r| r.key.as_str() <= after) {
            self.fb_buf.pop_front();
        }
        if self.fb_buf.is_empty() && self.fb_after.as_str() < after {
            self.fb_after = after.to_string();
        }
    }

    async fn refill(&mut self) -> VResult<()> {
        if self.idx_buf.is_empty() && !self.idx_done {
            let rows = self
                .index
                .list(&self.b.name, &self.prefix, &self.idx_after, PAGE)?;
            if rows.len() < PAGE {
                self.idx_done = true;
            }
            if let Some(l) = rows.last() {
                self.idx_after = l.key.clone();
            }
            self.idx_buf.extend(rows);
        }
        if self.fb_buf.is_empty() && !self.fb_done {
            let fb = self.b.fallback.as_ref().expect("fallback");
            let after = if self.fb_after.as_str() < self.prefix.as_str() {
                String::new()
            } else {
                self.fb_after.clone()
            };
            let sa = (!after.is_empty()).then_some(after.as_str());
            let page = fb
                .list(&self.prefix, sa, None, PAGE)
                .await
                .map_err(|e| map_fallback(&fb.label, e))?;
            if page.next_token.is_none() || page.items.is_empty() {
                self.fb_done = true;
            }
            if let Some(l) = page.items.last() {
                self.fb_after = l.key.clone();
            }
            self.fb_buf
                .extend(page.items.into_iter().filter(|i| i.key > after));
        }
        Ok(())
    }

    async fn next(&mut self) -> VResult<Option<ListEntry>> {
        loop {
            self.refill().await?;
            let ik = self.idx_buf.front().map(|r| r.key.clone());
            let fk = self.fb_buf.front().map(|r| r.key.clone());
            let take_index = match (&ik, &fk) {
                (None, None) => return Ok(None),
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (Some(i), Some(f)) => {
                    if i == f {
                        self.fb_buf.pop_front();
                    }
                    i <= f
                }
            };
            if take_index {
                let r = self.idx_buf.pop_front().unwrap();
                if r.state == TOMBSTONE {
                    continue;
                }
                return Ok(Some(ListEntry {
                    key: r.key,
                    size: r.size,
                    etag: r.etag,
                    mtime_ms: r.mtime_ms,
                }));
            }
            let f = self.fb_buf.pop_front().unwrap();
            return Ok(Some(ListEntry {
                key: f.key,
                size: f.size,
                etag: f.etag,
                mtime_ms: f.last_modified_ms.unwrap_or(0),
            }));
        }
    }
}
