//! Configuration (TOML). Secrets live in separate mode-600 files referenced from here, never inline.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerCfg,
    pub keys: KeysCfg,
    /// Stores of record: where the ciphertext lives (B2, Garage, MinIO, ...).
    pub stores: BTreeMap<String, RemoteCfg>,
    /// Read-through sources for keys not yet in the store of record (plain, read-only).
    #[serde(default)]
    pub fallbacks: BTreeMap<String, RemoteCfg>,
    pub buckets: Vec<BucketCfg>,
    #[serde(default)]
    pub clients: Vec<ClientCfg>,
    #[serde(default)]
    pub fill: FillCfg,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ServerCfg {
    /// S3 listeners. Bind only private addresses (loopback, Tailscale); the proxy has no rate limiting.
    pub listen: Vec<String>,
    /// Admin HTTP listener (status, fill, verify, snapshot). Must be a loopback address.
    #[serde(default)]
    pub admin_listen: Option<String>,
    /// File with the admin bearer token (one line, mode 640). Required with `admin_listen`: every admin
    /// call must send `Authorization: Bearer <token>`.
    #[serde(default)]
    pub admin_token_file: Option<PathBuf>,
    pub data_dir: PathBuf,
    #[serde(default = "default_region")]
    pub region: String,
    /// Upload bodies up to this size are buffered in RAM; larger ones spool to encrypted local files.
    #[serde(default = "default_mem_spool")]
    pub memory_spool_max: usize,
    /// Objects whose ciphertext exceeds this (or `store_multipart_part`, whichever is smaller) go to the
    /// store with a multipart upload. Every request body is buffered, so failed requests can be retried.
    #[serde(default = "default_mp_threshold")]
    pub store_multipart_threshold: u64,
    #[serde(default = "default_mp_part")]
    pub store_multipart_part: u64,
    /// Encrypted index snapshot to the first store every N seconds when the index changed (0 = off).
    #[serde(default = "default_snapshot_secs")]
    pub index_snapshot_secs: u64,
    /// Multipart uploads not completed after this many hours are aborted.
    #[serde(default = "default_upload_ttl")]
    pub upload_ttl_hours: u64,
}

fn default_region() -> String {
    "us-east-1".into()
}
fn default_mem_spool() -> usize {
    16 << 20
}
fn default_mp_threshold() -> u64 {
    512 << 20
}
fn default_mp_part() -> u64 {
    64 << 20
}
fn default_snapshot_secs() -> u64 {
    6 * 3600
}
fn default_upload_ttl() -> u64 {
    7 * 24
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
pub enum KeySource {
    /// Fetch the keyring from s3vault-keyd at start (held in RAM only).
    Keyd,
    /// Read the keyring from a local file (tests, disaster recovery on an owner machine).
    File,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct KeysCfg {
    pub source: KeySource,
    #[serde(default)]
    pub keyd_addr: Option<String>,
    #[serde(default)]
    pub psk_file: Option<PathBuf>,
    /// `source = "file"`: the master keyring (v2).
    #[serde(default)]
    pub file: Option<PathBuf>,
    /// `source = "file"`: the tenant keyring.
    #[serde(default)]
    pub tenants_file: Option<PathBuf>,
    /// `source = "file"`: the erasure ledger (JSON lines).
    #[serde(default)]
    pub ledger_file: Option<PathBuf>,
    #[serde(default = "default_retry")]
    pub retry_secs: u64,
}

fn default_retry() -> u64 {
    10
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RemoteCfg {
    pub endpoint: String,
    #[serde(default = "default_region")]
    pub region: String,
    /// Required for stores; fallbacks name their bucket per bucket entry.
    #[serde(default)]
    pub bucket: Option<String>,
    /// TOML file with `access_key_id` and `secret_access_key` (mode 600).
    pub credentials_file: PathBuf,
    /// Stores only: prefix for object names (default `o/`).
    #[serde(default = "default_prefix")]
    pub prefix: String,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_read_timeout")]
    pub read_timeout_secs: u64,
    /// Attempts per request (1 = no retry). Retried: throttling and transient errors (408, 429, 500, 502,
    /// 503, 504, timeouts, resets) for idempotent requests; for the non-idempotent ones (create multipart)
    /// only answers that guarantee the request was not processed (connect errors, 408, 429, 503).
    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,
    /// First backoff; doubles per attempt up to `retry_max_ms`, with jitter (a random delay between half
    /// and all of it). A `Retry-After` from the store raises the delay (capped at `retry_max_ms`).
    #[serde(default = "default_retry_base_ms")]
    pub retry_base_ms: u64,
    #[serde(default = "default_retry_max_ms")]
    pub retry_max_ms: u64,
}

fn default_prefix() -> String {
    "o/".into()
}
fn default_connect_timeout() -> u64 {
    5
}
fn default_read_timeout() -> u64 {
    60
}
fn default_retry_attempts() -> u32 {
    6
}
fn default_retry_base_ms() -> u64 {
    250
}
fn default_retry_max_ms() -> u64 {
    10_000
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BucketCfg {
    /// The bucket name clients use.
    pub name: String,
    /// Key into `[stores]`.
    pub store: String,
    /// The tenant (in the key service's tenant keyring) whose key encrypts this bucket. Several buckets
    /// may share a tenant; erasing the tenant shreds all of them.
    pub tenant: String,
    #[serde(default)]
    pub fallback: Option<FallbackRef>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FallbackRef {
    /// Key into `[fallbacks]`.
    pub source: String,
    pub bucket: String,
    /// The fallback is retired (emptied or switched off): fill and reconcile refuse to run against it.
    #[serde(default)]
    pub retired: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ClientCfg {
    pub name: String,
    pub access_key_id: String,
    /// File holding the secret access key (one line, mode 600).
    pub secret_file: PathBuf,
    /// Buckets with read and write access.
    #[serde(default)]
    pub buckets: Vec<String>,
    /// Buckets with read-only access.
    #[serde(default)]
    pub read_buckets: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FillCfg {
    #[serde(default = "default_fill_conc")]
    pub concurrency: usize,
    /// Byte budget for the background fill (bytes per second). Live read-through misses are not limited.
    #[serde(default = "default_fill_rate")]
    pub rate_bytes_per_sec: u64,
    /// While a live read-through fetch is running, the fill pauses in steps of this many milliseconds.
    #[serde(default = "default_fill_yield")]
    pub yield_ms: u64,
    /// Reconcile refuses to remove more than this fraction of the checked filled rows unless forced.
    #[serde(default = "default_reconcile_max_fraction")]
    pub reconcile_max_fraction: f64,
    /// Key prefixes of temporary objects (for example `.sessions/`, `.staging/`). The fill
    /// never copies them and reconcile ignores them (neither counted against the cap nor removed).
    #[serde(default)]
    pub skip_prefixes: Vec<String>,
    /// Promote on read: a GET served from the fallback (a miss in the store) also writes the whole object
    /// to the store in the background, with the fill's rules (create-only under the per-key lock, never
    /// over a tombstone, recorded in the index). The client is answered without waiting for the store.
    /// Off: a miss is only read through, and the background fill copies it.
    #[serde(default = "default_true")]
    pub promote_on_read: bool,
    /// Promotions waiting at most; a promotion that finds the queue full is dropped (`deferred`) and left
    /// to the background fill.
    #[serde(default = "default_promote_queue")]
    pub promote_queue: usize,
    /// Plaintext bytes the waiting promotions may hold (their spools) at most; beyond it, deferred.
    #[serde(default = "default_promote_queue_bytes")]
    pub promote_queue_bytes: u64,
    /// Promotions written to the store in parallel at most.
    #[serde(default = "default_promote_concurrency")]
    pub promote_concurrency: usize,
}

impl FillCfg {
    /// True when `key` lies under one of `skip_prefixes`.
    pub fn is_skipped(&self, key: &str) -> bool {
        self.skip_prefixes.iter().any(|p| key.starts_with(p.as_str()))
    }
}

/// Upper bound for the fill concurrency an admin call may ask for.
pub const MAX_FILL_CONCURRENCY: usize = 32;

fn default_reconcile_max_fraction() -> f64 {
    0.01
}

impl Default for FillCfg {
    fn default() -> Self {
        FillCfg {
            concurrency: default_fill_conc(),
            rate_bytes_per_sec: default_fill_rate(),
            yield_ms: default_fill_yield(),
            reconcile_max_fraction: default_reconcile_max_fraction(),
            skip_prefixes: Vec::new(),
            promote_on_read: true,
            promote_queue: default_promote_queue(),
            promote_queue_bytes: default_promote_queue_bytes(),
            promote_concurrency: default_promote_concurrency(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_promote_queue() -> usize {
    1000
}
fn default_promote_queue_bytes() -> u64 {
    256 << 20
}
fn default_promote_concurrency() -> usize {
    2
}

fn default_fill_conc() -> usize {
    4
}
fn default_fill_rate() -> u64 {
    1_000_000
}
fn default_fill_yield() -> u64 {
    250
}

#[derive(Deserialize)]
pub struct S3Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
}

impl std::fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "S3Credentials({})", self.access_key_id)
    }
}

pub fn read_credentials(path: &Path) -> Result<S3Credentials> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read credentials {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parse credentials {}", path.display()))
}

pub fn read_secret_line(path: &Path) -> Result<String> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read secret {}", path.display()))?;
    let s = text.trim().to_string();
    if s.is_empty() {
        bail!("secret file {} is empty", path.display());
    }
    Ok(s)
}

/// Logical bucket used for the proxy's own metadata objects (index snapshots). Not addressable by clients.
pub const META_BUCKET: &str = ".s3vault";

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.stores.is_empty() {
            bail!("at least one [stores.<name>] is required");
        }
        for (name, s) in &self.stores {
            if s.bucket.is_none() {
                bail!("store {name}: bucket is required");
            }
        }
        let mut seen = HashSet::new();
        for b in &self.buckets {
            if b.name == META_BUCKET || b.name.is_empty() {
                bail!("bucket name {:?} is reserved", b.name);
            }
            if !seen.insert(b.name.clone()) {
                bail!("bucket {} defined twice", b.name);
            }
            if !self.stores.contains_key(&b.store) {
                bail!("bucket {}: unknown store {}", b.name, b.store);
            }
            if !s3vault_format::keys2::valid_tenant_name(&b.tenant) {
                bail!("bucket {}: tenant names are 1-64 of [a-z0-9_-]", b.name);
            }
            if let Some(f) = &b.fallback
                && !self.fallbacks.contains_key(&f.source)
            {
                bail!("bucket {}: unknown fallback {}", b.name, f.source);
            }
        }
        let mut keys = HashSet::new();
        for c in &self.clients {
            if !keys.insert(c.access_key_id.clone()) {
                bail!("client access key {} defined twice", c.access_key_id);
            }
            for b in c.buckets.iter().chain(&c.read_buckets) {
                if !seen.contains(b) {
                    bail!("client {}: unknown bucket {b}", c.name);
                }
            }
        }
        if let Some(a) = &self.server.admin_listen {
            let sa: std::net::SocketAddr = a
                .parse()
                .with_context(|| format!("admin_listen {a}"))?;
            if !sa.ip().is_loopback() {
                bail!("admin_listen {a} must be a loopback address");
            }
            if self.server.admin_token_file.is_none() {
                bail!("admin_listen needs admin_token_file (s3vault gen-admin-token --out FILE)");
            }
        }
        if !(0.0..=1.0).contains(&self.fill.reconcile_max_fraction) {
            bail!("fill.reconcile_max_fraction must be within 0..1");
        }
        if self.fill.promote_concurrency == 0 || self.fill.promote_concurrency > MAX_FILL_CONCURRENCY {
            bail!("fill.promote_concurrency must be within 1..{MAX_FILL_CONCURRENCY}");
        }
        if self.fill.skip_prefixes.iter().any(|p| p.is_empty()) {
            bail!("fill.skip_prefixes must not contain an empty prefix (it would skip every key)");
        }
        match self.keys.source {
            KeySource::Keyd => {
                if self.keys.keyd_addr.is_none() || self.keys.psk_file.is_none() {
                    bail!("keys.source = \"keyd\" needs keyd_addr and psk_file");
                }
            }
            KeySource::File => {
                if self.keys.file.is_none() {
                    bail!("keys.source = \"file\" needs file");
                }
            }
        }
        Ok(())
    }

    /// The store that holds a tenant's index snapshots: the store of its first bucket (by name).
    pub fn tenant_store(&self, tenant: &str) -> Option<&str> {
        let mut bs: Vec<&BucketCfg> = self.buckets.iter().filter(|b| b.tenant == tenant).collect();
        bs.sort_by(|a, b| a.name.cmp(&b.name));
        bs.first().map(|b| b.store.as_str())
    }
}
