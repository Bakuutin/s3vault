//! Rebuild-at-scale drill (review H4): N synthetic index rows -> a real encrypted snapshot in an
//! in-process S3 store -> `rebuild --snapshot` into a fresh index, with a listing synthesised from the
//! rows (the store does not hold N objects; every listed name is older than the snapshot, so no header is
//! read, exactly as in a real rebuild after `w` is lost). The process RSS is sampled during each phase.
//!
//! `S3VAULT_SCALE_ROWS` sets N (default 50 000, a few seconds). The production-size drill:
//! `S3VAULT_SCALE_ROWS=8700000 cargo test --release -p s3vault --test scale -- --nocapture`.

use async_trait::async_trait;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use s3vault::config::Config;
use s3vault::index::{Index, LIVE, ObjRow};
use s3vault::remote::{
    ByteStream, ListItem, ListPage, RResult, Remote, RemoteMeta, StoreView,
};
use s3vault_format::keys2::{Bundle, MasterV2, TenantKeyring, TenantKeys};
use s3vault_format::object;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

const AK: &str = "backend-ak";
const SK: &str = "backend-secret-key";
const DROPPED: u64 = 10;

async fn start_fs_s3(root: &Path) -> std::net::SocketAddr {
    std::fs::create_dir_all(root).unwrap();
    let fs = s3s_fs::FileSystem::new(root).unwrap();
    let mut b = s3s::service::S3ServiceBuilder::new(fs);
    b.set_auth(s3s::auth::SimpleAuth::from_single(AK, SK));
    let service = b.build();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let http = ConnBuilder::new(TokioExecutor::new());
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                continue;
            };
            let conn = http
                .serve_connection(TokioIo::new(sock), service.clone())
                .into_owned();
            tokio::spawn(conn);
        }
    });
    addr
}

/// Current resident set size of this process in bytes (`ps`, works on Linux and macOS).
fn rss_bytes() -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u64>()
        .unwrap_or(0)
        * 1024
}

/// Samples the RSS every 100 ms until stopped; returns the peak.
struct Sampler {
    stop: Arc<AtomicBool>,
    peak: Arc<AtomicU64>,
    h: std::thread::JoinHandle<()>,
}

impl Sampler {
    fn start() -> Sampler {
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(rss_bytes()));
        let (s, p) = (stop.clone(), peak.clone());
        let h = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                p.fetch_max(rss_bytes(), Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        Sampler { stop, peak, h }
    }
    fn finish(self) -> u64 {
        self.stop.store(true, Ordering::SeqCst);
        self.h.join().unwrap();
        self.peak.load(Ordering::SeqCst).max(rss_bytes())
    }
}

fn mib(b: u64) -> f64 {
    b as f64 / (1 << 20) as f64
}

fn synthetic_row(i: u64) -> ObjRow {
    let mut salt = [0u8; 32];
    salt[..8].copy_from_slice(&i.to_be_bytes());
    let mut ad = [7u8; 32];
    ad[24..].copy_from_slice(&i.to_le_bytes());
    ObjRow {
        bucket: "data".into(),
        key: format!("audio/{:024x}/{:06}.opus", i / 8640, i % 8640),
        state: LIVE,
        size: 9000 + i % 5000,
        etag: format!("{:032x}", i as u128 * 2654435761),
        sha256: format!("{:064x}", i as u128 * 40503),
        content_type: Some("audio/ogg".into()),
        meta: "{}".into(),
        generation: 1_700_000_000_000 + i,
        kid: 1,
        salt,
        hlen: 1040,
        ad,
        mtime_ms: 1_700_000_000_000 + i as i64,
        origin: 1,
    }
}

/// The store's real objects (the snapshot) plus a synthesised listing of every source row except the
/// last `DROPPED` (objects "lost" since the snapshot, which the rebuild must drop).
struct SynthView {
    inner: Arc<Remote>,
    source: Arc<Index>,
    tk: Arc<s3vault::vault::TenantRt>,
    prefix: String,
    total: u64,
    old_ms: i64,
}

#[async_trait]
impl StoreView for SynthView {
    async fn list_page(&self, _prefix: &str, token: Option<&str>, max: usize) -> RResult<ListPage> {
        let (ab, ak, done) = match token {
            None => (String::new(), String::new(), 0u64),
            Some(t) => {
                let mut it = t.splitn(3, '\u{1}');
                let done = it.next().unwrap().parse().unwrap();
                (it.next().unwrap().to_string(), it.next().unwrap().to_string(), done)
            }
        };
        let rows = self.source.page_rows(&ab, &ak, max).unwrap();
        let keep = (self.total - DROPPED).saturating_sub(done) as usize;
        let items: Vec<ListItem> = rows
            .iter()
            .filter(|r| r.bucket == "data")
            .take(keep)
            .map(|r| ListItem {
                key: format!(
                    "{}{}",
                    self.prefix,
                    object::store_name_v2(&self.tk.keys, &r.bucket, &r.key)
                ),
                size: r.size,
                etag: String::new(),
                last_modified_ms: Some(self.old_ms),
            })
            .collect();
        let n = done + items.len() as u64;
        let next = match rows.last() {
            Some(l) if rows.len() == max && n < self.total - DROPPED => {
                Some(format!("{n}\u{1}{}\u{1}{}", l.bucket, l.key))
            }
            _ => None,
        };
        Ok(ListPage {
            items,
            prefixes: vec![],
            next_token: next,
        })
    }
    async fn get_stream(
        &self,
        key: &str,
        range: Option<(u64, u64)>,
    ) -> RResult<(RemoteMeta, ByteStream)> {
        self.inner.get_stream(key, range).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streamed_rebuild_at_scale() {
    let n: u64 = std::env::var("S3VAULT_SCALE_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000);
    let base = std::env::var("S3VAULT_SCALE_DIR").ok();
    let tmp = match &base {
        Some(b) => tempfile::tempdir_in(b).unwrap(),
        None => tempfile::tempdir().unwrap(),
    };
    let dir = tmp.path();
    let store_addr = start_fs_s3(&dir.join("store")).await;
    std::fs::write(
        dir.join("backend.toml"),
        format!("access_key_id = \"{AK}\"\nsecret_access_key = \"{SK}\"\n"),
    )
    .unwrap();
    let mut m = MasterV2::generate(None);
    m.confirm_escrow(&m.escrow_digest(), "test", 1).unwrap();
    let mut tk = TenantKeyring::default();
    tk.create("t1", 1).unwrap();
    let copy = tk.clone();
    tk.confirm_escrow(&copy, "d", "test", 1).unwrap();
    let bundle_text = format!("%master\n{}%tenants\n{}%ledger\n", m.to_text().as_str(), tk.to_text().as_str());
    let cfg_text = format!(
        r#"
[server]
listen = []
data_dir = "{d}/data"
index_snapshot_secs = 0

[keys]
source = "file"
file = "{d}/keyring"

[stores.main]
endpoint = "http://{store_addr}"
bucket = "cipher"
credentials_file = "{d}/backend.toml"
read_timeout_secs = 600

[[buckets]]
name = "data"
store = "main"
tenant = "t1"
"#,
        d = dir.display()
    );
    let cfg: Config = toml::from_str(&cfg_text).unwrap();
    cfg.validate().unwrap();
    aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .endpoint_url(format!("http://{store_addr}"))
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(AK, SK, None, None, "t"))
            .force_path_style(true)
            .build(),
    )
    .create_bucket()
    .bucket("cipher")
    .send()
    .await
    .unwrap();

    let vault = s3vault::vault::Vault::new(cfg.clone()).unwrap();
    vault.unlock(Bundle::parse(&bundle_text).unwrap()).unwrap();
    let tenant = vault.unlocked().unwrap().tenant_loaded("t1").unwrap();
    let src = tenant.index.clone();
    let rss0 = rss_bytes();

    // 1. the source index
    let t = Instant::now();
    let s = Sampler::start();
    let mut i = 0u64;
    while i < n {
        let end = (i + 20_000).min(n);
        let rows: Vec<ObjRow> = (i..end).map(synthetic_row).collect();
        src.upsert_many_if_newer(&rows).unwrap();
        i = end;
    }
    let populate = (t.elapsed(), s.finish());

    // 2. the encrypted snapshot (streamed through an encrypted spool file, then uploaded)
    let t = Instant::now();
    let s = Sampler::start();
    let snap = s3vault::background::snapshot(&vault).await.unwrap();
    let snapshot = (t.elapsed(), s.finish());
    assert_eq!(snap.rows, n);

    // 3. rebuild --snapshot into a fresh index with the synthesised listing
    let keys: &TenantKeys = &tenant.keys;
    let fresh = Index::open(&dir.join("rebuilt.db"), Some(&keys.index_key)).unwrap();
    let view: Arc<dyn StoreView> = Arc::new(SynthView {
        inner: vault.stores["main"].clone(),
        source: src.clone(),
        tk: tenant.clone(),
        prefix: "o/".into(),
        total: n,
        old_ms: s3vault::vault::now_ms() - 7_200_000,
    });
    let t = Instant::now();
    let s = Sampler::start();
    let rep = s3vault::background::rebuild_with(vault.clone(), keys, &fresh, true, 16, &|_| {
        view.clone()
    })
    .await
    .unwrap();
    let rebuild = (t.elapsed(), s.finish());

    assert_eq!(rep.snapshot_rows, n);
    assert_eq!(rep.listed, n - DROPPED);
    assert_eq!(rep.headers_read, 0, "nothing newer than the snapshot");
    assert_eq!(rep.removed_stale, DROPPED);
    assert_eq!(rep.errors, 0);
    assert_eq!(fresh.counts("data").unwrap().0, n - DROPPED);
    for i in [0, n / 2, n - DROPPED - 1] {
        let r = synthetic_row(i);
        assert_eq!(fresh.get("data", &r.key).unwrap().unwrap(), r);
    }
    assert!(fresh.get("data", &synthetic_row(n - 1).key).unwrap().is_none());
    assert!(
        !std::fs::read_dir(dir.join("data"))
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with("rebuild-scratch")),
        "scratch file removed"
    );
    let report = serde_json::json!({
        "rows": n,
        "snapshot_plaintext_mib": mib(snap.plaintext_bytes),
        "baseline_rss_mib": mib(rss0),
        "populate": {"secs": populate.0.as_secs_f64(), "peak_rss_mib": mib(populate.1)},
        "snapshot": {"secs": snapshot.0.as_secs_f64(), "peak_rss_mib": mib(snapshot.1)},
        "rebuild": {"secs": rebuild.0.as_secs_f64(), "peak_rss_mib": mib(rebuild.1)},
    });
    println!("SCALE {report}");
    // Bounded RAM: far below the snapshot size (the old code held it twice).
    if n >= 1_000_000 {
        assert!(rebuild.1 < 1 << 30, "rebuild peak RSS {} MiB", mib(rebuild.1));
    }
}
