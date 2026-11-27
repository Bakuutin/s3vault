//! End-to-end tests: a real S3 client (aws-sdk-s3) talks to s3vault, which uses two in-process S3 servers
//! (s3s-fs) as the store of record and the read-through fallback.

use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use s3vault::config::Config;
use s3vault::index::{Index, LIVE, TOMBSTONE};
use s3vault_format::keys2::{Bundle, MasterV2, TenantKeyring};
use std::sync::Arc;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::TcpListener;

const AK: &str = "backend-ak";
const SK: &str = "backend-secret-key";
const ADMIN_TOKEN: &str = "test-admin-token-0123456789abcdef0123456789";

/// An in-process S3 server (s3s-fs) on a random loopback port.
struct FsS3 {
    addr: SocketAddr,
    root: PathBuf,
    task: tokio::task::JoinHandle<()>,
    stop: tokio::sync::watch::Sender<bool>,
}

impl FsS3 {
    /// Stop accepting and drop every open connection (a real outage, not just a closed listener).
    fn kill(&self) {
        let _ = self.stop.send(true);
        self.task.abort();
    }
}

async fn start_fs_s3(root: &Path, addr: Option<SocketAddr>) -> FsS3 {
    std::fs::create_dir_all(root).unwrap();
    let fs = s3s_fs::FileSystem::new(root).unwrap();
    let mut b = s3s::service::S3ServiceBuilder::new(fs);
    b.set_auth(s3s::auth::SimpleAuth::from_single(AK, SK));
    let service = b.build();
    let listener = TcpListener::bind(addr.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap()))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        let http = ConnBuilder::new(TokioExecutor::new());
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                continue;
            };
            let conn = http
                .serve_connection(TokioIo::new(sock), service.clone())
                .into_owned();
            let mut rx = rx.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = conn => {}
                    _ = rx.changed() => {}
                }
            });
        }
    });
    FsS3 {
        addr,
        root: root.to_path_buf(),
        task,
        stop,
    }
}

fn client(endpoint: &str, ak: &str, sk: &str) -> Client {
    let conf = aws_sdk_s3::config::Builder::new()
        .behavior_version(BehaviorVersion::latest())
        .endpoint_url(endpoint)
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new(ak, sk, None, None, "test"))
        .force_path_style(true)
        .build();
    Client::from_conf(conf)
}

struct Env {
    _dir: tempfile::TempDir,
    dir: PathBuf,
    store: FsS3,
    fallback: FsS3,
    cfg: Config,
    keyring_path: PathBuf,
    running: Option<s3vault::Running>,
    rw: Client,
    ro: Client,
    legacy: Client,
}

fn write(p: &Path, s: &str) {
    std::fs::write(p, s).unwrap();
}

fn config_text(dir: &Path, store: SocketAddr, fallback: SocketAddr, keys: &str) -> String {
    format!(
        r#"
[server]
listen = ["127.0.0.1:0"]
admin_listen = "127.0.0.1:0"
admin_token_file = "{dir}/admin.token"
data_dir = "{data}"
memory_spool_max = 100000
store_multipart_threshold = 6000000
store_multipart_part = 5242880
index_snapshot_secs = 0

[keys]
{keys}
retry_secs = 1

[stores.main]
endpoint = "http://{store}"
bucket = "cipher"
credentials_file = "{dir}/backend.toml"

[fallbacks.legacy]
endpoint = "http://{fallback}"
credentials_file = "{dir}/backend.toml"
connect_timeout_secs = 1
read_timeout_secs = 5
# The outage tests kill the fallback: keep the retries short (the aws-sdk client retries 503s itself too).
retry_attempts = 2
retry_base_ms = 10
retry_max_ms = 20

[[buckets]]
name = "data"
store = "main"
tenant = "t1"
fallback = {{ source = "legacy", bucket = "legacy" }}

[[buckets]]
name = "plain"
store = "main"
tenant = "t2"

[[clients]]
name = "app"
access_key_id = "APPKEY"
secret_file = "{dir}/app.secret"
buckets = ["data", "plain"]

[[clients]]
name = "reader"
access_key_id = "READKEY"
secret_file = "{dir}/reader.secret"
read_buckets = ["data"]

[fill]
concurrency = 2
rate_bytes_per_sec = 100000000
yield_ms = 20
skip_prefixes = [".sessions/", ".staging/"]
"#,
        data = dir.join("data").display(),
        dir = dir.display(),
    )
}

/// An escrowed master keyring and a tenant keyring with these tenants active (texts).
fn test_keys(tenants: &[&str]) -> (String, String) {
    let mut m = MasterV2::generate(None);
    m.confirm_escrow(&m.escrow_digest(), "test", 1).unwrap();
    let mut tk = TenantKeyring::default();
    for t in tenants {
        tk.create(t, 1).unwrap();
    }
    let copy = tk.clone();
    tk.confirm_escrow(&copy, "d", "test", 1).unwrap();
    (m.to_text().to_string(), tk.to_text().to_string())
}

/// The index partition of a bucket's tenant.
fn tidx(v: &s3vault::vault::Vault, bucket: &str) -> Arc<Index> {
    let u = v.unlocked().unwrap();
    u.tenant_loaded(&v.buckets[bucket].tenant).unwrap().index.clone()
}

fn tenant_rt(v: &s3vault::vault::Vault, bucket: &str) -> Arc<s3vault::vault::TenantRt> {
    let u = v.unlocked().unwrap();
    u.tenant_loaded(&v.buckets[bucket].tenant).unwrap()
}

fn bundle(env: &Env) -> Bundle {
    s3vault::background::fetch_bundle(&env.cfg.keys).unwrap()
}

async fn wait_unlocked(r: &s3vault::Running) {
    for _ in 0..100 {
        if !r.vault.is_locked() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("vault did not unlock");
}

async fn setup() -> Env {
    setup_with("").await
}

/// `extra` is appended to the config (it lands in the trailing `[fill]` table).
async fn setup_with(extra: &str) -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let store = start_fs_s3(&dir.join("store"), None).await;
    let fallback = start_fs_s3(&dir.join("fallback"), None).await;
    write(
        &dir.join("backend.toml"),
        &format!("access_key_id = \"{AK}\"\nsecret_access_key = \"{SK}\"\n"),
    );
    write(&dir.join("app.secret"), "app-secret\n");
    write(&dir.join("reader.secret"), "reader-secret\n");
    write(&dir.join("admin.token"), &format!("{ADMIN_TOKEN}\n"));
    let keyring_path = dir.join("keyring");
    let (master, tenants) = test_keys(&["t1", "t2"]);
    write(&keyring_path, &master);
    write(&dir.join("tenants"), &tenants);
    write(&dir.join("ledger.jsonl"), "");
    let keys = format!(
        "source = \"file\"\nfile = \"{}\"\ntenants_file = \"{d}/tenants\"\nledger_file = \"{d}/ledger.jsonl\"",
        keyring_path.display(),
        d = dir.display()
    );
    let text = config_text(&dir, store.addr, fallback.addr, &keys) + extra;
    let cfg: Config = toml::from_str(&text).unwrap();
    cfg.validate().unwrap();
    client(&format!("http://{}", store.addr), AK, SK)
        .create_bucket()
        .bucket("cipher")
        .send()
        .await
        .unwrap();
    let legacy = client(&format!("http://{}", fallback.addr), AK, SK);
    legacy
        .create_bucket()
        .bucket("legacy")
        .send()
        .await
        .unwrap();
    let running = s3vault::start(cfg.clone()).await.unwrap();
    wait_unlocked(&running).await;
    let ep = format!("http://{}", running.s3_addrs[0]);
    Env {
        rw: client(&ep, "APPKEY", "app-secret"),
        ro: client(&ep, "READKEY", "reader-secret"),
        legacy,
        _dir: tmp,
        dir,
        store,
        fallback,
        cfg,
        keyring_path,
        running: Some(running),
    }
}

impl Env {
    fn vault(&self) -> &s3vault::vault::Vault {
        &self.running.as_ref().unwrap().vault
    }
    fn admin(&self) -> String {
        format!(
            "http://{}",
            self.running.as_ref().unwrap().admin_addr.unwrap()
        )
    }
}

fn data(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| ((i as u64 * 7919 + seed as u64) % 251) as u8)
        .collect()
}

async fn get_all(c: &Client, b: &str, k: &str, range: Option<&str>) -> Result<Vec<u8>, String> {
    let mut req = c.get_object().bucket(b).key(k);
    if let Some(r) = range {
        req = req.range(r);
    }
    match req.send().await {
        Ok(o) => Ok(o.body.collect().await.unwrap().into_bytes().to_vec()),
        Err(e) => Err(status_of(&e)),
    }
}

fn status_of<E: std::fmt::Debug, R: std::fmt::Debug>(
    e: &aws_sdk_s3::error::SdkError<E, R>,
) -> String {
    match e {
        aws_sdk_s3::error::SdkError::ServiceError(se) => format!("{:?}", se.raw())
            .split("status: StatusCode(")
            .nth(1)
            .map(|s| s[..3].to_string())
            .unwrap_or_else(|| format!("{e:?}")),
        other => format!("{other:?}"),
    }
}

fn http_status<E, R: HasStatus>(e: &aws_sdk_s3::error::SdkError<E, R>) -> u16 {
    match e {
        aws_sdk_s3::error::SdkError::ServiceError(se) => se.raw().status_code(),
        aws_sdk_s3::error::SdkError::ResponseError(re) => re.raw().status_code(),
        _ => 0,
    }
}

trait HasStatus {
    fn status_code(&self) -> u16;
}

impl HasStatus for aws_sdk_s3::config::http::HttpResponse {
    fn status_code(&self) -> u16 {
        self.status().as_u16()
    }
}

fn all_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
}

async fn admin_post(env: &Env, path: &str) -> serde_json::Value {
    let r = reqwest::Client::new()
        .post(format!("{}{path}", env.admin()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    serde_json::from_slice(&r.bytes().await.unwrap()).unwrap()
}

async fn admin_get(env: &Env, path: &str) -> serde_json::Value {
    serde_json::from_slice(
        &reqwest::Client::new()
            .get(format!("{}{path}", env.admin()))
            .bearer_auth(ADMIN_TOKEN)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn core_s3_needs_and_ciphertext_only() {
    let env = setup().await;
    let c = &env.rw;
    // put / head / get
    let body = data(3 * 65536 + 1234, 1);
    let put = c
        .put_object()
        .bucket("plain")
        .key("audio/rec-1/000001.opus")
        .content_type("audio/ogg")
        .metadata("speaker", "alice")
        .body(ByteStream::from(body.clone()))
        .send()
        .await
        .unwrap();
    let etag = put.e_tag().unwrap().to_string();
    let head = c
        .head_object()
        .bucket("plain")
        .key("audio/rec-1/000001.opus")
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_length(), Some(body.len() as i64));
    assert_eq!(head.e_tag(), Some(etag.as_str()));
    assert_eq!(head.content_type(), Some("audio/ogg"));
    assert_eq!(
        head.metadata().unwrap().get("speaker").map(String::as_str),
        Some("alice")
    );
    assert_eq!(
        get_all(c, "plain", "audio/rec-1/000001.opus", None)
            .await
            .unwrap(),
        body
    );
    // inclusive ranges across chunk boundaries, with Content-Range total
    for (s, e) in [
        (0usize, 0usize),
        (65535, 65536),
        (65530, 131080),
        (100, body.len() - 1),
        (body.len() - 10, body.len() - 1),
    ] {
        let r = c
            .get_object()
            .bucket("plain")
            .key("audio/rec-1/000001.opus")
            .range(format!("bytes={s}-{e}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.content_range(),
            Some(format!("bytes {s}-{e}/{}", body.len()).as_str())
        );
        let got = r.body.collect().await.unwrap().into_bytes();
        assert_eq!(&got[..], &body[s..=e], "range {s}-{e}");
    }
    let suffix = get_all(c, "plain", "audio/rec-1/000001.opus", Some("bytes=-5"))
        .await
        .unwrap();
    assert_eq!(suffix, &body[body.len() - 5..]);
    // empty object
    c.put_object()
        .bucket("plain")
        .key("empty")
        .body(ByteStream::from(Vec::new()))
        .send()
        .await
        .unwrap();
    assert_eq!(
        get_all(c, "plain", "empty", None).await.unwrap(),
        Vec::<u8>::new()
    );
    // list with prefix, limit, continuation, delimiter
    for i in 0..5 {
        c.put_object()
            .bucket("plain")
            .key(format!("audio/rec-2/{i:06}.opus"))
            .body(ByteStream::from(vec![i as u8; 10]))
            .send()
            .await
            .unwrap();
    }
    let l = c
        .list_objects_v2()
        .bucket("plain")
        .prefix("audio/rec-2/")
        .max_keys(2)
        .send()
        .await
        .unwrap();
    assert_eq!(l.contents().len(), 2);
    assert_eq!(l.is_truncated(), Some(true));
    let l2 = c
        .list_objects_v2()
        .bucket("plain")
        .prefix("audio/rec-2/")
        .continuation_token(l.next_continuation_token().unwrap())
        .send()
        .await
        .unwrap();
    let keys: Vec<_> = l2
        .contents()
        .iter()
        .map(|o| o.key().unwrap().to_string())
        .collect();
    assert_eq!(
        keys,
        [
            "audio/rec-2/000002.opus",
            "audio/rec-2/000003.opus",
            "audio/rec-2/000004.opus"
        ]
    );
    let d = c
        .list_objects_v2()
        .bucket("plain")
        .delimiter("/")
        .send()
        .await
        .unwrap();
    let cps: Vec<_> = d
        .common_prefixes()
        .iter()
        .map(|p| p.prefix().unwrap().to_string())
        .collect();
    assert_eq!(cps, ["audio/"]);
    assert_eq!(
        d.contents()
            .iter()
            .map(|o| o.key().unwrap())
            .collect::<Vec<_>>(),
        ["empty"]
    );
    let d2 = c
        .list_objects_v2()
        .bucket("plain")
        .prefix("audio/")
        .delimiter("/")
        .max_keys(1)
        .send()
        .await
        .unwrap();
    assert_eq!(d2.common_prefixes()[0].prefix(), Some("audio/rec-1/"));
    let d3 = c
        .list_objects_v2()
        .bucket("plain")
        .prefix("audio/")
        .delimiter("/")
        .continuation_token(d2.next_continuation_token().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(d3.common_prefixes()[0].prefix(), Some("audio/rec-2/"));
    assert_eq!(d3.is_truncated(), Some(false));
    // create-only put
    c.put_object()
        .bucket("plain")
        .key("once")
        .if_none_match("*")
        .body(ByteStream::from_static(b"1"))
        .send()
        .await
        .unwrap();
    let e = c
        .put_object()
        .bucket("plain")
        .key("once")
        .if_none_match("*")
        .body(ByteStream::from_static(b"2"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(http_status(&e), 412);
    assert_eq!(get_all(c, "plain", "once", None).await.unwrap(), b"1");
    // copy
    let cp = c
        .copy_object()
        .bucket("plain")
        .key("copy-of-1")
        .copy_source("plain/audio/rec-1/000001.opus")
        .send()
        .await
        .unwrap();
    assert!(cp.copy_object_result().unwrap().e_tag().is_some());
    assert_eq!(get_all(c, "plain", "copy-of-1", None).await.unwrap(), body);
    let h = c
        .head_object()
        .bucket("plain")
        .key("copy-of-1")
        .send()
        .await
        .unwrap();
    assert_eq!(h.content_type(), Some("audio/ogg"));
    // delete (no fallback on this bucket: removed from store and index)
    c.delete_object()
        .bucket("plain")
        .key("copy-of-1")
        .send()
        .await
        .unwrap();
    assert_eq!(
        http_status(
            &c.get_object()
                .bucket("plain")
                .key("copy-of-1")
                .send()
                .await
                .unwrap_err()
        ),
        404
    );
    // multipart: parts invisible before complete, read across the part boundary, abort
    let mp = c
        .create_multipart_upload()
        .bucket("plain")
        .key("big/obj")
        .content_type("application/x-test")
        .send()
        .await
        .unwrap();
    let id = mp.upload_id().unwrap().to_string();
    let p1 = data(5 * 1024 * 1024 + 1000, 2);
    let p2 = data(70_000, 3);
    let e1 = c
        .upload_part()
        .bucket("plain")
        .key("big/obj")
        .upload_id(&id)
        .part_number(1)
        .body(ByteStream::from(p1.clone()))
        .send()
        .await
        .unwrap();
    let e2 = c
        .upload_part()
        .bucket("plain")
        .key("big/obj")
        .upload_id(&id)
        .part_number(2)
        .body(ByteStream::from(p2.clone()))
        .send()
        .await
        .unwrap();
    assert_eq!(
        http_status(
            &c.head_object()
                .bucket("plain")
                .key("big/obj")
                .send()
                .await
                .unwrap_err()
        ),
        404
    );
    let parts = c
        .list_parts()
        .bucket("plain")
        .key("big/obj")
        .upload_id(&id)
        .send()
        .await
        .unwrap();
    assert_eq!(parts.parts().len(), 2);
    let done = c
        .complete_multipart_upload()
        .bucket("plain")
        .key("big/obj")
        .upload_id(&id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .parts(
                    CompletedPart::builder()
                        .part_number(1)
                        .e_tag(e1.e_tag().unwrap())
                        .build(),
                )
                .parts(
                    CompletedPart::builder()
                        .part_number(2)
                        .e_tag(e2.e_tag().unwrap())
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert!(done.e_tag().unwrap().ends_with("-2\""));
    let mut whole = p1.clone();
    whole.extend_from_slice(&p2);
    let b = p1.len();
    let across = get_all(
        c,
        "plain",
        "big/obj",
        Some(&format!("bytes={}-{}", b - 100, b + 100)),
    )
    .await
    .unwrap();
    assert_eq!(across, &whole[b - 100..=b + 100]);
    assert_eq!(get_all(c, "plain", "big/obj", None).await.unwrap(), whole);
    let mp2 = c
        .create_multipart_upload()
        .bucket("plain")
        .key("big/aborted")
        .send()
        .await
        .unwrap();
    let id2 = mp2.upload_id().unwrap();
    c.upload_part()
        .bucket("plain")
        .key("big/aborted")
        .upload_id(id2)
        .part_number(1)
        .body(ByteStream::from(vec![1u8; 100]))
        .send()
        .await
        .unwrap();
    c.abort_multipart_upload()
        .bucket("plain")
        .key("big/aborted")
        .upload_id(id2)
        .send()
        .await
        .unwrap();
    assert_eq!(
        http_status(
            &c.head_object()
                .bucket("plain")
                .key("big/aborted")
                .send()
                .await
                .unwrap_err()
        ),
        404
    );
    assert!(
        all_files(&env.dir.join("data/staging")).is_empty(),
        "staging cleaned up"
    );
    // The store holds only ciphertext: flat keyed-hash names, no key names, no plaintext runs.
    let files = all_files(&env.store.root.join("cipher"));
    assert!(!files.is_empty());
    let needles: Vec<&[u8]> = vec![
        b"audio/rec-1",
        b"000001.opus",
        b"alice",
        b"audio/ogg",
        b"big/obj",
    ];
    for f in &files {
        let rel = f
            .strip_prefix(env.store.root.join("cipher"))
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert!(
            !rel.contains("audio") && !rel.contains("big"),
            "plain name in store: {rel}"
        );
        let bytes = std::fs::read(f).unwrap();
        for n in &needles {
            assert!(
                !bytes.windows(n.len()).any(|w| w == *n),
                "plaintext {:?} found in {rel}",
                String::from_utf8_lossy(n)
            );
        }
        assert!(
            !bytes.windows(64).any(|w| w == &body[1000..1064]),
            "plaintext body run found in {rel}"
        );
    }
    // access control
    let e = env
        .ro
        .put_object()
        .bucket("data")
        .key("x")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(http_status(&e), 403);
    let e = env
        .ro
        .get_object()
        .bucket("plain")
        .key("once")
        .send()
        .await
        .unwrap_err();
    assert_eq!(http_status(&e), 403);
    let bad = client(
        &format!("http://{}", env.running.as_ref().unwrap().s3_addrs[0]),
        "APPKEY",
        "wrong",
    );
    assert_eq!(
        http_status(
            &bad.get_object()
                .bucket("plain")
                .key("once")
                .send()
                .await
                .unwrap_err()
        ),
        403
    );
    // tampering with a stored object is detected (500, never wrong data)
    let row = tidx(env.vault(), "plain").get("plain", "once").unwrap().unwrap();
    let t = tenant_rt(env.vault(), "plain");
    let name = env
        .vault()
        .store_name(&t, &env.vault().buckets["plain"].store, "plain", "once");
    let path = env.store.root.join("cipher").join(&name);
    let mut raw = std::fs::read(&path).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0x55;
    std::fs::write(&path, &raw).unwrap();
    let e = c
        .get_object()
        .bucket("plain")
        .key("once")
        .send()
        .await
        .unwrap_err();
    assert_eq!(http_status(&e), 500);
    assert_eq!(row.size, 1);
    env.running.unwrap().shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_through_write_back_tombstones_and_503() {
    let mut env = setup().await;
    let c = env.rw.clone();
    let old = data(150_000, 9);
    env.legacy
        .put_object()
        .bucket("legacy")
        .key("rec/a.opus")
        .content_type("audio/ogg")
        .body(ByteStream::from(old.clone()))
        .send()
        .await
        .unwrap();
    env.legacy
        .put_object()
        .bucket("legacy")
        .key("rec/b.opus")
        .body(ByteStream::from_static(b"bbb"))
        .send()
        .await
        .unwrap();
    env.legacy
        .put_object()
        .bucket("legacy")
        .key("rec/c.opus")
        .body(ByteStream::from_static(b"ccc"))
        .send()
        .await
        .unwrap();
    // HEAD of an unfilled key answers from the fallback, without copying
    let h = c
        .head_object()
        .bucket("data")
        .key("rec/a.opus")
        .send()
        .await
        .unwrap();
    assert_eq!(h.content_length(), Some(old.len() as i64));
    let idx = tidx(env.vault(), "data");
    assert!(idx.get("data", "rec/a.opus").unwrap().is_none());
    // Merged listing: fallback keys appear
    let l = c.list_objects_v2().bucket("data").send().await.unwrap();
    assert_eq!(l.contents().len(), 3);
    // ranged GET of an unfilled key: served from the fallback and written back encrypted
    let r = get_all(&c, "data", "rec/a.opus", Some("bytes=70000-80000"))
        .await
        .unwrap();
    assert_eq!(r, &old[70000..=80000]);
    wait_promotions(env.vault()).await;
    let row = idx.get("data", "rec/a.opus").unwrap().unwrap();
    assert_eq!(
        (row.state, row.origin, row.size),
        (LIVE, 1, old.len() as u64)
    );
    // Deleting a key the fallback still has leaves a tombstone: never resurrected
    c.delete_object()
        .bucket("data")
        .key("rec/b.opus")
        .send()
        .await
        .unwrap();
    assert_eq!(
        http_status(
            &c.get_object()
                .bucket("data")
                .key("rec/b.opus")
                .send()
                .await
                .unwrap_err()
        ),
        404
    );
    assert_eq!(
        http_status(
            &c.head_object()
                .bucket("data")
                .key("rec/b.opus")
                .send()
                .await
                .unwrap_err()
        ),
        404
    );
    assert_eq!(
        idx.get("data", "rec/b.opus").unwrap().unwrap().state,
        TOMBSTONE
    );
    let keys: Vec<String> = c
        .list_objects_v2()
        .bucket("data")
        .send()
        .await
        .unwrap()
        .contents()
        .iter()
        .map(|o| o.key().unwrap().to_string())
        .collect();
    assert_eq!(keys, ["rec/a.opus", "rec/c.opus"]);
    // create-only on a key that exists only in the fallback is refused
    let e = c
        .put_object()
        .bucket("data")
        .key("rec/c.opus")
        .if_none_match("*")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(http_status(&e), 412);
    // a missing key with the fallback up is a 404
    assert_eq!(
        http_status(
            &c.get_object()
                .bucket("data")
                .key("nope")
                .send()
                .await
                .unwrap_err()
        ),
        404
    );
    // writes go to the store only
    c.put_object()
        .bucket("data")
        .key("new/x")
        .body(ByteStream::from_static(b"new"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        http_status(
            &env.legacy
                .head_object()
                .bucket("legacy")
                .key("new/x")
                .send()
                .await
                .unwrap_err()
        ),
        404
    );

    // Fallback down: filled keys still read; unfilled keys and listings are 503, never 404.
    env.fallback.kill();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(get_all(&c, "data", "rec/a.opus", None).await.unwrap(), old);
    assert_eq!(get_all(&c, "data", "new/x", None).await.unwrap(), b"new");
    assert_eq!(
        http_status(
            &c.get_object()
                .bucket("data")
                .key("rec/c.opus")
                .send()
                .await
                .unwrap_err()
        ),
        503
    );
    assert_eq!(
        http_status(
            &c.get_object()
                .bucket("data")
                .key("never-existed")
                .send()
                .await
                .unwrap_err()
        ),
        503
    );
    assert_eq!(
        http_status(
            &c.head_object()
                .bucket("data")
                .key("rec/c.opus")
                .send()
                .await
                .unwrap_err()
        ),
        503
    );
    assert_eq!(
        http_status(&c.list_objects_v2().bucket("data").send().await.unwrap_err()),
        503
    );
    // tombstoned keys stay 404 without asking the fallback
    assert_eq!(
        http_status(
            &c.get_object()
                .bucket("data")
                .key("rec/b.opus")
                .send()
                .await
                .unwrap_err()
        ),
        404
    );
    // a bucket without a fallback is unaffected
    c.put_object()
        .bucket("plain")
        .key("p")
        .body(ByteStream::from_static(b"p"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        http_status(
            &c.get_object()
                .bucket("plain")
                .key("nope")
                .send()
                .await
                .unwrap_err()
        ),
        404
    );

    // Rebuild from the store plus the keyring alone, into a fresh index; compare with the live one.
    env.fallback = start_fs_s3(&env.dir.join("fallback"), Some(env.fallback.addr)).await;
    let t1 = tenant_rt(env.vault(), "data");
    let t2 = tenant_rt(env.vault(), "plain");
    let fresh = Index::open(&env.dir.join("rebuilt.db"), Some(&t1.keys.index_key)).unwrap();
    let rep = s3vault::background::rebuild(
        env.running.as_ref().unwrap().vault.clone(),
        &t1.keys,
        &fresh,
        false,
        4,
    )
    .await
    .unwrap();
    assert_eq!(rep.errors, 0);
    let fresh2 = Index::open(&env.dir.join("rebuilt2.db"), Some(&t2.keys.index_key)).unwrap();
    let rep_b = s3vault::background::rebuild(
        env.running.as_ref().unwrap().vault.clone(),
        &t2.keys,
        &fresh2,
        false,
        4,
    )
    .await
    .unwrap();
    assert_eq!(rep_b.errors, 0);
    for (b, k) in [
        ("data", "rec/a.opus"),
        ("data", "rec/b.opus"),
        ("data", "new/x"),
        ("plain", "p"),
    ] {
        let mut a = tidx(env.vault(), b).get(b, k).unwrap().unwrap();
        let mut r = if b == "data" { &fresh } else { &fresh2 }.get(b, k).unwrap().unwrap();
        a.origin = 0;
        r.origin = 0;
        assert_eq!(a, r, "{b}/{k}");
    }
    assert_eq!(fresh.counts("data").unwrap(), idx.counts("data").unwrap());
    assert_eq!(fresh.counts("plain").unwrap(), (0, 0, 0), "a tenant rebuild sees only its own objects");
    // With another tenant secret (same id, same prefix) nothing is readable.
    let mut b = bundle(&env);
    let mut e = b.tenants.tenants["t1"].clone();
    e.k_t = Some(zeroize::Zeroizing::new([9u8; 32]));
    b.tenants.tenants.insert("t1".into(), e.clone());
    let m = Arc::new(b.master);
    let wrong = m.tenant_keys(&e).unwrap();
    let other_idx = Index::open(&env.dir.join("other.db"), Some(&wrong.index_key)).unwrap();
    let rep2 = s3vault::background::rebuild(
        env.running.as_ref().unwrap().vault.clone(),
        &wrong,
        &other_idx,
        false,
        4,
    )
    .await
    .unwrap();
    assert_eq!(rep2.live + rep2.tombstones, 0);
    assert!(rep2.errors > 0);
    // snapshot + incremental rebuild
    let snap = s3vault::background::snapshot(env.vault()).await.unwrap();
    assert!(snap.rows >= 4);
    assert_eq!(snap.tenants, 2);
    let inc = Index::open(&env.dir.join("inc.db"), Some(&t1.keys.index_key)).unwrap();
    let rep3 = s3vault::background::rebuild(
        env.running.as_ref().unwrap().vault.clone(),
        &t1.keys,
        &inc,
        true,
        4,
    )
    .await
    .unwrap();
    assert!(rep3.snapshot_rows >= 3, "{rep3:?}");
    assert_eq!(rep3.snapshot_rows, idx.counts("data").unwrap().0 + idx.counts("data").unwrap().1);
    assert_eq!(inc.counts("data").unwrap(), idx.counts("data").unwrap());
    env.running.take().unwrap().shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn background_fill_and_verify() {
    let env = setup().await;
    for i in 0..12 {
        env.legacy
            .put_object()
            .bucket("legacy")
            .key(format!("f/{i:03}"))
            .body(ByteStream::from(data(1000 + i * 5000, i as u8)))
            .send()
            .await
            .unwrap();
    }
    // a live write and a delete before the fill: the fill must not overwrite or resurrect them
    env.rw
        .put_object()
        .bucket("data")
        .key("f/001")
        .body(ByteStream::from_static(b"live"))
        .send()
        .await
        .unwrap();
    env.rw
        .delete_object()
        .bucket("data")
        .key("f/002")
        .send()
        .await
        .unwrap();
    let r = admin_post(&env, "/fill/start?bucket=data&max_objects=5").await;
    assert_eq!(r["started"], "data");
    for _ in 0..200 {
        let st = admin_get(&env, "/fill").await;
        if st[0]["running"] == false {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let idx = tidx(env.vault(), "data");
    let st = admin_get(&env, "/fill").await;
    assert_eq!(
        st[0]["session_copied"].as_u64().unwrap() + st[0]["session_skipped"].as_u64().unwrap(),
        5
    );
    // complete the fill
    admin_post(&env, "/fill/start?bucket=data").await;
    for _ in 0..200 {
        let st = admin_get(&env, "/fill").await;
        if st[0]["running"] == false {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let st = admin_get(&env, "/fill").await;
    assert_eq!(st[0]["total"]["finished"], true);
    assert_eq!(st[0]["total"]["copied"].as_u64().unwrap(), 10);
    assert_eq!(
        idx.get("data", "f/001").unwrap().unwrap().origin,
        0,
        "live write kept"
    );
    assert_eq!(
        get_all(&env.rw, "data", "f/001", None).await.unwrap(),
        b"live"
    );
    assert_eq!(
        idx.get("data", "f/002").unwrap().unwrap().state,
        TOMBSTONE,
        "delete kept"
    );
    let v = admin_post(&env, "/verify?bucket=data&max=100&fallback=1").await;
    assert_eq!(v["checked"], 10);
    assert_eq!(v["ok"], 10);
    assert_eq!(v["store_mismatch"], 0);
    assert_eq!(v["fallback_mismatch"], 0);
    // The fallback changes after the fill (the old writer is still live): reconcile drops the stale copies.
    env.legacy
        .delete_object()
        .bucket("legacy")
        .key("f/005")
        .send()
        .await
        .unwrap();
    env.legacy
        .put_object()
        .bucket("legacy")
        .key("f/006")
        .body(ByteStream::from_static(b"changed on the old store"))
        .send()
        .await
        .unwrap();
    let dry = admin_post(&env, "/reconcile?bucket=data&dry_run=1").await;
    assert_eq!(
        (
            dry["gone_in_fallback"].as_u64(),
            dry["changed_in_fallback"].as_u64(),
            dry["removed"].as_u64()
        ),
        (Some(1), Some(1), Some(0))
    );
    assert_eq!(dry["stale"], 2);
    // A real run needs the dry run's count; 2 of 10 is above the 1% default cap, so it also needs force.
    let no_expect = admin_post(&env, "/reconcile?bucket=data").await;
    assert!(no_expect["error"].as_str().unwrap().contains("dry_run"), "{no_expect}");
    let wrong = admin_post(&env, "/reconcile?bucket=data&expect=3&force=1").await;
    assert!(wrong["error"].as_str().unwrap().contains("does not match"), "{wrong}");
    let capped = admin_post(&env, "/reconcile?bucket=data&expect=2").await;
    assert!(capped["error"].as_str().unwrap().contains("cap"), "{capped}");
    assert!(idx.get("data", "f/005").unwrap().is_some(), "nothing removed by a refused run");
    let rec = admin_post(&env, "/reconcile?bucket=data&expect=2&force=1").await;
    assert_eq!(rec["removed"], 2);
    assert_eq!(rec["checked"], 10);
    assert_eq!(
        http_status(
            &env.rw
                .get_object()
                .bucket("data")
                .key("f/005")
                .send()
                .await
                .unwrap_err()
        ),
        404
    );
    assert_eq!(
        get_all(&env.rw, "data", "f/006", None).await.unwrap(),
        b"changed on the old store"
    );
    assert_eq!(
        get_all(&env.rw, "data", "f/001", None).await.unwrap(),
        b"live",
        "client writes untouched"
    );
    assert_eq!(
        idx.get("data", "f/002").unwrap().unwrap().state,
        TOMBSTONE,
        "tombstones untouched"
    );
    let again = admin_post(&env, "/reconcile?bucket=data&expect=0").await;
    assert_eq!(again["removed"], 0);
    let status = admin_get(&env, "/status").await;
    assert_eq!(status["locked"], false);
    env.running.unwrap().shutdown().await;
}

/// Temporary prefixes (`fill.skip_prefixes`): the fill never copies them, reconcile ignores them (the ST1-b case:
/// 13 leftover `.sessions/` objects among real chunks must not trip the 1% cap), real mismatches above
/// the cap still stop it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconcile_and_fill_skip_temporary_prefixes() {
    let env = setup().await;
    let put = |k: String, body: Vec<u8>| {
        let c = env.legacy.clone();
        async move {
            c.put_object().bucket("legacy").key(k).body(ByteStream::from(body)).send().await.unwrap();
        }
    };
    for i in 0..100 {
        put(format!("audio/a/{i:06}.opus"), data(200 + i, i as u8)).await;
    }
    let mut temp: Vec<String> = (0..13).map(|i| format!(".sessions/up{i:02}")).collect();
    temp.push(".staging/up00".into());
    for k in &temp {
        put(k.clone(), data(50, 1)).await;
    }
    put(".sessions/never-read".into(), data(50, 2)).await;
    // The temp objects were filled before the skip existed: a read-through creates the same filled rows.
    for k in &temp {
        get_all(&env.rw, "data", k, None).await.unwrap();
    }
    wait_promotions(env.vault()).await;
    let idx = tidx(env.vault(), "data");
    assert_eq!(idx.get("data", &temp[0]).unwrap().unwrap().origin, 1);
    admin_post(&env, "/fill/start?bucket=data").await;
    wait_fill_idle(&env).await;
    let st = admin_get(&env, "/fill").await;
    assert_eq!(st[0]["total"]["finished"], true);
    assert_eq!(st[0]["total"]["copied"].as_u64().unwrap(), 100, "{st}");
    assert_eq!(st[0]["session_skipped_temp"].as_u64().unwrap(), 15, "{st}");
    assert!(idx.get("data", ".sessions/never-read").unwrap().is_none(), "temp object not copied");
    // The core's sweep removed the sessions on the old store: 14 stale temp rows, 0 stale real rows.
    for k in &temp {
        env.legacy.delete_object().bucket("legacy").key(k).send().await.unwrap();
    }
    let dry = admin_post(&env, "/reconcile?bucket=data&dry_run=1").await;
    assert_eq!((dry["checked"].as_u64(), dry["skipped_temp"].as_u64(), dry["stale"].as_u64()),
        (Some(100), Some(14), Some(0)), "{dry}");
    let rec = admin_post(&env, "/reconcile?bucket=data&expect=0").await;
    assert_eq!(rec["removed"], 0, "passes without force: {rec}");
    assert!(idx.get("data", &temp[0]).unwrap().is_some(), "temp rows ignored, not removed");
    // Real mismatches above 1% still stop it.
    for i in [3, 7] {
        env.legacy.delete_object().bucket("legacy").key(format!("audio/a/{i:06}.opus")).send().await.unwrap();
    }
    let dry = admin_post(&env, "/reconcile?bucket=data&dry_run=1").await;
    assert_eq!((dry["stale"].as_u64(), dry["skipped_temp"].as_u64()), (Some(2), Some(14)), "{dry}");
    let capped = admin_post(&env, "/reconcile?bucket=data&expect=2").await;
    assert!(capped["error"].as_str().unwrap().contains("cap"), "{capped}");
    let rec = admin_post(&env, "/reconcile?bucket=data&expect=2&force=1").await;
    assert_eq!(rec["removed"], 2);
    env.running.unwrap().shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn locked_without_key_service_returns_503() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let store = start_fs_s3(&dir.join("store"), None).await;
    let fallback = start_fs_s3(&dir.join("fallback"), None).await;
    write(
        &dir.join("backend.toml"),
        &format!("access_key_id = \"{AK}\"\nsecret_access_key = \"{SK}\"\n"),
    );
    write(&dir.join("app.secret"), "app-secret\n");
    write(&dir.join("reader.secret"), "reader-secret\n");
    write(
        &dir.join("psk"),
        &s3vault_format::keyproto::generate_psk_text(),
    );
    write(&dir.join("admin.token"), &format!("{ADMIN_TOKEN}\n"));
    // a key service that is not running
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let keys = format!(
        "source = \"keyd\"\nkeyd_addr = \"{dead_addr}\"\npsk_file = \"{}\"",
        dir.join("psk").display()
    );
    let cfg: Config = toml::from_str(&config_text(&dir, store.addr, fallback.addr, &keys)).unwrap();
    let running = s3vault::start(cfg).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(running.vault.is_locked());
    let c = client(
        &format!("http://{}", running.s3_addrs[0]),
        "APPKEY",
        "app-secret",
    );
    assert_eq!(
        http_status(
            &c.get_object()
                .bucket("data")
                .key("k")
                .send()
                .await
                .unwrap_err()
        ),
        503
    );
    assert_eq!(
        http_status(
            &c.put_object()
                .bucket("data")
                .key("k")
                .body(ByteStream::from_static(b"x"))
                .send()
                .await
                .unwrap_err()
        ),
        503
    );
    assert_eq!(
        http_status(&c.list_objects_v2().bucket("data").send().await.unwrap_err()),
        503
    );

    // Now the key service comes up on that address with the right PSK: the vault unlocks by itself.
    let (m, t) = test_keys(&["t1", "t2"]);
    let kr_text = format!("%master\n{m}%tenants\n{t}%ledger\n");
    let psk =
        s3vault_format::keyproto::parse_psk(&std::fs::read_to_string(dir.join("psk")).unwrap())
            .unwrap();
    let l = std::net::TcpListener::bind(dead_addr).unwrap();
    let kt = kr_text.to_string();
    std::thread::spawn(move || {
        for s in l.incoming().take(5) {
            let mut s = s.unwrap();
            let _ = s3vault_format::keyproto::server_serve(&mut s, &psk, kt.as_bytes());
        }
    });
    running.wake.notify_one();
    wait_unlocked(&running).await;
    c.create_bucket().bucket("cipher").send().await.ok();
    client(&format!("http://{}", store.addr), AK, SK)
        .create_bucket()
        .bucket("cipher")
        .send()
        .await
        .unwrap();
    c.put_object()
        .bucket("plain")
        .key("k")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap();
    assert_eq!(get_all(&c, "plain", "k", None).await.unwrap(), b"x");
    running.shutdown().await;
    drop(fallback);
}

async fn admin_status_code(env: &Env, path: &str, token: Option<&str>) -> u16 {
    let mut r = reqwest::Client::new().get(format!("{}{path}", env.admin()));
    if let Some(t) = token {
        r = r.bearer_auth(t);
    }
    r.send().await.unwrap().status().as_u16()
}

/// Wait until no promotion (promote on read) is queued or in flight.
async fn wait_promotions(v: &s3vault::vault::Vault) {
    for _ in 0..400 {
        if v.promoter.idle() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("promotions did not finish");
}

async fn wait_fill_idle(env: &Env) {
    for _ in 0..200 {
        let st = admin_get(env, "/fill").await;
        if st[0]["running"] == false {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("fill did not finish");
}

/// H3: every admin call needs the bearer token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_api_requires_token() {
    let env = setup().await;
    assert_eq!(admin_status_code(&env, "/status", None).await, 401);
    assert_eq!(admin_status_code(&env, "/status", Some("wrong")).await, 401);
    assert_eq!(
        admin_status_code(&env, "/status", Some(&ADMIN_TOKEN[..ADMIN_TOKEN.len() - 1])).await,
        401
    );
    assert_eq!(admin_status_code(&env, "/status", Some(ADMIN_TOKEN)).await, 200);
    // The manifest lists index rows only (never the fallback).
    env.rw
        .put_object()
        .bucket("data")
        .key("m/1")
        .body(ByteStream::from_static(b"m1"))
        .send()
        .await
        .unwrap();
    env.legacy
        .put_object()
        .bucket("legacy")
        .key("m/0-unfilled")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap();
    let m = admin_get(&env, "/manifest?bucket=data").await;
    assert_eq!(m["items"].as_array().unwrap().len(), 1, "{m}");
    assert_eq!(m["items"][0]["key"], "m/1");
    assert_eq!(
        m["items"][0]["sha256"],
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b"m1"))
    );
    assert_eq!(admin_status_code(&env, "/manifest?bucket=data", None).await, 401);
    let r = reqwest::Client::new()
        .post(format!("{}/reconcile?bucket=data&expect=0&force=1", env.admin()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401, "unauthenticated reconcile refused");
    // A non-loopback admin listener or a missing token file is a config error.
    let mut cfg = env.cfg.clone();
    cfg.server.admin_listen = Some("0.0.0.0:9101".into());
    assert!(cfg.validate().is_err());
    let mut cfg = env.cfg.clone();
    cfg.server.admin_token_file = None;
    assert!(cfg.validate().is_err());
    env.running.unwrap().shutdown().await;
}

/// H3: reconcile never removes filled copies because the fallback lists empty, is unreachable or retired.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconcile_refuses_empty_unreachable_or_retired_fallback() {
    let mut env = setup().await;
    for i in 0..6 {
        env.legacy
            .put_object()
            .bucket("legacy")
            .key(format!("r/{i}"))
            .body(ByteStream::from(data(100 + i, i as u8)))
            .send()
            .await
            .unwrap();
    }
    admin_post(&env, "/fill/start?bucket=data").await;
    wait_fill_idle(&env).await;
    let idx = tidx(env.vault(), "data");
    assert_eq!(idx.counts("data").unwrap().0, 6);

    // Empty fallback (retired, re-created or the wrong bucket): refused, nothing removed.
    for i in 0..6 {
        env.legacy
            .delete_object()
            .bucket("legacy")
            .key(format!("r/{i}"))
            .send()
            .await
            .unwrap();
    }
    let dry = admin_post(&env, "/reconcile?bucket=data&dry_run=1").await;
    assert!(dry["error"].as_str().unwrap().contains("lists no objects"), "{dry}");
    let real = admin_post(&env, "/reconcile?bucket=data&expect=6&force=1").await;
    assert!(real["error"].as_str().unwrap().contains("lists no objects"), "{real}");
    assert_eq!(idx.counts("data").unwrap().0, 6, "no filled row removed");

    // Unreachable fallback: an error, never "deleted".
    env.legacy
        .put_object()
        .bucket("legacy")
        .key("r/0")
        .body(ByteStream::from(data(100, 0)))
        .send()
        .await
        .unwrap();
    env.fallback.kill();
    let down = admin_post(&env, "/reconcile?bucket=data&dry_run=1").await;
    assert!(down["error"].is_string(), "{down}");
    let down = admin_post(&env, "/reconcile?bucket=data&expect=5&force=1").await;
    assert!(down["error"].is_string(), "{down}");
    assert_eq!(idx.counts("data").unwrap().0, 6);

    // Back up with one object: 5 of 6 gone is far above the cap; only force plus the exact count removes.
    env.fallback = start_fs_s3(&env.dir.join("fallback"), Some(env.fallback.addr)).await;
    let dry = admin_post(&env, "/reconcile?bucket=data&dry_run=1").await;
    assert_eq!(dry["stale"], 5, "{dry}");
    assert_eq!(dry["removed"], 0);
    let capped = admin_post(&env, "/reconcile?bucket=data&expect=5").await;
    assert!(capped["error"].as_str().unwrap().contains("cap"), "{capped}");
    assert_eq!(idx.counts("data").unwrap().0, 6);

    // A fallback marked retired: fill and reconcile refuse outright.
    let mut cfg = env.cfg.clone();
    cfg.buckets[0].fallback.as_mut().unwrap().retired = true;
    cfg.server.listen = vec![];
    cfg.server.admin_listen = None;
    cfg.server.data_dir = env.dir.join("retired-data");
    let v = s3vault::vault::Vault::new(cfg).unwrap();
    v.unlock(bundle(&env)).unwrap();
    let e = s3vault::background::reconcile(
        v.clone(),
        "data",
        s3vault::background::ReconcileOpts {
            dry_run: true,
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(e.to_string().contains("retired"), "{e}");
    let fills = std::sync::Arc::new(s3vault::background::Fills::default());
    assert!(fills.start(v, "data", None, 1000, 1, false).unwrap_err().contains("retired"));
    env.running.take().unwrap().shutdown().await;
}

/// H2 in format v2: an unescrowed master root is refused; KEK rotation is deterministic, so it needs no
/// new escrow, writes under the new generation and keeps old objects readable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotation_escrow_gate_in_proxy() {
    let env = setup().await;
    let open = |master: &str, sub: &str| {
        let mut cfg = env.cfg.clone();
        cfg.server.listen = vec![];
        cfg.server.admin_listen = None;
        cfg.server.data_dir = env.dir.join(sub);
        let v = s3vault::vault::Vault::new(cfg).unwrap();
        let mut b = bundle(&env);
        b.master = MasterV2::parse(master).unwrap();
        (v.clone(), v.unlock(b))
    };
    let text = std::fs::read_to_string(&env.keyring_path).unwrap();
    let unescrowed: String = text
        .lines()
        .filter(|l| !l.starts_with("escrow "))
        .map(|l| format!("{l}\n"))
        .collect();
    let (_, r) = open(&unescrowed, "gate-a");
    assert!(r.unwrap_err().to_string().contains("escrow"), "unescrowed root refused");
    let put = |v: Arc<s3vault::vault::Vault>, key: &'static str| async move {
        let body: s3vault::remote::ByteStream =
            Box::pin(futures::stream::once(async { Ok(bytes::Bytes::from_static(b"x")) }));
        v.put("plain", key, body, Default::default()).await.unwrap();
        tidx(&v, "plain").get("plain", key).unwrap().unwrap().kid
    };
    let (v1, r) = open(&text, "gate-b");
    r.unwrap();
    assert_eq!(put(v1.clone(), "gen1").await, 1);
    let fp = v1.unlocked().unwrap().master.fingerprint();
    drop(v1);
    let mut m = MasterV2::parse(&text).unwrap();
    assert_eq!(m.rotate(), 2);
    assert!(m.is_escrowed(), "rotation keeps the escrow valid");
    let (v2, r) = open(&m.to_text(), "gate-b");
    r.unwrap();
    assert_eq!(v2.unlocked().unwrap().master.fingerprint(), fp);
    assert_eq!(put(v2.clone(), "gen2").await, 2);
    assert_eq!(s3vault::background::read_all(&v2, "plain", "gen1").await.unwrap(), b"x");
    env.running.unwrap().shutdown().await;
}

// ------------------------------------------------------------------ promote on read

async fn legacy_put(env: &Env, key: &str, body: Vec<u8>) {
    env.legacy
        .put_object()
        .bucket("legacy")
        .key(key)
        .body(ByteStream::from(body))
        .send()
        .await
        .unwrap();
}

async fn legacy_delete(env: &Env, key: &str) {
    env.legacy
        .delete_object()
        .bucket("legacy")
        .key(key)
        .send()
        .await
        .unwrap();
}

fn promote_status(env: &Env) -> s3vault::promote::PromoteStatus {
    env.vault().promoter.status(env.vault())
}

/// Hold promotions back: the bucket's budget goes `secs` seconds into debt at `rate`.
async fn throttle_debt(env: &Env, rate: u64, secs: f64) {
    let th = env.vault().fill_throttle("data").unwrap();
    th.set_rate(rate);
    th.acquire(rate + (rate as f64 * secs) as u64).await;
}

async fn wait_for(what: &str, f: impl Fn() -> bool) {
    for _ in 0..400 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

/// A miss is served from the fallback and promoted in the background; the next read comes from the store
/// (the fallback no longer has the object); a ranged read promotes the whole object; `/status` counts it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn promote_on_read_whole_and_ranged() {
    let env = setup().await;
    let a = data(150_000, 3);
    let b = data(200_000, 4);
    legacy_put(&env, "p/a", a.clone()).await;
    legacy_put(&env, "p/b", b.clone()).await;
    let idx = tidx(env.vault(), "data");
    assert_eq!(get_all(&env.rw, "data", "p/a", None).await.unwrap(), a);
    let r = get_all(&env.rw, "data", "p/b", Some("bytes=1000-1999")).await.unwrap();
    assert_eq!(r, &b[1000..2000]);
    wait_promotions(env.vault()).await;
    let ra = idx.get("data", "p/a").unwrap().unwrap();
    let rb = idx.get("data", "p/b").unwrap().unwrap();
    assert_eq!((ra.state, ra.origin, ra.size), (LIVE, 1, a.len() as u64));
    assert_eq!((rb.state, rb.origin, rb.size), (LIVE, 1, b.len() as u64), "ranged read promoted the whole object");
    use sha2::Digest;
    assert_eq!(rb.sha256, hex::encode(sha2::Sha256::digest(&b)));
    // Gone from the fallback: the second reads can only come from the store.
    legacy_delete(&env, "p/a").await;
    legacy_delete(&env, "p/b").await;
    assert_eq!(get_all(&env.rw, "data", "p/a", None).await.unwrap(), a);
    assert_eq!(get_all(&env.rw, "data", "p/b", None).await.unwrap(), b);
    assert_eq!(
        get_all(&env.rw, "data", "p/b", Some("bytes=150000-150099")).await.unwrap(),
        &b[150_000..150_100]
    );
    let st = admin_get(&env, "/status").await;
    let p = &st["promote"];
    assert_eq!(p["enabled"], true);
    assert_eq!((p["promoted"].as_u64(), p["promoted_bytes"].as_u64()), (Some(2), Some(350_000)), "{p}");
    assert_eq!((p["failed"].as_u64(), p["deferred"].as_u64(), p["queue_depth"].as_u64()), (Some(0), Some(0), Some(0)));
    // The fill skips promoted keys.
    legacy_put(&env, "p/c", data(10, 1)).await;
    admin_post(&env, "/fill/start?bucket=data").await;
    wait_fill_idle(&env).await;
    let f = admin_get(&env, "/fill").await;
    assert_eq!(f[0]["total"]["copied"].as_u64(), Some(1), "{f}");
    env.running.unwrap().shutdown().await;
}

/// A delete before the promotion runs: never promoted. A live write racing the promotion: the live write
/// wins. The fallback down: 503 and nothing queued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn promote_on_read_races_and_outage() {
    let env = setup().await;
    let idx = tidx(env.vault(), "data");
    legacy_put(&env, "r/del", data(3000, 1)).await;
    legacy_put(&env, "r/put", data(3000, 2)).await;
    legacy_put(&env, "r/down", data(3000, 3)).await;
    // About 1.5 s of debt: both promotions wait at the budget.
    throttle_debt(&env, 10_000, 1.5).await;
    get_all(&env.rw, "data", "r/del", None).await.unwrap();
    get_all(&env.rw, "data", "r/put", None).await.unwrap();
    wait_for("both promotions in flight", || promote_status(&env).in_flight == 2).await;
    env.rw.delete_object().bucket("data").key("r/del").send().await.unwrap();
    env.rw
        .put_object()
        .bucket("data")
        .key("r/put")
        .body(ByteStream::from_static(b"live write"))
        .send()
        .await
        .unwrap();
    assert!(!env.vault().promoter.idle(), "the promotions were still waiting");
    wait_promotions(env.vault()).await;
    let st = promote_status(&env);
    assert_eq!((st.promoted, st.skipped_tombstone, st.skipped_exists, st.failed), (0, 1, 1, 0), "{st:?}");
    assert_eq!(idx.get("data", "r/del").unwrap().unwrap().state, TOMBSTONE);
    assert_eq!(
        http_status(&env.rw.get_object().bucket("data").key("r/del").send().await.unwrap_err()),
        404
    );
    let rp = idx.get("data", "r/put").unwrap().unwrap();
    assert_eq!((rp.origin, rp.size), (0, 10));
    assert_eq!(get_all(&env.rw, "data", "r/put", None).await.unwrap(), b"live write");
    // The fallback down: a miss is 503, nothing is queued or written.
    env.vault().fill_throttle("data").unwrap().set_rate(100_000_000);
    env.fallback.kill();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        http_status(&env.rw.get_object().bucket("data").key("r/down").send().await.unwrap_err()),
        503
    );
    let st2 = promote_status(&env);
    assert_eq!(st2.enqueued, st.enqueued);
    assert!(env.vault().promoter.idle());
    assert!(idx.get("data", "r/down").unwrap().is_none());
    env.running.unwrap().shutdown().await;
}

/// A full queue defers the promotion (counted); the background fill copies the key later.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn promote_on_read_full_queue_defers_to_fill() {
    let env = setup_with("promote_queue = 1\npromote_concurrency = 1\n").await;
    let idx = tidx(env.vault(), "data");
    for k in ["q/1", "q/2", "q/3"] {
        legacy_put(&env, k, data(2000, k.len() as u8)).await;
    }
    throttle_debt(&env, 10_000, 1.0).await;
    get_all(&env.rw, "data", "q/1", None).await.unwrap();
    wait_for("q/1 in flight", || promote_status(&env).in_flight == 1).await;
    get_all(&env.rw, "data", "q/2", None).await.unwrap(); // waits in the queue
    assert_eq!(get_all(&env.rw, "data", "q/3", None).await.unwrap(), data(2000, 3), "still served");
    let st = promote_status(&env);
    assert_eq!((st.queue_depth, st.in_flight, st.deferred, st.enqueued), (1, 1, 1, 2), "{st:?}");
    assert_eq!(admin_get(&env, "/status").await["promote"]["deferred"], 1);
    // A second read of a waiting key is not queued twice.
    get_all(&env.rw, "data", "q/2", None).await.unwrap();
    assert_eq!(promote_status(&env).duplicate, 1);
    wait_promotions(env.vault()).await;
    assert_eq!(promote_status(&env).promoted, 2);
    assert!(idx.get("data", "q/3").unwrap().is_none(), "deferred: not promoted");
    admin_post(&env, "/fill/start?bucket=data&rate=100000000").await;
    wait_fill_idle(&env).await;
    let f = admin_get(&env, "/fill").await;
    assert_eq!((f[0]["session_copied"].as_u64(), f[0]["session_skipped"].as_u64()), (Some(1), Some(2)), "{f}");
    assert_eq!(idx.get("data", "q/3").unwrap().unwrap().origin, 1);
    env.running.unwrap().shutdown().await;
}

/// Promotions spend the fill's byte budget, ahead of a running fill: from an empty budget at 20 kB/s three
/// 10 kB promotions take about 1.5 s (not instant) and finish while the throttled fill is early in its pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn promote_on_read_respects_the_fill_budget_with_priority() {
    let env = setup_with("promote_concurrency = 1\n").await;
    for i in 0..10 {
        legacy_put(&env, &format!("a/{i:02}"), data(10_000, i)).await;
    }
    for i in 0..3 {
        legacy_put(&env, &format!("z/{i}"), data(10_000, 50 + i)).await;
    }
    let r = admin_post(&env, "/fill/start?bucket=data&rate=20000&concurrency=1").await;
    assert_eq!(r["started"], "data");
    wait_for("budget set", || env.vault().fill_throttle("data").unwrap().rate() == 20_000).await;
    // Start from an empty budget (it holds up to one second's worth).
    env.vault().fill_throttle("data").unwrap().acquire(20_000).await;
    let t0 = std::time::Instant::now();
    for i in 0..3 {
        get_all(&env.rw, "data", &format!("z/{i}"), None).await.unwrap();
    }
    wait_promotions(env.vault()).await;
    let took = t0.elapsed();
    assert_eq!(promote_status(&env).promoted, 3);
    assert!(took >= Duration::from_millis(1_300), "budget respected: {took:?}");
    assert!(took < Duration::from_millis(4_000), "{took:?}");
    let f = admin_get(&env, "/fill").await;
    assert_eq!(f[0]["running"], true, "{f}");
    assert!(f[0]["session_copied"].as_u64().unwrap() <= 4, "the fill yielded: {f}");
    let st = admin_get(&env, "/status").await;
    assert_eq!(st["buckets"][0]["fill_budget_bytes_per_sec"], 20_000, "{st}");
    admin_post(&env, "/fill/stop?bucket=data").await;
    wait_fill_idle(&env).await;
    env.running.unwrap().shutdown().await;
}

/// `promote_on_read = false`: a miss is only read through (the fill copies it later).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn promote_on_read_off() {
    let env = setup_with("promote_on_read = false\n").await;
    legacy_put(&env, "o/1", data(5000, 1)).await;
    assert_eq!(get_all(&env.rw, "data", "o/1", None).await.unwrap(), data(5000, 1));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(tidx(env.vault(), "data").get("data", "o/1").unwrap().is_none());
    let st = promote_status(&env);
    assert_eq!((st.enabled, st.enqueued), (false, 0));
    env.running.unwrap().shutdown().await;
}
