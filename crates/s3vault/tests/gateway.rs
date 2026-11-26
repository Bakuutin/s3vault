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
use s3vault_format::keyring::Keyring;
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

[[buckets]]
name = "data"
store = "main"
fallback = {{ source = "legacy", bucket = "legacy" }}

[[buckets]]
name = "plain"
store = "main"

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
"#,
        data = dir.join("data").display(),
        dir = dir.display(),
    )
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
    write(&keyring_path, &Keyring::generate().to_text());
    let keys = format!("source = \"file\"\nfile = \"{}\"", keyring_path.display());
    let cfg: Config = toml::from_str(&config_text(&dir, store.addr, fallback.addr, &keys)).unwrap();
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
        std::fs::read_dir(env.dir.join("data/staging"))
            .unwrap()
            .next()
            .is_none(),
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
    let row = env
        .vault()
        .unlocked()
        .unwrap()
        .index
        .get("plain", "once")
        .unwrap()
        .unwrap();
    let u = env.vault().unlocked().unwrap();
    let name = env
        .vault()
        .store_name(&u, &env.vault().buckets["plain"].store, "plain", "once");
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
    let idx = env.vault().unlocked().unwrap().index.clone();
    assert!(idx.get("data", "rec/a.opus").unwrap().is_none());
    // Merged listing: fallback keys appear
    let l = c.list_objects_v2().bucket("data").send().await.unwrap();
    assert_eq!(l.contents().len(), 3);
    // ranged GET of an unfilled key: served from the fallback and written back encrypted
    let r = get_all(&c, "data", "rec/a.opus", Some("bytes=70000-80000"))
        .await
        .unwrap();
    assert_eq!(r, &old[70000..=80000]);
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
    let kr = Keyring::parse(&std::fs::read_to_string(&env.keyring_path).unwrap()).unwrap();
    let fresh = Index::open(&env.dir.join("rebuilt.db"), Some(&kr.index_db_key())).unwrap();
    let rep = s3vault::background::rebuild(
        env.running.as_ref().unwrap().vault.clone(),
        &kr,
        &fresh,
        false,
        4,
    )
    .await
    .unwrap();
    assert_eq!(rep.errors, 0);
    for (b, k) in [
        ("data", "rec/a.opus"),
        ("data", "rec/b.opus"),
        ("data", "new/x"),
        ("plain", "p"),
    ] {
        let mut a = idx.get(b, k).unwrap().unwrap();
        let mut r = fresh.get(b, k).unwrap().unwrap();
        a.origin = 0;
        r.origin = 0;
        assert_eq!(a, r, "{b}/{k}");
    }
    assert_eq!(fresh.counts("data").unwrap(), idx.counts("data").unwrap());
    // with the wrong keyring nothing is readable
    let other = Keyring::generate();
    let other_idx = Index::open(&env.dir.join("other.db"), Some(&other.index_db_key())).unwrap();
    let rep2 = s3vault::background::rebuild(
        env.running.as_ref().unwrap().vault.clone(),
        &other,
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
    let inc = Index::open(&env.dir.join("inc.db"), Some(&kr.index_db_key())).unwrap();
    let rep3 = s3vault::background::rebuild(
        env.running.as_ref().unwrap().vault.clone(),
        &kr,
        &inc,
        true,
        4,
    )
    .await
    .unwrap();
    assert!(rep3.snapshot_rows >= 4);
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
    let idx = env.vault().unlocked().unwrap().index.clone();
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
    let kr_text = Keyring::generate().to_text();
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
    let idx = env.vault().unlocked().unwrap().index.clone();
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
    v.unlock(Keyring::parse(&std::fs::read_to_string(&env.keyring_path).unwrap()).unwrap())
        .unwrap();
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

/// H2: a rotated key that is not escrowed is never used for writes, even if a keyring marks it active.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotation_escrow_gate_in_proxy() {
    let env = setup().await;
    let mut kr = Keyring::parse(&std::fs::read_to_string(&env.keyring_path).unwrap()).unwrap();
    let fp = kr.fingerprint();
    kr.rotate().unwrap();
    // a hand edit that activates the pending key without an escrow record
    let text = kr.to_text().replace("active 1", "active 2").replace("pending 2\n", "");
    let open = |text: &str, sub: &str| {
        let mut cfg = env.cfg.clone();
        cfg.server.listen = vec![];
        cfg.server.admin_listen = None;
        cfg.server.data_dir = env.dir.join(sub);
        let v = s3vault::vault::Vault::new(cfg).unwrap();
        v.unlock(Keyring::parse(text).unwrap()).unwrap();
        v
    };
    let v = open(&text, "gate-a");
    let put = |v: std::sync::Arc<s3vault::vault::Vault>, key: &'static str| async move {
        let body: s3vault::remote::ByteStream =
            Box::pin(futures::stream::once(async { Ok(bytes::Bytes::from_static(b"x")) }));
        v.put("plain", key, body, Default::default()).await.unwrap();
        v.unlocked().unwrap().index.get("plain", key).unwrap().unwrap().kid
    };
    assert_eq!(put(v.clone(), "before-escrow").await, 1, "unescrowed key 2 not used");
    // After the escrow is confirmed with the copy's digest, key 2 is used; the fingerprint is unchanged.
    kr.confirm_escrow(&kr.escrow_digest(), "owner-mac", 1).unwrap();
    let v2 = open(&kr.to_text(), "gate-b");
    assert_eq!(put(v2.clone(), "after-escrow").await, 2);
    assert_eq!(v2.unlocked().unwrap().keyring.fingerprint(), fp);
    env.running.unwrap().shutdown().await;
}
