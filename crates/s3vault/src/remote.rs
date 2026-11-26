//! Minimal S3 client for the store of record and the fallbacks (presigned SigV4 via `rusty-s3`, `reqwest`).

use crate::config::{RemoteCfg, read_credentials};
use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{Stream, StreamExt, TryStreamExt};
use reqwest::{Method, StatusCode};
use rusty_s3::actions::{
    AbortMultipartUpload, CompleteMultipartUpload, CreateMultipartUpload, DeleteObject, GetObject,
    HeadObject, ListObjectsV2, PutObject, S3Action, UploadPart,
};
use rusty_s3::{Bucket, Credentials, UrlStyle};
use std::collections::BTreeMap;
use std::pin::Pin;
use std::time::Duration;

const SIGN_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    #[error("not found")]
    NotFound,
    #[error("unavailable: {0}")]
    Unavailable(String),
}

pub type RResult<T> = std::result::Result<T, RemoteError>;

fn unavailable(e: impl std::fmt::Display) -> RemoteError {
    RemoteError::Unavailable(e.to_string())
}

#[derive(Debug, Clone, Default)]
pub struct RemoteMeta {
    pub size: u64,
    pub etag: String,
    pub last_modified_ms: Option<i64>,
    pub content_type: Option<String>,
    /// `x-amz-meta-*` (names without the prefix) and `:cache-control` style system headers.
    pub meta: BTreeMap<String, String>,
    /// Total object size from `Content-Range`, for ranged GETs.
    pub total_size: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ListItem {
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub last_modified_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ListPage {
    pub items: Vec<ListItem>,
    pub prefixes: Vec<String>,
    pub next_token: Option<String>,
}

pub type ByteStream = Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send>>;

pub struct Remote {
    pub label: String,
    bucket: Bucket,
    creds: Credentials,
    http: reqwest::Client,
    pub prefix: String,
    retry: RetryPolicy,
}

impl std::fmt::Debug for Remote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Remote({} {})", self.label, self.bucket.base_url())
    }
}

pub const STORED_SYSTEM_HEADERS: [&str; 5] = [
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "expires",
];

fn parse_meta(headers: &reqwest::header::HeaderMap) -> RemoteMeta {
    let get = |n: &str| {
        headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let mut meta = BTreeMap::new();
    for (k, v) in headers {
        if let Some(name) = k.as_str().strip_prefix("x-amz-meta-")
            && let Ok(v) = v.to_str()
        {
            meta.insert(name.to_string(), v.to_string());
        }
    }
    for h in STORED_SYSTEM_HEADERS {
        if let Some(v) = get(h) {
            meta.insert(format!(":{h}"), v);
        }
    }
    let total_size =
        get("content-range").and_then(|cr| cr.rsplit('/').next().and_then(|t| t.parse().ok()));
    RemoteMeta {
        size: get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        etag: get("etag")
            .map(|e| e.trim_matches('"').to_string())
            .unwrap_or_default(),
        last_modified_ms: get("last-modified")
            .and_then(|v| httpdate::parse_http_date(&v).ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64),
        content_type: get("content-type"),
        meta,
        total_size,
    }
}

fn parse_iso_ms(s: &str) -> Option<i64> {
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    Some((t.unix_timestamp_nanos() / 1_000_000) as i64)
}

async fn check(resp: reqwest::Response) -> RResult<reqwest::Response> {
    match resp.status() {
        s if s.is_success() => Ok(resp),
        StatusCode::NOT_FOUND => Err(RemoteError::NotFound),
        s => {
            let body = resp.text().await.unwrap_or_default();
            let code = body
                .split("<Code>")
                .nth(1)
                .and_then(|r| r.split("</Code>").next())
                .unwrap_or("")
                .to_string();
            Err(RemoteError::Unavailable(format!("HTTP {s} {code}")))
        }
    }
}

/// Whether repeating a request can change the outcome beyond what one successful request does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Idempotency {
    /// GET, HEAD, LIST, DELETE, PUT of a whole buffered object, upload of part N, complete and abort of
    /// a multipart upload: a repeat writes the same thing again (or finds it already done).
    Safe,
    /// Create multipart upload: a repeat after a lost answer leaves an orphan upload. Retried only when
    /// the store certainly did not process the request.
    Unsafe,
}

/// Bounded exponential backoff with jitter.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub attempts: u32,
    pub base: Duration,
    pub max: Duration,
}

impl RetryPolicy {
    pub fn from_cfg(cfg: &RemoteCfg) -> RetryPolicy {
        RetryPolicy {
            attempts: cfg.retry_attempts.max(1),
            base: Duration::from_millis(cfg.retry_base_ms),
            max: Duration::from_millis(cfg.retry_max_ms.max(cfg.retry_base_ms)),
        }
    }

    /// Delay after failed attempt `attempt` (1-based): a random value in [cap/2, cap] with
    /// cap = min(max, base * 2^(attempt-1)); at least `retry_after` (capped at `max`) when the store sent one.
    pub fn delay(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        use rand::Rng;
        let exp = self
            .base
            .saturating_mul(1u32.checked_shl(attempt.saturating_sub(1).min(20)).unwrap_or(u32::MAX));
        let cap = exp.min(self.max);
        let half = cap / 2;
        let jitter = if cap > half {
            rand::thread_rng().gen_range(half..=cap)
        } else {
            cap
        };
        match retry_after {
            Some(ra) => jitter.max(ra.min(self.max)),
            None => jitter,
        }
    }
}

/// Statuses worth another attempt. 408/429/503 mean the request was refused before it was processed;
/// 500/502/504 may have been processed, so only idempotent requests repeat them.
pub fn retryable_status(s: StatusCode, idem: Idempotency) -> bool {
    match s.as_u16() {
        408 | 429 | 503 => true,
        500 | 502 | 504 => idem == Idempotency::Safe,
        _ => false,
    }
}

fn retryable_transport(e: &reqwest::Error, idem: Idempotency) -> bool {
    match idem {
        // Timeouts, resets, broken connections: the request may or may not have arrived.
        Idempotency::Safe => e.is_connect() || e.is_timeout() || e.is_request() || e.is_body(),
        // Only a failed connect proves the store never saw the request.
        Idempotency::Unsafe => e.is_connect(),
    }
}

fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let v = headers.get("retry-after")?.to_str().ok()?.trim();
    if let Ok(secs) = v.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let t = httpdate::parse_http_date(v).ok()?;
    Some(t.duration_since(std::time::SystemTime::now()).unwrap_or_default())
}

/// AWS-style multipart ETag: MD5 of the concatenated binary part MD5s, then `-<parts>`.
fn multipart_etag(part_etags: &[String]) -> Option<String> {
    use md5::Digest;
    let mut h = md5::Md5::new();
    for e in part_etags {
        h.update(hex::decode(e.trim_matches('"')).ok()?);
    }
    Some(format!("{}-{}", hex::encode(h.finalize()), part_etags.len()))
}

impl Remote {
    pub fn from_cfg(label: &str, cfg: &RemoteCfg, bucket_override: Option<&str>) -> Result<Remote> {
        let creds = read_credentials(&cfg.credentials_file)?;
        let name = bucket_override
            .map(str::to_string)
            .or_else(|| cfg.bucket.clone())
            .context("bucket name")?;
        let endpoint = cfg
            .endpoint
            .parse()
            .with_context(|| format!("{label}: endpoint"))?;
        let bucket = Bucket::new(endpoint, UrlStyle::Path, name, cfg.region.clone())
            .with_context(|| format!("{label}: bucket"))?;
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(cfg.connect_timeout_secs))
            .read_timeout(Duration::from_secs(cfg.read_timeout_secs))
            .pool_max_idle_per_host(32)
            .build()?;
        Ok(Remote {
            label: label.to_string(),
            bucket,
            creds: Credentials::new(creds.access_key_id, creds.secret_access_key),
            http,
            prefix: cfg.prefix.clone(),
            retry: RetryPolicy::from_cfg(cfg),
        })
    }

    pub fn bucket_name(&self) -> &str {
        self.bucket.name()
    }

    /// Send a request built by `mk` (called again for every attempt, so each is freshly signed and has a
    /// fresh body), retrying per [`RetryPolicy`] and [`Idempotency`]. Returns the checked response and the
    /// number of attempts made.
    async fn send(
        &self,
        op: &'static str,
        idem: Idempotency,
        mk: impl Fn() -> reqwest::RequestBuilder,
    ) -> (RResult<reqwest::Response>, u32) {
        let mut attempt = 1;
        loop {
            let last = attempt >= self.retry.attempts;
            let (err, ra) = match mk().send().await {
                Ok(resp) => {
                    if last || !retryable_status(resp.status(), idem) {
                        return (check(resp).await, attempt);
                    }
                    let ra = retry_after(resp.headers());
                    match check(resp).await {
                        Ok(r) => return (Ok(r), attempt),
                        Err(e) => (e, ra),
                    }
                }
                Err(e) => {
                    if last || !retryable_transport(&e, idem) {
                        return (Err(unavailable(e)), attempt);
                    }
                    // Without the URL: it carries a presigned query.
                    (unavailable(e.without_url()), None)
                }
            };
            let d = self.retry.delay(attempt, ra);
            tracing::warn!(
                store = %self.label,
                op,
                attempt,
                of = self.retry.attempts,
                delay_ms = d.as_millis() as u64,
                "store request failed, retrying: {err}"
            );
            tokio::time::sleep(d).await;
            attempt += 1;
        }
    }

    pub async fn head(&self, key: &str) -> RResult<RemoteMeta> {
        let resp = self
            .send("head", Idempotency::Safe, || {
                let url = HeadObject::new(&self.bucket, Some(&self.creds), key).sign(SIGN_TTL);
                self.http.head(url)
            })
            .await
            .0?;
        Ok(parse_meta(resp.headers()))
    }

    /// GET with an optional inclusive byte range; returns the metadata and a byte stream. Getting the
    /// answer is retried; an error in the middle of the body stream is not (the caller sees it).
    pub async fn get_stream(
        &self,
        key: &str,
        range: Option<(u64, u64)>,
    ) -> RResult<(RemoteMeta, ByteStream)> {
        let resp = self
            .send("get", Idempotency::Safe, || {
                let url = GetObject::new(&self.bucket, Some(&self.creds), key).sign(SIGN_TTL);
                let mut req = self.http.get(url);
                if let Some((s, e)) = range {
                    req = req.header("range", format!("bytes={s}-{e}"));
                }
                req
            })
            .await
            .0?;
        if range.is_some() && resp.status() != StatusCode::PARTIAL_CONTENT {
            // A store that ignores Range would make us decrypt the wrong bytes; treat as an error.
            if resp.status() != StatusCode::OK {
                return Err(unavailable(format!("unexpected status {}", resp.status())));
            }
        }
        let meta = parse_meta(resp.headers());
        let ranged_ok = resp.status() == StatusCode::PARTIAL_CONTENT;
        let stream = resp.bytes_stream().map_err(std::io::Error::other);
        let stream: ByteStream = if range.is_some() && !ranged_ok {
            // Whole object returned: cut the requested window ourselves.
            let (s, e) = range.unwrap();
            Box::pin(crate::streams::window(stream, s, e - s + 1))
        } else {
            Box::pin(stream)
        };
        Ok((meta, stream))
    }

    pub async fn get_bytes(
        &self,
        key: &str,
        range: Option<(u64, u64)>,
    ) -> RResult<(RemoteMeta, Bytes)> {
        let (meta, mut s) = self.get_stream(key, range).await?;
        let mut buf = Vec::new();
        while let Some(c) = s.next().await {
            buf.extend_from_slice(&c.map_err(unavailable)?);
        }
        Ok((meta, Bytes::from(buf)))
    }

    /// PUT from a stream: one attempt only (a stream cannot be replayed). The proxy's own uploads use
    /// [`Remote::put_bytes`].
    pub async fn put(&self, key: &str, body: reqwest::Body, len: u64) -> RResult<()> {
        let url = PutObject::new(&self.bucket, Some(&self.creds), key).sign(SIGN_TTL);
        let resp = self
            .http
            .request(Method::PUT, url)
            .header("content-length", len)
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
            .await
            .map_err(unavailable)?;
        check(resp).await.map(|_| ())
    }

    /// PUT of a whole object held in memory, retried (a repeat writes the same bytes under the same name).
    pub async fn put_bytes(&self, key: &str, body: Bytes) -> RResult<()> {
        self.send("put", Idempotency::Safe, || {
            let url = PutObject::new(&self.bucket, Some(&self.creds), key).sign(SIGN_TTL);
            self.http
                .request(Method::PUT, url)
                .header("content-length", body.len())
                .header("content-type", "application/octet-stream")
                .body(body.clone())
        })
        .await
        .0
        .map(|_| ())
    }

    pub async fn delete(&self, key: &str) -> RResult<()> {
        let res = self
            .send("delete", Idempotency::Safe, || {
                let url = DeleteObject::new(&self.bucket, Some(&self.creds), key).sign(SIGN_TTL);
                self.http.delete(url)
            })
            .await
            .0;
        match res {
            Ok(_) | Err(RemoteError::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub async fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        token: Option<&str>,
        max: usize,
    ) -> RResult<ListPage> {
        let resp = self
            .send("list", Idempotency::Safe, || {
                let mut action = ListObjectsV2::new(&self.bucket, Some(&self.creds));
                if !prefix.is_empty() {
                    action.with_prefix(prefix);
                }
                if let Some(sa) = start_after.filter(|s| !s.is_empty()) {
                    action.with_start_after(sa);
                }
                if let Some(t) = token {
                    action.with_continuation_token(t);
                }
                action.with_max_keys(max);
                self.http.get(action.sign(SIGN_TTL))
            })
            .await
            .0?;
        let text = resp.text().await.map_err(unavailable)?;
        let parsed = ListObjectsV2::parse_response(&text)
            .map_err(|e| unavailable(format!("list xml: {e}")))?;
        Ok(ListPage {
            items: parsed
                .contents
                .into_iter()
                .map(|c| ListItem {
                    size: c.size.unwrap_or(0),
                    etag: c.etag.unwrap_or_default().trim_matches('"').to_string(),
                    last_modified_ms: c.last_modified.as_deref().and_then(parse_iso_ms),
                    key: c.key,
                })
                .collect(),
            prefixes: parsed
                .common_prefixes
                .into_iter()
                .map(|p| p.prefix)
                .collect(),
            next_token: parsed.next_continuation_token,
        })
    }

    pub async fn mp_create(&self, key: &str) -> RResult<String> {
        let resp = self
            .send("mp_create", Idempotency::Unsafe, || {
                let url =
                    CreateMultipartUpload::new(&self.bucket, Some(&self.creds), key).sign(SIGN_TTL);
                self.http.post(url)
            })
            .await
            .0?;
        let text = resp.text().await.map_err(unavailable)?;
        let parsed = CreateMultipartUpload::parse_response(&text)
            .map_err(|e| unavailable(format!("xml: {e}")))?;
        Ok(parsed.upload_id().to_string())
    }

    /// Upload part `n`, retried: a repeat replaces part `n` of the same upload with the same bytes.
    pub async fn mp_part(
        &self,
        key: &str,
        upload_id: &str,
        n: u16,
        body: Bytes,
    ) -> RResult<String> {
        let resp = self
            .send("mp_part", Idempotency::Safe, || {
                let url = UploadPart::new(&self.bucket, Some(&self.creds), key, n, upload_id)
                    .sign(SIGN_TTL);
                self.http
                    .put(url)
                    .header("content-length", body.len())
                    .body(body.clone())
            })
            .await
            .0?;
        Ok(resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string())
    }

    /// Complete a multipart upload of `total` bytes, retried. A repeat after a lost answer finds the
    /// upload gone (404 NoSuchUpload): then the object is checked with a HEAD (size, and the multipart
    /// ETag when the store reports one) and the completion counts as done if it matches. A 200 answer
    /// with an error body (S3 sends those for failures after the headers) is retried too.
    pub async fn mp_complete(
        &self,
        key: &str,
        upload_id: &str,
        etags: &[String],
        total: u64,
    ) -> RResult<()> {
        let mut tries: u32 = 0;
        loop {
            let (res, attempts) = self
                .send("mp_complete", Idempotency::Safe, || {
                    let action = CompleteMultipartUpload::new(
                        &self.bucket,
                        Some(&self.creds),
                        key,
                        upload_id,
                        etags.iter().map(String::as_str),
                    );
                    let url = action.sign(SIGN_TTL);
                    self.http.post(url).body(action.body())
                })
                .await;
            tries += attempts;
            let err = match res {
                Ok(resp) => match resp.text().await {
                    Ok(text) if !text.contains("<Error>") => return Ok(()),
                    Ok(_) => unavailable("complete multipart returned an error body"),
                    Err(e) => unavailable(e.without_url()),
                },
                Err(RemoteError::NotFound) if tries > 1 => {
                    let m = self.head(key).await?;
                    let etag_ok = !m.etag.contains('-')
                        || multipart_etag(etags).is_none_or(|want| want == m.etag);
                    if m.size == total && etag_ok {
                        tracing::info!(store = %self.label, "mp_complete: done by an earlier attempt");
                        return Ok(());
                    }
                    return Err(unavailable(format!(
                        "complete multipart: upload gone and the object does not match ({} of {total} bytes)",
                        m.size
                    )));
                }
                Err(e) => return Err(e),
            };
            if tries >= self.retry.attempts {
                return Err(err);
            }
            let d = self.retry.delay(tries, None);
            tracing::warn!(store = %self.label, op = "mp_complete", attempt = tries, "retrying: {err}");
            tokio::time::sleep(d).await;
        }
    }

    pub async fn mp_abort(&self, key: &str, upload_id: &str) -> RResult<()> {
        let res = self
            .send("mp_abort", Idempotency::Safe, || {
                let url = AbortMultipartUpload::new(&self.bucket, Some(&self.creds), key, upload_id)
                    .sign(SIGN_TTL);
                self.http.delete(url)
            })
            .await
            .0;
        match res {
            Ok(_) | Err(RemoteError::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// The read side of a store that the rebuild needs. [`Remote`] implements it; the scale drill wraps it to
/// synthesise a listing of millions of names without storing millions of objects.
#[async_trait::async_trait]
pub trait StoreView: Send + Sync {
    async fn list_page(&self, prefix: &str, token: Option<&str>, max: usize) -> RResult<ListPage>;
    async fn get_stream(
        &self,
        key: &str,
        range: Option<(u64, u64)>,
    ) -> RResult<(RemoteMeta, ByteStream)>;
    async fn get_bytes(&self, key: &str, range: Option<(u64, u64)>) -> RResult<Bytes> {
        let (_, mut s) = self.get_stream(key, range).await?;
        let mut buf = Vec::new();
        while let Some(c) = s.next().await {
            buf.extend_from_slice(&c.map_err(unavailable)?);
        }
        Ok(Bytes::from(buf))
    }
}

#[async_trait::async_trait]
impl StoreView for Remote {
    async fn list_page(&self, prefix: &str, token: Option<&str>, max: usize) -> RResult<ListPage> {
        self.list(prefix, None, token, max).await
    }
    async fn get_stream(
        &self,
        key: &str,
        range: Option<(u64, u64)>,
    ) -> RResult<(RemoteMeta, ByteStream)> {
        Remote::get_stream(self, key, range).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// One scripted answer: status, extra headers, body.
    type Answer = (u16, Vec<(&'static str, String)>, String);

    #[derive(Clone, Default)]
    struct Fake {
        script: Arc<Mutex<VecDeque<Answer>>>,
        /// (method, path and query, body length) of every request received.
        seen: Arc<Mutex<Vec<(String, String, usize)>>>,
    }

    impl Fake {
        fn push(&self, status: u16, headers: Vec<(&'static str, String)>, body: &str) {
            self.script
                .lock()
                .unwrap()
                .push_back((status, headers, body.to_string()));
        }
        fn seen(&self) -> Vec<(String, String, usize)> {
            self.seen.lock().unwrap().clone()
        }
    }

    async fn start(fake: Fake, attempts: u32) -> (Remote, tempfile::TempDir) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (sock, _) = listener.accept().await.unwrap();
                let fake = fake.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let fake = fake.clone();
                        async move {
                            use http_body_util::BodyExt;
                            let method = req.method().to_string();
                            let pq = req
                                .uri()
                                .path_and_query()
                                .map(|p| p.to_string())
                                .unwrap_or_default();
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            fake.seen.lock().unwrap().push((method, pq, body.len()));
                            let (status, headers, text) = fake
                                .script
                                .lock()
                                .unwrap()
                                .pop_front()
                                .unwrap_or((200, vec![], String::new()));
                            let mut resp = hyper::Response::builder().status(status);
                            for (k, v) in headers {
                                resp = resp.header(k, v);
                            }
                            Ok::<_, std::convert::Infallible>(
                                resp.body(Full::new(Bytes::from(text))).unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(sock), svc)
                        .await;
                });
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let cred = dir.path().join("cred.toml");
        std::fs::write(&cred, "access_key_id = \"AK\"\nsecret_access_key = \"SK\"\n").unwrap();
        let cfg = RemoteCfg {
            endpoint: format!("http://{addr}"),
            region: "test".into(),
            bucket: Some("b".into()),
            credentials_file: cred,
            prefix: "o/".into(),
            connect_timeout_secs: 2,
            read_timeout_secs: 5,
            retry_attempts: attempts,
            retry_base_ms: 1,
            retry_max_ms: 5,
        };
        (Remote::from_cfg("t", &cfg, None).unwrap(), dir)
    }

    const NO_SUCH_UPLOAD: &str = "<Error><Code>NoSuchUpload</Code></Error>";
    const SLOW_DOWN: &str = "<Error><Code>SlowDown</Code></Error>";

    #[tokio::test]
    async fn get_retries_503_and_500_then_succeeds() {
        let f = Fake::default();
        f.push(503, vec![], SLOW_DOWN);
        f.push(500, vec![], "");
        f.push(200, vec![], "hello");
        let (r, _d) = start(f.clone(), 5).await;
        let (_, body) = r.get_bytes("o/x", None).await.unwrap();
        assert_eq!(&body[..], b"hello");
        assert_eq!(f.seen().len(), 3);
    }

    #[tokio::test]
    async fn client_errors_are_not_retried() {
        let f = Fake::default();
        f.push(403, vec![], "<Error><Code>AccessDenied</Code></Error>");
        let (r, _d) = start(f.clone(), 5).await;
        let e = r.get_bytes("o/x", None).await.unwrap_err();
        assert!(e.to_string().contains("403"), "{e}");
        assert_eq!(f.seen().len(), 1);
        f.push(404, vec![], "");
        assert!(matches!(r.head("o/x").await, Err(RemoteError::NotFound)));
        assert_eq!(f.seen().len(), 2);
    }

    #[tokio::test]
    async fn attempts_are_bounded() {
        let f = Fake::default();
        for _ in 0..10 {
            f.push(503, vec![], SLOW_DOWN);
        }
        let (r, _d) = start(f.clone(), 4).await;
        let e = r.list("o/", None, None, 10).await.unwrap_err();
        assert!(e.to_string().contains("503") && e.to_string().contains("SlowDown"), "{e}");
        assert_eq!(f.seen().len(), 4);
    }

    #[tokio::test]
    async fn put_bytes_retries_429_and_408_with_the_same_body() {
        let f = Fake::default();
        f.push(429, vec![("retry-after", "0".into())], "");
        f.push(408, vec![], "");
        f.push(200, vec![("etag", "\"e\"".into())], "");
        let (r, _d) = start(f.clone(), 5).await;
        r.put_bytes("o/x", Bytes::from(vec![7u8; 1000])).await.unwrap();
        let seen = f.seen();
        assert_eq!(seen.len(), 3);
        assert!(seen.iter().all(|(m, p, n)| m == "PUT" && p.starts_with("/b/o/x") && *n == 1000));
    }

    #[tokio::test]
    async fn create_multipart_repeats_only_unprocessed_requests() {
        let xml = "<InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>b</Bucket><Key>o/x</Key><UploadId>u1</UploadId></InitiateMultipartUploadResult>";
        // 500 may have created an upload: no retry.
        let f = Fake::default();
        f.push(500, vec![], "");
        let (r, _d) = start(f.clone(), 5).await;
        assert!(r.mp_create("o/x").await.is_err());
        assert_eq!(f.seen().len(), 1);
        // 503 and 429 were refused before processing: retried.
        f.push(503, vec![], SLOW_DOWN);
        f.push(429, vec![], "");
        f.push(200, vec![], xml);
        assert_eq!(r.mp_create("o/x").await.unwrap(), "u1");
        assert_eq!(f.seen().len(), 4);
    }

    #[tokio::test]
    async fn parts_are_retried_by_part_number() {
        let f = Fake::default();
        f.push(500, vec![], "");
        f.push(503, vec![], "");
        f.push(200, vec![("etag", "\"abc\"".into())], "");
        let (r, _d) = start(f.clone(), 5).await;
        let etag = r
            .mp_part("o/x", "u1", 3, Bytes::from(vec![1u8; 4096]))
            .await
            .unwrap();
        assert_eq!(etag, "\"abc\"");
        let seen = f.seen();
        assert_eq!(seen.len(), 3);
        for (m, p, n) in seen {
            assert_eq!(m, "PUT");
            assert!(p.contains("partNumber=3") && p.contains("uploadId=u1"), "{p}");
            assert_eq!(n, 4096);
        }
    }

    #[tokio::test]
    async fn complete_after_a_lost_answer_checks_the_object() {
        let parts = vec![
            "\"00112233445566778899aabbccddeeff\"".to_string(),
            "\"ffeeddccbbaa99887766554433221100\"".to_string(),
        ];
        let want = multipart_etag(&parts).unwrap();
        // The first attempt was applied but its answer lost (500); the repeat finds no upload.
        let f = Fake::default();
        f.push(500, vec![], "");
        f.push(404, vec![], NO_SUCH_UPLOAD);
        f.push(
            200,
            vec![("content-length", "12345".into()), ("etag", format!("\"{want}\""))],
            "",
        );
        let (r, _d) = start(f.clone(), 5).await;
        r.mp_complete("o/x", "u1", &parts, 12345).await.unwrap();
        let methods: Vec<String> = f.seen().into_iter().map(|s| s.0).collect();
        assert_eq!(methods, ["POST", "POST", "HEAD"]);

        // Same, but the object in the store is another one: an error, not a silent success.
        f.push(500, vec![], "");
        f.push(404, vec![], NO_SUCH_UPLOAD);
        f.push(200, vec![("content-length", "999".into())], "");
        assert!(r.mp_complete("o/x", "u1", &parts, 12345).await.is_err());

        // A 404 on the first attempt is a real failure (no HEAD).
        let n = f.seen().len();
        f.push(404, vec![], NO_SUCH_UPLOAD);
        assert!(matches!(
            r.mp_complete("o/x", "u1", &parts, 12345).await,
            Err(RemoteError::NotFound)
        ));
        assert_eq!(f.seen().len(), n + 1);

        // A 200 with an error body is retried.
        f.push(200, vec![], "<Error><Code>InternalError</Code></Error>");
        f.push(200, vec![], "<CompleteMultipartUploadResult></CompleteMultipartUploadResult>");
        r.mp_complete("o/x", "u1", &parts, 12345).await.unwrap();
        assert_eq!(f.seen().len(), n + 3);
    }

    #[tokio::test]
    async fn delete_and_abort_retry_and_accept_gone() {
        let f = Fake::default();
        f.push(503, vec![], "");
        f.push(404, vec![], "");
        let (r, _d) = start(f.clone(), 5).await;
        r.delete("o/x").await.unwrap();
        f.push(500, vec![], "");
        f.push(404, vec![], NO_SUCH_UPLOAD);
        r.mp_abort("o/x", "u1").await.unwrap();
        assert_eq!(f.seen().len(), 4);
    }

    #[tokio::test]
    async fn connect_errors_are_retried_up_to_the_bound() {
        // A port with nothing listening: every attempt fails to connect.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let dir = tempfile::tempdir().unwrap();
        let cred = dir.path().join("cred.toml");
        std::fs::write(&cred, "access_key_id = \"AK\"\nsecret_access_key = \"SK\"\n").unwrap();
        let cfg = RemoteCfg {
            endpoint: format!("http://{addr}"),
            region: "test".into(),
            bucket: Some("b".into()),
            credentials_file: cred,
            prefix: "o/".into(),
            connect_timeout_secs: 1,
            read_timeout_secs: 1,
            retry_attempts: 3,
            retry_base_ms: 20,
            retry_max_ms: 20,
        };
        let r = Remote::from_cfg("t", &cfg, None).unwrap();
        let t0 = std::time::Instant::now();
        assert!(r.head("o/x").await.is_err());
        // Two backoffs of 10..=20 ms between three attempts.
        assert!(t0.elapsed() >= Duration::from_millis(20), "{:?}", t0.elapsed());
    }

    #[test]
    fn backoff_is_exponential_jittered_and_capped() {
        let p = RetryPolicy {
            attempts: 6,
            base: Duration::from_millis(100),
            max: Duration::from_millis(1000),
        };
        for _ in 0..200 {
            for (attempt, cap) in [(1, 100), (2, 200), (3, 400), (4, 800), (5, 1000), (40, 1000)] {
                let d = p.delay(attempt, None).as_millis() as u64;
                assert!(d >= cap / 2 && d <= cap, "attempt {attempt}: {d} not in [{}, {cap}]", cap / 2);
            }
        }
        // Retry-After raises the delay but never past the cap.
        assert!(p.delay(1, Some(Duration::from_millis(700))) >= Duration::from_millis(700));
        assert_eq!(p.delay(1, Some(Duration::from_secs(3600))), Duration::from_millis(1000));
        // Jitter actually varies.
        let ds: std::collections::BTreeSet<_> = (0..50).map(|_| p.delay(4, None)).collect();
        assert!(ds.len() > 5);
    }

    #[test]
    fn retryable_statuses() {
        use Idempotency::*;
        for s in [408, 429, 500, 502, 503, 504] {
            assert!(retryable_status(StatusCode::from_u16(s).unwrap(), Safe), "{s}");
        }
        for s in [408, 429, 503] {
            assert!(retryable_status(StatusCode::from_u16(s).unwrap(), Unsafe), "{s}");
        }
        for s in [500, 502, 504] {
            assert!(!retryable_status(StatusCode::from_u16(s).unwrap(), Unsafe), "{s}");
        }
        for s in [400, 401, 403, 404, 409, 412, 416] {
            assert!(!retryable_status(StatusCode::from_u16(s).unwrap(), Safe), "{s}");
        }
    }
}
