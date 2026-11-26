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
        })
    }

    pub fn bucket_name(&self) -> &str {
        self.bucket.name()
    }

    pub async fn head(&self, key: &str) -> RResult<RemoteMeta> {
        let url = HeadObject::new(&self.bucket, Some(&self.creds), key).sign(SIGN_TTL);
        let resp = self.http.head(url).send().await.map_err(unavailable)?;
        let resp = check(resp).await?;
        Ok(parse_meta(resp.headers()))
    }

    /// GET with an optional inclusive byte range; returns the metadata and a byte stream.
    pub async fn get_stream(
        &self,
        key: &str,
        range: Option<(u64, u64)>,
    ) -> RResult<(RemoteMeta, ByteStream)> {
        let url = GetObject::new(&self.bucket, Some(&self.creds), key).sign(SIGN_TTL);
        let mut req = self.http.get(url);
        if let Some((s, e)) = range {
            req = req.header("range", format!("bytes={s}-{e}"));
        }
        let resp = check(req.send().await.map_err(unavailable)?).await?;
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

    pub async fn delete(&self, key: &str) -> RResult<()> {
        let url = DeleteObject::new(&self.bucket, Some(&self.creds), key).sign(SIGN_TTL);
        match check(self.http.delete(url).send().await.map_err(unavailable)?).await {
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
        let url = action.sign(SIGN_TTL);
        let resp = check(self.http.get(url).send().await.map_err(unavailable)?).await?;
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
        let url = CreateMultipartUpload::new(&self.bucket, Some(&self.creds), key).sign(SIGN_TTL);
        let resp = check(self.http.post(url).send().await.map_err(unavailable)?).await?;
        let text = resp.text().await.map_err(unavailable)?;
        let parsed = CreateMultipartUpload::parse_response(&text)
            .map_err(|e| unavailable(format!("xml: {e}")))?;
        Ok(parsed.upload_id().to_string())
    }

    pub async fn mp_part(
        &self,
        key: &str,
        upload_id: &str,
        n: u16,
        body: Bytes,
    ) -> RResult<String> {
        let url =
            UploadPart::new(&self.bucket, Some(&self.creds), key, n, upload_id).sign(SIGN_TTL);
        let len = body.len();
        let resp = self
            .http
            .put(url)
            .header("content-length", len)
            .body(body)
            .send()
            .await
            .map_err(unavailable)?;
        let resp = check(resp).await?;
        Ok(resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string())
    }

    pub async fn mp_complete(&self, key: &str, upload_id: &str, etags: &[String]) -> RResult<()> {
        let action = CompleteMultipartUpload::new(
            &self.bucket,
            Some(&self.creds),
            key,
            upload_id,
            etags.iter().map(String::as_str),
        );
        let url = action.sign(SIGN_TTL);
        let body = action.body();
        let resp = check(
            self.http
                .post(url)
                .body(body)
                .send()
                .await
                .map_err(unavailable)?,
        )
        .await?;
        let text = resp.text().await.map_err(unavailable)?;
        if text.contains("<Error>") {
            return Err(unavailable("complete multipart returned an error body"));
        }
        Ok(())
    }

    pub async fn mp_abort(&self, key: &str, upload_id: &str) -> RResult<()> {
        let url = AbortMultipartUpload::new(&self.bucket, Some(&self.creds), key, upload_id)
            .sign(SIGN_TTL);
        check(self.http.delete(url).send().await.map_err(unavailable)?)
            .await
            .map(|_| ())
    }
}
