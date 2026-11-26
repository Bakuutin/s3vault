//! The S3 wire layer (`s3s`): authentication, per-bucket access, and the mapping of S3 operations onto
//! [`Vault`].

use crate::config::{Config, read_secret_line};
use crate::remote::{ByteStream, STORED_SYSTEM_HEADERS};
use crate::vault::{ObjInfo, PutOpts, Vault, VaultError};
use anyhow::Result;
use data_encoding::{BASE64, BASE64URL_NOPAD};
use futures::StreamExt;
use s3s::access::{S3Access, S3AccessContext};
use s3s::auth::{S3Auth, SecretKey};
use s3s::dto::*;
use s3s::path::S3Path;
use s3s::{S3, S3Error, S3Request, S3Response, S3Result, s3_error};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use sync_wrapper::SyncStream;
use tracing::{error, warn};

// ------------------------------------------------------------------ auth and access

pub struct VaultAuth {
    secrets: HashMap<String, SecretKey>,
}

#[async_trait::async_trait]
impl S3Auth for VaultAuth {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<SecretKey> {
        self.secrets
            .get(access_key)
            .cloned()
            .ok_or_else(|| s3_error!(InvalidAccessKeyId))
    }
}

#[derive(Default, Clone)]
pub struct Perms {
    pub rw: HashSet<String>,
    pub ro: HashSet<String>,
}

impl Perms {
    fn can_read(&self, b: &str) -> bool {
        self.rw.contains(b) || self.ro.contains(b)
    }
}

pub struct Clients {
    pub perms: HashMap<String, Perms>,
}

pub fn load_clients(cfg: &Config) -> Result<(VaultAuth, Arc<Clients>)> {
    let mut secrets = HashMap::new();
    let mut perms = HashMap::new();
    for c in &cfg.clients {
        let secret = read_secret_line(&c.secret_file)?;
        secrets.insert(c.access_key_id.clone(), SecretKey::from(secret));
        perms.insert(
            c.access_key_id.clone(),
            Perms {
                rw: c.buckets.iter().cloned().collect(),
                ro: c.read_buckets.iter().cloned().collect(),
            },
        );
    }
    Ok((VaultAuth { secrets }, Arc::new(Clients { perms })))
}

const READ_OPS: &[&str] = &[
    "GetObject",
    "HeadObject",
    "ListObjects",
    "ListObjectsV2",
    "HeadBucket",
    "GetBucketLocation",
    "ListParts",
    "ListMultipartUploads",
];

pub struct VaultAccess {
    pub clients: Arc<Clients>,
}

#[async_trait::async_trait]
impl S3Access for VaultAccess {
    async fn check(&self, cx: &mut S3AccessContext<'_>) -> S3Result<()> {
        let Some(creds) = cx.credentials() else {
            return Err(s3_error!(AccessDenied, "authentication required"));
        };
        let Some(p) = self.clients.perms.get(&creds.access_key) else {
            return Err(s3_error!(AccessDenied));
        };
        let bucket = match cx.s3_path() {
            S3Path::Root => return Ok(()),
            S3Path::Bucket { bucket } | S3Path::Object { bucket, .. } => bucket,
        };
        let read = READ_OPS.contains(&cx.s3_op().name());
        if p.rw.contains(&**bucket) || (read && p.ro.contains(&**bucket)) {
            Ok(())
        } else {
            Err(s3_error!(AccessDenied, "no access to bucket {bucket}"))
        }
    }
}

// ------------------------------------------------------------------ helpers

fn s3err(e: VaultError) -> S3Error {
    match e {
        VaultError::Locked => s3_error!(
            ServiceUnavailable,
            "vault locked: the key service is unreachable"
        ),
        VaultError::Unavailable(m) => {
            warn!("503: {m}");
            s3_error!(ServiceUnavailable, "{m}")
        }
        VaultError::NoSuchKey => s3_error!(NoSuchKey),
        VaultError::NoSuchBucket => s3_error!(NoSuchBucket),
        VaultError::NoSuchUpload => s3_error!(NoSuchUpload),
        VaultError::PreconditionFailed => s3_error!(PreconditionFailed),
        VaultError::InvalidPart(m) => s3_error!(InvalidPart, "{m}"),
        VaultError::BadDigest => s3_error!(BadDigest),
        VaultError::InvalidRange => s3_error!(InvalidRange),
        VaultError::InvalidRequest(m) => s3_error!(InvalidRequest, "{m}"),
        VaultError::Integrity(m) => {
            error!("integrity: {m}");
            s3_error!(InternalError, "integrity check failed")
        }
        VaultError::Internal(e) => {
            error!("internal: {e:#}");
            s3_error!(InternalError)
        }
    }
}

fn ts(ms: i64) -> Timestamp {
    Timestamp::from(UNIX_EPOCH + Duration::from_millis(ms.max(0) as u64))
}

fn etag(s: &str) -> Option<ETag> {
    (!s.is_empty()).then(|| ETag::Strong(s.to_string()))
}

fn body_in(b: Option<StreamingBlob>) -> ByteStream {
    match b {
        None => Box::pin(futures::stream::empty()),
        Some(b) => Box::pin(b.map(|r| r.map_err(std::io::Error::other))),
    }
}

fn body_out(s: ByteStream) -> StreamingBlob {
    StreamingBlob::wrap(SyncStream::new(s))
}

fn md5_header(v: Option<&String>) -> S3Result<Option<[u8; 16]>> {
    match v {
        None => Ok(None),
        Some(b64) => {
            let raw = BASE64
                .decode(b64.as_bytes())
                .map_err(|_| s3_error!(InvalidDigest))?;
            Ok(Some(raw.try_into().map_err(|_| s3_error!(InvalidDigest))?))
        }
    }
}

struct SysHeaders {
    cache_control: Option<String>,
    content_disposition: Option<String>,
    content_encoding: Option<String>,
    content_language: Option<String>,
    expires: Option<String>,
}

fn build_meta(user: Option<Metadata>, sys: SysHeaders) -> BTreeMap<String, String> {
    let mut m: BTreeMap<String, String> = user
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .collect();
    m.retain(|k, _| !k.starts_with(':'));
    let pairs = [
        ("cache-control", sys.cache_control),
        ("content-disposition", sys.content_disposition),
        ("content-encoding", sys.content_encoding),
        ("content-language", sys.content_language),
        ("expires", sys.expires),
    ];
    for (k, v) in pairs {
        if let Some(v) = v {
            m.insert(format!(":{k}"), v);
        }
    }
    m
}

fn split_meta(info: &ObjInfo) -> (Option<Metadata>, HashMap<&'static str, String>) {
    let mut user = Metadata::new();
    let mut sys = HashMap::new();
    for (k, v) in &info.meta {
        if let Some(h) = k.strip_prefix(':') {
            if let Some(name) = STORED_SYSTEM_HEADERS.iter().find(|n| **n == h) {
                sys.insert(*name, v.clone());
            }
        } else {
            user.insert(k.clone(), v.clone());
        }
    }
    ((!user.is_empty()).then_some(user), sys)
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn decode_token(t: &str) -> S3Result<String> {
    let raw = BASE64URL_NOPAD
        .decode(t.as_bytes())
        .map_err(|_| s3_error!(InvalidArgument, "bad continuation token"))?;
    String::from_utf8(raw).map_err(|_| s3_error!(InvalidArgument, "bad continuation token"))
}

fn encode_token(after: &str) -> String {
    BASE64URL_NOPAD.encode(after.as_bytes())
}

// ------------------------------------------------------------------ S3 impl

pub struct VaultS3 {
    pub vault: Arc<Vault>,
    pub clients: Arc<Clients>,
}

impl VaultS3 {
    fn perms<T>(&self, req: &S3Request<T>) -> Perms {
        req.credentials
            .as_ref()
            .and_then(|c| self.clients.perms.get(&c.access_key))
            .cloned()
            .unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl S3 for VaultS3 {
    async fn list_buckets(
        &self,
        req: S3Request<ListBucketsInput>,
    ) -> S3Result<S3Response<ListBucketsOutput>> {
        let p = self.perms(&req);
        let mut names: Vec<&String> = self
            .vault
            .buckets
            .keys()
            .filter(|b| p.can_read(b))
            .collect();
        names.sort();
        let buckets = names
            .into_iter()
            .map(|n| Bucket {
                name: Some(n.clone()),
                creation_date: Some(ts(self.vault.started_ms)),
                ..Default::default()
            })
            .collect();
        Ok(S3Response::new(ListBucketsOutput {
            buckets: Some(buckets),
            ..Default::default()
        }))
    }

    async fn create_bucket(
        &self,
        req: S3Request<CreateBucketInput>,
    ) -> S3Result<S3Response<CreateBucketOutput>> {
        if self.vault.buckets.contains_key(&req.input.bucket) {
            return Err(s3_error!(BucketAlreadyOwnedByYou));
        }
        Err(s3_error!(
            AccessDenied,
            "buckets are defined in the s3vault configuration"
        ))
    }

    async fn head_bucket(
        &self,
        req: S3Request<HeadBucketInput>,
    ) -> S3Result<S3Response<HeadBucketOutput>> {
        self.vault.bucket(&req.input.bucket).map_err(s3err)?;
        Ok(S3Response::new(HeadBucketOutput::default()))
    }

    async fn get_bucket_location(
        &self,
        req: S3Request<GetBucketLocationInput>,
    ) -> S3Result<S3Response<GetBucketLocationOutput>> {
        self.vault.bucket(&req.input.bucket).map_err(s3err)?;
        let region = &self.vault.cfg.server.region;
        let loc = (region != "us-east-1").then(|| BucketLocationConstraint::from(region.clone()));
        Ok(S3Response::new(GetBucketLocationOutput {
            location_constraint: loc,
        }))
    }

    async fn head_object(
        &self,
        req: S3Request<HeadObjectInput>,
    ) -> S3Result<S3Response<HeadObjectOutput>> {
        let i = req.input;
        let info = self.vault.head(&i.bucket, &i.key).await.map_err(s3err)?;
        let (metadata, sys) = split_meta(&info);
        Ok(S3Response::new(HeadObjectOutput {
            content_length: Some(info.size as i64),
            e_tag: etag(&info.etag),
            last_modified: Some(ts(info.mtime_ms)),
            content_type: info.content_type.clone(),
            metadata,
            cache_control: sys.get("cache-control").cloned(),
            content_disposition: sys.get("content-disposition").cloned(),
            content_encoding: sys.get("content-encoding").cloned(),
            content_language: sys.get("content-language").cloned(),
            accept_ranges: Some("bytes".into()),
            ..Default::default()
        }))
    }

    async fn get_object(
        &self,
        req: S3Request<GetObjectInput>,
    ) -> S3Result<S3Response<GetObjectOutput>> {
        let i = req.input;
        let r = self
            .vault
            .get(&i.bucket, &i.key, i.range)
            .await
            .map_err(s3err)?;
        let (metadata, sys) = split_meta(&r.info);
        let (len, content_range) = match r.range {
            Some((s, e)) => (
                e - s,
                Some(format!("bytes {}-{}/{}", s, e - 1, r.info.size)),
            ),
            None => (r.info.size, None),
        };
        Ok(S3Response::new(GetObjectOutput {
            body: Some(body_out(r.body)),
            content_length: Some(len as i64),
            content_range,
            e_tag: etag(&r.info.etag),
            last_modified: Some(ts(r.info.mtime_ms)),
            content_type: r.info.content_type.clone(),
            metadata,
            cache_control: sys.get("cache-control").cloned(),
            content_disposition: sys.get("content-disposition").cloned(),
            content_encoding: sys.get("content-encoding").cloned(),
            content_language: sys.get("content-language").cloned(),
            accept_ranges: Some("bytes".into()),
            ..Default::default()
        }))
    }

    async fn put_object(
        &self,
        req: S3Request<PutObjectInput>,
    ) -> S3Result<S3Response<PutObjectOutput>> {
        let i = req.input;
        let opts = PutOpts {
            content_md5: md5_header(i.content_md5.as_ref())?,
            create_only: i.if_none_match.as_ref().is_some_and(|c| c.is_any()),
            if_match: i.if_match.as_ref().map(|c| match c.as_etag() {
                Some(e) => e.value().to_string(),
                None => "*".to_string(),
            }),
            content_type: i.content_type.clone(),
            meta: build_meta(
                i.metadata,
                SysHeaders {
                    cache_control: i.cache_control,
                    content_disposition: i.content_disposition,
                    content_encoding: i.content_encoding,
                    content_language: i.content_language,
                    expires: None,
                },
            ),
        };
        if i.if_none_match.as_ref().is_some_and(|c| !c.is_any()) {
            return Err(s3_error!(NotImplemented, "If-None-Match supports only *"));
        }
        let info = self
            .vault
            .put(&i.bucket, &i.key, body_in(i.body), opts)
            .await
            .map_err(s3err)?;
        Ok(S3Response::new(PutObjectOutput {
            e_tag: etag(&info.etag),
            size: Some(info.size as i64),
            ..Default::default()
        }))
    }

    async fn delete_object(
        &self,
        req: S3Request<DeleteObjectInput>,
    ) -> S3Result<S3Response<DeleteObjectOutput>> {
        let i = req.input;
        self.vault.delete(&i.bucket, &i.key).await.map_err(s3err)?;
        Ok(S3Response::new(DeleteObjectOutput::default()))
    }

    async fn delete_objects(
        &self,
        req: S3Request<DeleteObjectsInput>,
    ) -> S3Result<S3Response<DeleteObjectsOutput>> {
        let i = req.input;
        let quiet = i.delete.quiet.unwrap_or(false);
        let mut deleted = Vec::new();
        let mut errors = Vec::new();
        for o in i.delete.objects {
            match self.vault.delete(&i.bucket, &o.key).await {
                Ok(()) => {
                    if !quiet {
                        deleted.push(DeletedObject {
                            key: Some(o.key),
                            ..Default::default()
                        })
                    }
                }
                Err(e) => {
                    let se = s3err(e);
                    errors.push(Error {
                        code: Some(se.code().as_str().to_string()),
                        key: Some(o.key),
                        message: se.message().map(str::to_string),
                        version_id: None,
                    })
                }
            }
        }
        Ok(S3Response::new(DeleteObjectsOutput {
            deleted: (!deleted.is_empty()).then_some(deleted),
            errors: (!errors.is_empty()).then_some(errors),
            ..Default::default()
        }))
    }

    async fn copy_object(
        &self,
        req: S3Request<CopyObjectInput>,
    ) -> S3Result<S3Response<CopyObjectOutput>> {
        let p = self.perms(&req);
        let i = req.input;
        let (sb, sk) = match &i.copy_source {
            CopySource::Bucket {
                bucket,
                key,
                version_id: None,
            } => (bucket.to_string(), key.to_string()),
            CopySource::Bucket { .. } => {
                return Err(s3_error!(NotImplemented, "versioned copy source"));
            }
            _ => return Err(s3_error!(NotImplemented)),
        };
        if !p.can_read(&sb) {
            return Err(s3_error!(
                AccessDenied,
                "no read access to the copy source bucket"
            ));
        }
        let replace = i
            .metadata_directive
            .as_ref()
            .is_some_and(|d| d.as_str() == MetadataDirective::REPLACE);
        let replace = replace.then(|| {
            (
                i.content_type.clone(),
                build_meta(
                    i.metadata.clone(),
                    SysHeaders {
                        cache_control: i.cache_control.clone(),
                        content_disposition: i.content_disposition.clone(),
                        content_encoding: i.content_encoding.clone(),
                        content_language: i.content_language.clone(),
                        expires: None,
                    },
                ),
            )
        });
        let info = self
            .vault
            .copy(&sb, &sk, &i.bucket, &i.key, replace)
            .await
            .map_err(s3err)?;
        Ok(S3Response::new(CopyObjectOutput {
            copy_object_result: Some(CopyObjectResult {
                e_tag: etag(&info.etag),
                last_modified: Some(ts(info.mtime_ms)),
                ..Default::default()
            }),
            ..Default::default()
        }))
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<ListObjectsV2Input>,
    ) -> S3Result<S3Response<ListObjectsV2Output>> {
        let i = req.input;
        let max = i.max_keys.unwrap_or(1000).clamp(0, 1000) as usize;
        let prefix = i.prefix.clone().unwrap_or_default();
        let after = match &i.continuation_token {
            Some(t) => decode_token(t)?,
            None => i.start_after.clone().unwrap_or_default(),
        };
        let r = self
            .vault
            .list(&i.bucket, &prefix, i.delimiter.as_deref(), &after, max)
            .await
            .map_err(s3err)?;
        let enc = i
            .encoding_type
            .as_ref()
            .is_some_and(|e| e.as_str() == EncodingType::URL);
        let k = |s: &str| if enc { url_encode(s) } else { s.to_string() };
        let contents: Vec<Object> = r
            .entries
            .iter()
            .map(|e| Object {
                key: Some(k(&e.key)),
                size: Some(e.size as i64),
                e_tag: etag(&e.etag),
                last_modified: Some(ts(e.mtime_ms)),
                storage_class: Some(ObjectStorageClass::from_static(
                    ObjectStorageClass::STANDARD,
                )),
                ..Default::default()
            })
            .collect();
        let cps: Vec<CommonPrefix> = r
            .prefixes
            .iter()
            .map(|p| CommonPrefix { prefix: Some(k(p)) })
            .collect();
        Ok(S3Response::new(ListObjectsV2Output {
            key_count: Some((contents.len() + cps.len()) as i32),
            max_keys: Some(max as i32),
            is_truncated: Some(r.truncated),
            contents: (!contents.is_empty()).then_some(contents),
            common_prefixes: (!cps.is_empty()).then_some(cps),
            continuation_token: i.continuation_token,
            next_continuation_token: r
                .next_after
                .as_deref()
                .filter(|_| r.truncated)
                .map(encode_token),
            delimiter: i.delimiter.as_deref().map(k),
            encoding_type: i.encoding_type,
            name: Some(i.bucket),
            prefix: Some(k(&prefix)),
            start_after: i.start_after.as_deref().map(k),
            ..Default::default()
        }))
    }

    async fn list_objects(
        &self,
        req: S3Request<ListObjectsInput>,
    ) -> S3Result<S3Response<ListObjectsOutput>> {
        let i = req.input;
        let max = i.max_keys.unwrap_or(1000).clamp(0, 1000) as usize;
        let prefix = i.prefix.clone().unwrap_or_default();
        let marker = i.marker.clone().unwrap_or_default();
        let after = match i.delimiter.as_deref() {
            Some(d)
                if !d.is_empty()
                    && marker.ends_with(d)
                    && marker.starts_with(&prefix)
                    && marker.len() > prefix.len() =>
            {
                format!("{marker}{}", char::MAX)
            }
            _ => marker.clone(),
        };
        let r = self
            .vault
            .list(&i.bucket, &prefix, i.delimiter.as_deref(), &after, max)
            .await
            .map_err(s3err)?;
        let enc = i
            .encoding_type
            .as_ref()
            .is_some_and(|e| e.as_str() == EncodingType::URL);
        let k = |s: &str| if enc { url_encode(s) } else { s.to_string() };
        let contents: Vec<Object> = r
            .entries
            .iter()
            .map(|e| Object {
                key: Some(k(&e.key)),
                size: Some(e.size as i64),
                e_tag: etag(&e.etag),
                last_modified: Some(ts(e.mtime_ms)),
                storage_class: Some(ObjectStorageClass::from_static(
                    ObjectStorageClass::STANDARD,
                )),
                ..Default::default()
            })
            .collect();
        let cps: Vec<CommonPrefix> = r
            .prefixes
            .iter()
            .map(|p| CommonPrefix { prefix: Some(k(p)) })
            .collect();
        Ok(S3Response::new(ListObjectsOutput {
            max_keys: Some(max as i32),
            is_truncated: Some(r.truncated),
            contents: (!contents.is_empty()).then_some(contents),
            common_prefixes: (!cps.is_empty()).then_some(cps),
            marker: i.marker.as_deref().map(k),
            next_marker: r.next_marker.as_deref().filter(|_| r.truncated).map(k),
            delimiter: i.delimiter.as_deref().map(k),
            encoding_type: i.encoding_type,
            name: Some(i.bucket),
            prefix: Some(k(&prefix)),
            ..Default::default()
        }))
    }

    async fn create_multipart_upload(
        &self,
        req: S3Request<CreateMultipartUploadInput>,
    ) -> S3Result<S3Response<CreateMultipartUploadOutput>> {
        let i = req.input;
        let meta = build_meta(
            i.metadata,
            SysHeaders {
                cache_control: i.cache_control,
                content_disposition: i.content_disposition,
                content_encoding: i.content_encoding,
                content_language: i.content_language,
                expires: None,
            },
        );
        let id = self
            .vault
            .create_upload(&i.bucket, &i.key, i.content_type, meta)
            .map_err(s3err)?;
        Ok(S3Response::new(CreateMultipartUploadOutput {
            bucket: Some(i.bucket),
            key: Some(i.key),
            upload_id: Some(id),
            ..Default::default()
        }))
    }

    async fn upload_part(
        &self,
        req: S3Request<UploadPartInput>,
    ) -> S3Result<S3Response<UploadPartOutput>> {
        let i = req.input;
        let md5 = md5_header(i.content_md5.as_ref())?;
        let e = self
            .vault
            .upload_part(
                &i.bucket,
                &i.key,
                &i.upload_id,
                i.part_number,
                body_in(i.body),
                md5,
            )
            .await
            .map_err(s3err)?;
        Ok(S3Response::new(UploadPartOutput {
            e_tag: etag(&e),
            ..Default::default()
        }))
    }

    async fn list_parts(
        &self,
        req: S3Request<ListPartsInput>,
    ) -> S3Result<S3Response<ListPartsOutput>> {
        let i = req.input;
        let marker = i.part_number_marker.unwrap_or(0) as i64;
        let max = i.max_parts.unwrap_or(1000).clamp(1, 1000) as usize;
        let all = self
            .vault
            .list_parts(&i.bucket, &i.key, &i.upload_id)
            .map_err(s3err)?;
        let rest: Vec<_> = all.into_iter().filter(|p| p.part_number > marker).collect();
        let truncated = rest.len() > max;
        let page: Vec<_> = rest.into_iter().take(max).collect();
        let next = page.last().map(|p| p.part_number as i32);
        let parts = page
            .into_iter()
            .map(|p| Part {
                part_number: Some(p.part_number as i32),
                size: Some(p.size as i64),
                e_tag: etag(&p.etag),
                last_modified: Some(ts(p.mtime_ms)),
                ..Default::default()
            })
            .collect();
        Ok(S3Response::new(ListPartsOutput {
            bucket: Some(i.bucket),
            key: Some(i.key),
            upload_id: Some(i.upload_id),
            parts: Some(parts),
            is_truncated: Some(truncated),
            max_parts: Some(max as i32),
            part_number_marker: i.part_number_marker,
            next_part_number_marker: next.filter(|_| truncated),
            ..Default::default()
        }))
    }

    async fn list_multipart_uploads(
        &self,
        req: S3Request<ListMultipartUploadsInput>,
    ) -> S3Result<S3Response<ListMultipartUploadsOutput>> {
        let i = req.input;
        let max = i.max_uploads.unwrap_or(1000).clamp(1, 1000) as usize;
        let prefix = i.prefix.clone().unwrap_or_default();
        let ups = self
            .vault
            .list_uploads(&i.bucket, &prefix, max)
            .map_err(s3err)?;
        let uploads = ups
            .into_iter()
            .map(|u| MultipartUpload {
                key: Some(u.key),
                upload_id: Some(u.upload_id),
                initiated: Some(ts(u.created_ms)),
                ..Default::default()
            })
            .collect();
        Ok(S3Response::new(ListMultipartUploadsOutput {
            bucket: Some(i.bucket),
            uploads: Some(uploads),
            is_truncated: Some(false),
            max_uploads: Some(max as i32),
            prefix: i.prefix,
            ..Default::default()
        }))
    }

    async fn complete_multipart_upload(
        &self,
        req: S3Request<CompleteMultipartUploadInput>,
    ) -> S3Result<S3Response<CompleteMultipartUploadOutput>> {
        let i = req.input;
        let parts: Vec<(i32, String)> = i
            .multipart_upload
            .and_then(|m| m.parts)
            .unwrap_or_default()
            .into_iter()
            .map(|p| {
                (
                    p.part_number.unwrap_or(0),
                    p.e_tag.map(|e| e.value().to_string()).unwrap_or_default(),
                )
            })
            .collect();
        let info = self
            .vault
            .complete_upload(&i.bucket, &i.key, &i.upload_id, parts)
            .await
            .map_err(s3err)?;
        Ok(S3Response::new(CompleteMultipartUploadOutput {
            bucket: Some(i.bucket.clone()),
            key: Some(i.key.clone()),
            e_tag: etag(&info.etag),
            location: Some(format!("/{}/{}", i.bucket, i.key)),
            ..Default::default()
        }))
    }

    async fn abort_multipart_upload(
        &self,
        req: S3Request<AbortMultipartUploadInput>,
    ) -> S3Result<S3Response<AbortMultipartUploadOutput>> {
        let i = req.input;
        self.vault
            .abort_upload(&i.bucket, &i.key, &i.upload_id)
            .await
            .map_err(s3err)?;
        Ok(S3Response::new(AbortMultipartUploadOutput::default()))
    }
}
