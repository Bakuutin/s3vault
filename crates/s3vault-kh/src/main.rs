//! s3vault-kh: the network side of the key hierarchy. It never holds a slot key except for `sample`, and the
//! mirror commands read only sealed keystore files.
//!
//! ```text
//! s3vault-kh mirror-push --keystore-dir DIR --mirror CFG [--places FILE] [--place b2-mirror] [--require-lock-days N]
//!     upload the newest epoch to the fixed object `keystore.s3vks` (B2 keeps the versions), read the version
//!     back, compare SHA-256, check its object lock, record the place
//! s3vault-kh kit-push --mirror CFG --file KIT [--require-lock-days N]      the recovery kit as `recovery-kit.tar`
//! s3vault-kh mirror-versions --mirror CFG [--object keystore.s3vks]       list versions (id, time, size, latest)
//! s3vault-kh mirror-pull --mirror CFG --out FILE [--version-id V] [--object NAME]
//! s3vault-kh mirror-pull-all --mirror CFG --out-dir DIR                   every keystore version (drills)
//! s3vault-kh mirror-delete-version --mirror CFG --version-id V [--object NAME]
//!     undo of 7.4 and the object lock test: a locked version must refuse
//! s3vault-kh sample (--keystore F | --keystore-dir DIR) --slot DESC --store CFG --tenant NAME
//!     (--n N | --all) [--manifest FILE] [--v1]
//!     kh-verify --sample: list the tenant's objects in the store, open N (or all) with the keys from the
//!     keystore, check every body against the SHA-256 in its header; with a manifest (lines
//!     `<bucket> <key> <sha256>`), every listed object must be found and match
//! ```
//!
//! CFG is TOML: `endpoint`, `region`, `bucket`, `credentials_file` (TOML `access_key_id`, `secret_access_key`),
//! optional `prefix` (store objects, default "o/") and `url_style` ("path" default, or "vhost").

use anyhow::{Context, Result, anyhow, bail};
use rand::seq::SliceRandom;
use rusty_s3::actions::{
    DeleteObject, GetObject, HeadObject, ListObjectsV2, PutObject, S3Action,
};
use rusty_s3::{Bucket, Credentials, Method, UrlStyle};
use s3vault_format::keys2::{MasterV2, TenantStatus};
use s3vault_format::keystore::{Keystore, KeystoreDir, Places, PublicInfo, file_digest};
use s3vault_format::object;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const KS_OBJECT: &str = "keystore.s3vks";
const KIT_OBJECT: &str = "recovery-kit.tar";

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}
fn need(args: &[String], name: &str) -> Result<String> {
    arg(args, name).with_context(|| format!("missing {name}"))
}
fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Deserialize)]
struct S3Cfg {
    endpoint: String,
    region: String,
    bucket: String,
    credentials_file: PathBuf,
    #[serde(default = "default_prefix")]
    prefix: String,
    #[serde(default)]
    url_style: Option<String>,
}
fn default_prefix() -> String {
    "o/".into()
}

#[derive(Deserialize)]
struct Creds {
    access_key_id: String,
    secret_access_key: String,
}

struct S3 {
    bucket: Bucket,
    creds: Credentials,
    http: reqwest::blocking::Client,
    prefix: String,
}

impl S3 {
    fn load(path: &str) -> Result<S3> {
        let cfg: S3Cfg = toml::from_str(&std::fs::read_to_string(path).with_context(|| format!("read {path}"))?)
            .with_context(|| format!("parse {path}"))?;
        let c: Creds = toml::from_str(
            &std::fs::read_to_string(&cfg.credentials_file)
                .with_context(|| format!("read {}", cfg.credentials_file.display()))?,
        )?;
        let style = match cfg.url_style.as_deref() {
            Some("vhost") => UrlStyle::VirtualHost,
            _ => UrlStyle::Path,
        };
        Ok(S3 {
            bucket: Bucket::new(cfg.endpoint.parse()?, style, cfg.bucket, cfg.region)?,
            creds: Credentials::new(c.access_key_id, c.secret_access_key),
            http: reqwest::blocking::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(300))
                .build()?,
            prefix: cfg.prefix,
        })
    }

    fn put(&self, key: &str, body: &[u8]) -> Result<Option<String>> {
        use base64_md5::md5_b64;
        let md5 = md5_b64(body);
        let mut a = PutObject::new(&self.bucket, Some(&self.creds), key);
        a.headers_mut().insert("content-md5", md5.clone());
        let url = a.sign(Duration::from_secs(600));
        let r = self.http.put(url).header("content-md5", md5).body(body.to_vec()).send()?;
        let st = r.status();
        let vid = r.headers().get("x-amz-version-id").and_then(|v| v.to_str().ok()).map(String::from);
        if !st.is_success() {
            bail!("PUT {key}: {st} {}", r.text().unwrap_or_default());
        }
        Ok(vid)
    }

    fn get(&self, key: &str, version: Option<&str>) -> Result<Vec<u8>> {
        let mut a = GetObject::new(&self.bucket, Some(&self.creds), key);
        if let Some(v) = version {
            a.query_mut().insert("versionId", v.to_string());
        }
        let r = self.http.get(a.sign(Duration::from_secs(600))).send()?;
        let st = r.status();
        if !st.is_success() {
            bail!("GET {key}: {st}");
        }
        Ok(r.bytes()?.to_vec())
    }

    fn head(&self, key: &str, version: Option<&str>) -> Result<reqwest::header::HeaderMap> {
        let mut a = HeadObject::new(&self.bucket, Some(&self.creds), key);
        if let Some(v) = version {
            a.query_mut().insert("versionId", v.to_string());
        }
        let r = self.http.head(a.sign(Duration::from_secs(600))).send()?;
        if !r.status().is_success() {
            bail!("HEAD {key}: {}", r.status());
        }
        Ok(r.headers().clone())
    }

    fn delete_version(&self, key: &str, version: &str) -> Result<reqwest::StatusCode> {
        let mut a = DeleteObject::new(&self.bucket, Some(&self.creds), key);
        a.query_mut().insert("versionId", version.to_string());
        Ok(self.http.delete(a.sign(Duration::from_secs(600))).send()?.status())
    }

    fn list(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut a = ListObjectsV2::new(&self.bucket, Some(&self.creds));
            a.with_prefix(prefix);
            if let Some(t) = &token {
                a.with_continuation_token(t.clone());
            }
            let r = self.http.get(a.sign(Duration::from_secs(600))).send()?;
            if !r.status().is_success() {
                bail!("LIST {prefix}: {}", r.status());
            }
            let p = ListObjectsV2::parse_response(&r.text()?)?;
            out.extend(p.contents.into_iter().map(|c| (c.key, c.size.unwrap_or(0))));
            match p.next_continuation_token {
                Some(t) => token = Some(t),
                None => break,
            }
        }
        Ok(out)
    }

    /// ListObjectVersions (`GET /?versions&prefix=`), signed by hand: rusty-s3 has no action for it.
    fn versions(&self, key: &str) -> Result<Vec<Version>> {
        let url = self.bucket.base_url().clone();
        let date = jiff::Timestamp::now();
        let q = [("versions", ""), ("prefix", key)];
        let signed = rusty_s3::signing::sign(
            &date,
            Method::Get,
            url,
            self.creds.key(),
            self.creds.secret(),
            None,
            self.bucket.region(),
            600,
            q.iter().copied(),
            std::iter::empty(),
        );
        let r = self.http.get(signed).send()?;
        if !r.status().is_success() {
            bail!("LIST VERSIONS: {}", r.status());
        }
        let text = r.text()?;
        let mut v = Vec::new();
        for block in text.split("<Version>").skip(1) {
            let block = block.split("</Version>").next().unwrap_or("");
            let tag = |t: &str| -> String {
                block
                    .split(&format!("<{t}>"))
                    .nth(1)
                    .and_then(|s| s.split(&format!("</{t}>")).next())
                    .unwrap_or("")
                    .to_string()
            };
            if tag("Key") != key {
                continue;
            }
            v.push(Version {
                id: tag("VersionId"),
                latest: tag("IsLatest") == "true",
                modified: tag("LastModified"),
                size: tag("Size").parse().unwrap_or(0),
            });
        }
        Ok(v)
    }
}

#[derive(Debug)]
struct Version {
    id: String,
    latest: bool,
    modified: String,
    size: u64,
}

mod base64_md5 {
    pub fn md5_b64(b: &[u8]) -> String {
        use md5::Digest;
        data_encoding::BASE64.encode(&md5::Md5::digest(b))
    }
}

/// Upload with read-back and lock check. Returns (version id, retain-until).
fn push_object(s3: &S3, key: &str, bytes: &[u8], lock_days: Option<u64>) -> Result<(String, String)> {
    let vid = s3.put(key, bytes)?.unwrap_or_default();
    let back = s3.get(key, if vid.is_empty() { None } else { Some(&vid) })?;
    if Sha256::digest(&back)[..] != Sha256::digest(bytes)[..] {
        bail!("{key}: the version read back differs from what was uploaded");
    }
    let h = s3.head(key, if vid.is_empty() { None } else { Some(&vid) })?;
    let mode = h.get("x-amz-object-lock-mode").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let until = h.get("x-amz-object-lock-retain-until-date").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if let Some(days) = lock_days {
        if !mode.eq_ignore_ascii_case("COMPLIANCE") {
            bail!("{key} version {vid}: object lock mode is '{mode}', not COMPLIANCE (bucket default retention?)");
        }
        let t: jiff::Timestamp = until.parse().map_err(|_| anyhow!("{key}: bad retain-until '{until}'"))?;
        let min = jiff::Timestamp::now() + jiff::SignedDuration::from_hours(24 * (days as i64 - 1));
        if t < min {
            bail!("{key} version {vid}: retained only until {until}, policy wants {days} days");
        }
    }
    Ok((vid, if mode.is_empty() { "none".into() } else { format!("{mode} until {until}") }))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let lock_days = arg(&args, "--require-lock-days").map(|d| d.parse()).transpose()?;
    match cmd {
        "mirror-push" => {
            let s3 = S3::load(&need(&args, "--mirror")?)?;
            let kd = KeystoreDir::new(PathBuf::from(need(&args, "--keystore-dir")?));
            let (n, bytes) = kd.read_newest().map_err(|e| anyhow!("{e}"))?;
            let info = PublicInfo::parse(&bytes)?;
            let d = file_digest(&bytes);
            s3vault_format::keystore::crash_point("mirror-before-put");
            let (vid, lock) = push_object(&s3, KS_OBJECT, &bytes, lock_days)?;
            s3vault_format::keystore::crash_point("mirror-after-put");
            println!("mirror: epoch {n} ({} slots) sha256 {d} -> {KS_OBJECT} version {vid}; read back equal; lock {lock}", info.slots.len());
            if let Some(p) = arg(&args, "--places") {
                let place = arg(&args, "--place").unwrap_or_else(|| "b2-mirror".into());
                Places::append(Path::new(&p), n, &d, &place, now()).map_err(|e| anyhow!("{e}"))?;
                println!("place {place} recorded for epoch {n}");
            }
        }
        "kit-push" => {
            let s3 = S3::load(&need(&args, "--mirror")?)?;
            let f = need(&args, "--file")?;
            let bytes = std::fs::read(&f)?;
            let (vid, lock) = push_object(&s3, KIT_OBJECT, &bytes, lock_days)?;
            println!("kit: {f} sha256 {} -> {KIT_OBJECT} version {vid}; read back equal; lock {lock}", file_digest(&bytes));
        }
        "mirror-versions" => {
            let s3 = S3::load(&need(&args, "--mirror")?)?;
            let obj = arg(&args, "--object").unwrap_or_else(|| KS_OBJECT.into());
            for v in s3.versions(&obj)? {
                println!("{} {} {} bytes{}", v.id, v.modified, v.size, if v.latest { " latest" } else { "" });
            }
        }
        "mirror-pull" => {
            let s3 = S3::load(&need(&args, "--mirror")?)?;
            let obj = arg(&args, "--object").unwrap_or_else(|| KS_OBJECT.into());
            let b = s3.get(&obj, arg(&args, "--version-id").as_deref())?;
            write_new(&need(&args, "--out")?, &b)?;
            if obj == KS_OBJECT {
                let i = PublicInfo::parse(&b)?;
                println!("pulled epoch {} sha256 {}", i.epoch, file_digest(&b));
            } else {
                println!("pulled {obj} sha256 {}", file_digest(&b));
            }
        }
        "mirror-pull-all" => {
            let s3 = S3::load(&need(&args, "--mirror")?)?;
            let out = PathBuf::from(need(&args, "--out-dir")?);
            std::fs::create_dir_all(&out)?;
            for v in s3.versions(KS_OBJECT)? {
                let b = s3.get(KS_OBJECT, Some(&v.id))?;
                let i = PublicInfo::parse(&b)?;
                let p = out.join(s3vault_format::keystore::epoch_file_name(i.epoch));
                if !p.exists() {
                    write_new(&p.to_string_lossy(), &b)?;
                }
                println!("version {} epoch {} sha256 {}", v.id, i.epoch, &file_digest(&b)[..16]);
            }
        }
        "mirror-delete-version" => {
            let s3 = S3::load(&need(&args, "--mirror")?)?;
            let obj = arg(&args, "--object").unwrap_or_else(|| KS_OBJECT.into());
            let v = need(&args, "--version-id")?;
            let st = s3.delete_version(&obj, &v)?;
            println!("delete {obj} version {v}: {st}");
            if !st.is_success() {
                std::process::exit(4);
            }
        }
        "sample" => sample(&args)?,
        _ => {
            eprintln!("usage: s3vault-kh mirror-push|kit-push|mirror-versions|mirror-pull|mirror-pull-all|mirror-delete-version|sample (see the header of crates/s3vault-kh/src/main.rs)");
            std::process::exit(2)
        }
    }
    Ok(())
}

fn write_new(path: &str, b: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {path} (refusing to overwrite)"))?;
    f.write_all(b)?;
    Ok(())
}

/// Decrypt one whole stored object. Returns (bucket, key, sha256, size, tombstone).
fn open_object_v2(tk: &s3vault_format::keys2::TenantKeys, bytes: &[u8]) -> Result<(String, String, String, u64, bool)> {
    let (h, info) = object::open_head_v2(tk, bytes)?;
    let layout = object::Layout { header_sealed_len: info.header_sealed_len as u64, size: h.size };
    if layout.total_len() != bytes.len() as u64 {
        bail!("length {} differs from the layout {}", bytes.len(), layout.total_len());
    }
    let c = object::body_cipher_v2(tk, &info);
    let body = &bytes[layout.body_offset() as usize..];
    let plain = object::open_range(&c, &layout, 0, layout.n_chunks() - 1, body, 0, h.size)?;
    let sha = hex::encode(Sha256::digest(&plain));
    if sha != h.sha256 {
        bail!("body SHA-256 differs from the header");
    }
    Ok((h.bucket, h.key, sha, h.size, h.tombstone))
}

fn open_object_v1(kr: &s3vault_format::keyring::Keyring, bytes: &[u8]) -> Result<(String, String, String, u64, bool)> {
    let (h, info) = object::open_head(kr, bytes)?;
    let layout = object::Layout { header_sealed_len: info.header_sealed_len as u64, size: h.size };
    let c = object::body_cipher(kr, &info)?;
    let body = &bytes[layout.body_offset() as usize..];
    let plain = object::open_range(&c, &layout, 0, layout.n_chunks() - 1, body, 0, h.size)?;
    let sha = hex::encode(Sha256::digest(&plain));
    if sha != h.sha256 {
        bail!("body SHA-256 differs from the header");
    }
    Ok((h.bucket, h.key, sha, h.size, h.tombstone))
}

fn sample(args: &[String]) -> Result<()> {
    let slot = s3vault_format::slots::open_descriptor(&need(args, "--slot")?)?;
    let bytes = match arg(args, "--keystore") {
        Some(f) => std::fs::read(f)?,
        None => KeystoreDir::new(PathBuf::from(need(args, "--keystore-dir")?)).read_newest().map_err(|e| anyhow!("{e}"))?.1,
    };
    let ks = Keystore::open(&bytes, slot.as_ref())?;
    let master = Arc::new(MasterV2::parse(&ks.master_text)?);
    let s3 = S3::load(&need(args, "--store")?)?;
    let all = args.iter().any(|a| a == "--all");
    let n: usize = arg(args, "--n").map(|v| v.parse()).transpose()?.unwrap_or(50);
    let mut found: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut opened = 0usize;
    let mut failed = 0usize;
    let pick = |mut keys: Vec<(String, u64)>| -> Vec<(String, u64)> {
        keys.shuffle(&mut rand::thread_rng());
        if !all {
            keys.truncate(n);
        }
        keys
    };
    if args.iter().any(|a| a == "--v1") {
        let legacy = master.legacy.as_ref().context("no legacy v1 keys in the master keyring")?;
        let keys: Vec<(String, u64)> =
            s3.list(&s3.prefix)?.into_iter().filter(|(k, _)| !k[s3.prefix.len()..].contains('/')).collect();
        let total = keys.len();
        for (k, _) in pick(keys) {
            match s3.get(&k, None).map_err(|e| anyhow!(e)).and_then(|b| open_object_v1(legacy, &b)) {
                Ok((b, key, sha, _, _)) => {
                    opened += 1;
                    found.insert((b, key), sha);
                }
                Err(e) => {
                    failed += 1;
                    println!("FAIL v1 {k}: {e}");
                }
            }
        }
        println!("v1: {total} objects in the store, opened {opened}, failed {failed}");
    } else {
        let name = need(args, "--tenant")?;
        let t = ks.tenants.tenants.get(&name).with_context(|| format!("no tenant {name} in the keystore"))?;
        if t.status == TenantStatus::Erased {
            bail!("tenant {name} is erased");
        }
        let tk = master.tenant_keys(t)?;
        let prefix = format!("{}{}/", s3.prefix, tk.tag);
        let keys = s3.list(&prefix)?;
        let total = keys.len();
        for (k, _) in pick(keys) {
            match s3.get(&k, None).map_err(|e| anyhow!(e)).and_then(|b| open_object_v2(&tk, &b)) {
                Ok((b, key, sha, _, _)) => {
                    // the object's name must be the one its header implies (no swapped objects)
                    if format!("{}{}", s3.prefix, object::store_name_v2(&tk, &b, &key)) != k {
                        failed += 1;
                        println!("FAIL {k}: stored under a name its header does not give");
                        continue;
                    }
                    opened += 1;
                    found.insert((b, key), sha);
                }
                Err(e) => {
                    failed += 1;
                    println!("FAIL {k}: {e}");
                }
            }
        }
        println!(
            "tenant {name} (K_t fp {}): {total} objects under its prefix, opened {opened}, failed {failed}",
            tk.fingerprint
        );
    }
    if let Some(mf) = arg(args, "--manifest") {
        let mut missing = 0usize;
        let mut lines = 0usize;
        for l in std::fs::read_to_string(&mf)?.lines().filter(|l| !l.trim().is_empty()) {
            let p: Vec<&str> = l.split_whitespace().collect();
            if p.len() != 3 {
                continue;
            }
            lines += 1;
            match found.get(&(p[0].to_string(), p[1].to_string())) {
                Some(s) if s == p[2] => {}
                Some(_) => {
                    missing += 1;
                    println!("FAIL manifest {} {}: content differs", p[0], p[1]);
                }
                None => {
                    missing += 1;
                    println!("FAIL manifest {} {}: not found or not readable", p[0], p[1]);
                }
            }
        }
        println!("manifest {mf}: {lines} objects, {} readable and equal, {missing} missing", lines - missing);
        if missing > 0 {
            failed += missing;
        }
    }
    if failed > 0 {
        bail!("{failed} failures");
    }
    println!("sample: ok");
    Ok(())
}
