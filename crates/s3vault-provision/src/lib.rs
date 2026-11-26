//! s3vault-provision: one Backblaze B2 bucket and one bucket-scoped application key per s3vault tenant.
//!
//! Runs on the key host with the provisioning key (an account-admin key: it holds `writeKeys`, which B2
//! cannot scope). The proxy only ever receives the bucket-scoped key of each tenant. Nothing here learns
//! or sends tenant names to B2: bucket names and key names are random, and the tenant-to-bucket mapping
//! lives only in the local state file. See `docs/PROVISIONING.md`.

use anyhow::{Context, Result, anyhow, bail};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zeroize::Zeroizing;

/// B2 native API base for `b2_authorize_account`.
pub const DEFAULT_API: &str = "https://api.backblazeb2.com";

/// Capabilities of a tenant's bucket-scoped key: what the proxy needs (S3 get, put, list, delete), nothing
/// that manages buckets or keys.
pub const SCOPED_CAPS: &[&str] = &["listBuckets", "listFiles", "readFiles", "writeFiles", "deleteFiles"];

/// Capabilities the provisioning key needs. `writeKeys` makes it account-admin equivalent (it can mint a key
/// with any capability), which is why it never goes to the proxy.
pub const ADMIN_CAPS: &[&str] = &[
    "listBuckets",
    "readBuckets",
    "writeBuckets",
    "deleteBuckets",
    "readBucketLifecycleRules",
    "writeBucketLifecycleRules",
    "listKeys",
    "writeKeys",
    "deleteKeys",
    "listFiles",
    "deleteFiles",
];

/// Decision D2: keep only the last version, 7 days from hide to delete.
pub const HIDE_TO_DELETE_DAYS: u64 = 7;

/// Default B2 bucket limit per account (raised only by Backblaze sales).
pub const DEFAULT_MAX_BUCKETS: usize = 100;

/// The lifecycle rule of a live tenant bucket (D2).
pub fn live_lifecycle() -> Value {
    json!([{ "fileNamePrefix": "", "daysFromHidingToDeleting": HIDE_TO_DELETE_DAYS, "daysFromUploadingToHiding": null }])
}

/// The lifecycle rule of a retired tenant bucket: hide everything a day after upload, delete a day after
/// hiding, so B2 empties the bucket itself (no per-object deletes at production size).
pub fn drain_lifecycle() -> Value {
    json!([{ "fileNamePrefix": "", "daysFromHidingToDeleting": 1, "daysFromUploadingToHiding": 1 }])
}

/// An application key id and its secret. Debug shows the first 4 characters of the id only.
pub struct Creds {
    pub key_id: String,
    pub key: Zeroizing<String>,
}

impl std::fmt::Debug for Creds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Creds({})", short(&self.key_id))
    }
}

/// Last 4 characters of a key id (B2 key ids of one account share their first characters): the most any
/// output shows.
pub fn short(id: &str) -> String {
    let c: Vec<char> = id.chars().collect();
    format!("…{}", c[c.len().saturating_sub(4)..].iter().collect::<String>())
}

/// Parse an env file (`KEY=VALUE`, optional `export `, optional quotes, `#` comments).
pub fn read_env_file(path: &Path) -> Result<BTreeMap<String, Zeroizing<String>>> {
    let text = Zeroizing::new(
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?,
    );
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.trim();
        let v = v
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
            .unwrap_or(v);
        out.insert(k.trim().to_string(), Zeroizing::new(v.to_string()));
    }
    Ok(out)
}

/// The provisioning key from its env file (`B2_APPLICATION_KEY_ID`, `B2_APPLICATION_KEY`).
pub fn admin_creds(path: &Path) -> Result<Creds> {
    let env = read_env_file(path)?;
    let get = |k: &str| {
        env.get(k)
            .map(|v| v.to_string())
            .with_context(|| format!("{} has no {k}", path.display()))
    };
    Ok(Creds { key_id: get("B2_APPLICATION_KEY_ID")?, key: Zeroizing::new(get("B2_APPLICATION_KEY")?) })
}

/// A B2 API error (`status`, `code`, `message`).
#[derive(Debug)]
pub struct B2Error {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for B2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "B2 {} {}: {}", self.status, self.code, self.message)
    }
}
impl std::error::Error for B2Error {}

/// Whether an error is a B2 error with this code.
pub fn is_b2(e: &anyhow::Error, code: &str) -> bool {
    e.downcast_ref::<B2Error>().is_some_and(|b| b.code == code)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketInfo {
    pub bucket_id: String,
    pub bucket_name: String,
    #[serde(default)]
    pub bucket_type: String,
    #[serde(default)]
    pub lifecycle_rules: Value,
    #[serde(default)]
    pub file_lock_configuration: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    pub application_key_id: String,
    #[serde(default)]
    pub key_name: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub bucket_ids: Option<Vec<String>>,
}

/// An authorized session against the B2 native API (v4).
pub struct B2 {
    http: reqwest::blocking::Client,
    pub account_id: String,
    pub api_url: String,
    pub s3_api_url: String,
    token: Zeroizing<String>,
    pub capabilities: Vec<String>,
    /// `(id, name)` of the buckets the key is restricted to (empty: unrestricted).
    pub buckets: Vec<(String, Option<String>)>,
    pub name_prefix: Option<String>,
}

fn http_client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?)
}

fn b2_error(status: u16, body: &str) -> anyhow::Error {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    anyhow::Error::new(B2Error {
        status,
        code: v["code"].as_str().unwrap_or("unknown").to_string(),
        message: v["message"].as_str().unwrap_or("").chars().take(200).collect(),
    })
}

impl B2 {
    /// `b2_authorize_account` with an application key.
    pub fn authorize(base: &str, c: &Creds) -> Result<B2> {
        let http = http_client()?;
        let basic = Zeroizing::new(data_encoding::BASE64.encode(format!("{}:{}", c.key_id, c.key.as_str()).as_bytes()));
        let resp = http
            .get(format!("{}/b2api/v4/b2_authorize_account", base.trim_end_matches('/')))
            .header("authorization", format!("Basic {}", basic.as_str()))
            .send()
            .context("b2_authorize_account")?;
        let status = resp.status().as_u16();
        let body = Zeroizing::new(resp.text()?);
        if status != 200 {
            return Err(b2_error(status, &body)).context("b2_authorize_account");
        }
        let v: Value = serde_json::from_str(&body)?;
        let st = &v["apiInfo"]["storageApi"];
        let s = |x: &Value| x.as_str().map(String::from);
        Ok(B2 {
            http,
            account_id: s(&v["accountId"]).context("no accountId")?,
            api_url: s(&st["apiUrl"]).context("no apiUrl")?,
            s3_api_url: s(&st["s3ApiUrl"]).unwrap_or_default(),
            token: Zeroizing::new(s(&v["authorizationToken"]).context("no authorizationToken")?),
            capabilities: st["allowed"]["capabilities"]
                .as_array()
                .map(|a| a.iter().filter_map(|c| c.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            buckets: st["allowed"]["buckets"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|b| Some((b["id"].as_str()?.to_string(), s(&b["name"]))))
                        .collect()
                })
                .unwrap_or_default(),
            name_prefix: s(&st["allowed"]["namePrefix"]),
        })
    }

    /// The S3 region from the S3 endpoint (`https://s3.<region>.backblazeb2.com`).
    pub fn region(&self) -> String {
        self.s3_api_url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .strip_prefix("s3.")
            .and_then(|r| r.split('.').next())
            .unwrap_or("")
            .to_string()
    }

    /// Refuse to go on unless the key holds every capability in `caps`.
    pub fn require(&self, caps: &[&str]) -> Result<()> {
        let missing: Vec<&str> =
            caps.iter().copied().filter(|c| !self.capabilities.iter().any(|h| h == c)).collect();
        if !missing.is_empty() {
            bail!("the key lacks capabilities {missing:?}");
        }
        Ok(())
    }

    fn call(&self, op: &str, body: Value) -> Result<Value> {
        let resp = self
            .http
            .post(format!("{}/b2api/v4/{op}", self.api_url))
            .header("authorization", self.token.as_str())
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .with_context(|| op.to_string())?;
        let status = resp.status().as_u16();
        let text = Zeroizing::new(resp.text()?);
        if status != 200 {
            return Err(b2_error(status, &text)).context(op.to_string());
        }
        Ok(serde_json::from_str(&text)?)
    }

    pub fn list_buckets(&self) -> Result<Vec<BucketInfo>> {
        let v = self.call("b2_list_buckets", json!({ "accountId": self.account_id }))?;
        Ok(serde_json::from_value(v["buckets"].clone())?)
    }

    /// A private bucket, object lock off, default B2 encryption (SSE-B2, the account default), no bucket info.
    pub fn create_bucket(&self, name: &str, lifecycle: Value) -> Result<BucketInfo> {
        let v = self.call(
            "b2_create_bucket",
            json!({
                "accountId": self.account_id,
                "bucketName": name,
                "bucketType": "allPrivate",
                "fileLockEnabled": false,
                "lifecycleRules": lifecycle,
            }),
        )?;
        Ok(serde_json::from_value(v)?)
    }

    pub fn update_lifecycle(&self, bucket_id: &str, lifecycle: Value) -> Result<()> {
        self.call(
            "b2_update_bucket",
            json!({ "accountId": self.account_id, "bucketId": bucket_id, "lifecycleRules": lifecycle }),
        )?;
        Ok(())
    }

    pub fn delete_bucket(&self, bucket_id: &str) -> Result<()> {
        self.call("b2_delete_bucket", json!({ "accountId": self.account_id, "bucketId": bucket_id }))?;
        Ok(())
    }

    /// A key restricted to one bucket with `caps`.
    pub fn create_key(&self, key_name: &str, caps: &[&str], bucket_id: &str) -> Result<Creds> {
        let v = self.call(
            "b2_create_key",
            json!({
                "accountId": self.account_id,
                "capabilities": caps,
                "keyName": key_name,
                "bucketIds": [bucket_id],
            }),
        )?;
        let key_id = v["applicationKeyId"].as_str().context("no applicationKeyId")?.to_string();
        let key = Zeroizing::new(v["applicationKey"].as_str().context("no applicationKey")?.to_string());
        Ok(Creds { key_id, key })
    }

    pub fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        let mut out = Vec::new();
        let mut start: Option<String> = None;
        loop {
            let mut body = json!({ "accountId": self.account_id, "maxKeyCount": 1000 });
            if let Some(s) = &start {
                body["startApplicationKeyId"] = json!(s);
            }
            let v = self.call("b2_list_keys", body)?;
            let page: Vec<KeyInfo> = serde_json::from_value(v["keys"].clone())?;
            out.extend(page);
            match v["nextApplicationKeyId"].as_str() {
                Some(n) => start = Some(n.to_string()),
                None => return Ok(out),
            }
        }
    }

    pub fn delete_key(&self, key_id: &str) -> Result<()> {
        self.call("b2_delete_key", json!({ "applicationKeyId": key_id }))?;
        Ok(())
    }

    /// One page of file versions: `(fileName, fileId)` and the next start, if any.
    #[allow(clippy::type_complexity)]
    pub fn list_file_versions(
        &self,
        bucket_id: &str,
        start: Option<(String, String)>,
    ) -> Result<(Vec<(String, String)>, Option<(String, String)>)> {
        let mut body = json!({ "bucketId": bucket_id, "maxFileCount": 1000 });
        if let Some((n, i)) = start {
            body["startFileName"] = json!(n);
            body["startFileId"] = json!(i);
        }
        let v = self.call("b2_list_file_versions", body)?;
        let files = v["files"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|f| Some((f["fileName"].as_str()?.to_string(), f["fileId"].as_str()?.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let next = match (v["nextFileName"].as_str(), v["nextFileId"].as_str()) {
            (Some(n), Some(i)) => Some((n.to_string(), i.to_string())),
            _ => None,
        };
        Ok((files, next))
    }

    pub fn delete_file_version(&self, name: &str, id: &str) -> Result<()> {
        self.call("b2_delete_file_version", json!({ "fileName": name, "fileId": id }))?;
        Ok(())
    }
}

const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// A random lowercase name: a letter, then `len - 1` of `[a-z0-9]`. Says nothing about tenants or the tool.
pub fn random_name(len: usize) -> String {
    let mut r = rand::rngs::OsRng;
    let mut s = String::with_capacity(len);
    s.push((b'a' + r.gen_range(0..26u8)) as char);
    for _ in 1..len {
        s.push(ALNUM[r.gen_range(0..ALNUM.len())] as char);
    }
    s
}

pub const BUCKET_NAME_LEN: usize = 32;
pub const KEY_NAME_LEN: usize = 24;

fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Active,
    Retired,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub id: String,
    pub name: String,
    pub created: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantEntry {
    pub bucket_name: String,
    pub bucket_id: String,
    /// Oldest first; the last one is the current key.
    pub keys: Vec<KeyEntry>,
    pub status: Status,
    pub created: String,
    #[serde(default)]
    pub retired: Option<String>,
    #[serde(default)]
    pub deleted: Option<String>,
}

/// The tenant-to-bucket mapping (local only; B2 never sees tenant names). JSON, mode 600.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub tenants: BTreeMap<String, TenantEntry>,
}

impl State {
    pub fn load(path: &Path) -> Result<State> {
        match std::fs::read_to_string(path) {
            Ok(t) => serde_json::from_str(&t).with_context(|| format!("parse {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    /// Atomic write (temp file, mode 600, rename).
    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    fn get(&self, tenant: &str) -> Result<&TenantEntry> {
        self.tenants.get(tenant).with_context(|| format!("tenant {tenant} is not provisioned"))
    }
}

/// Tenant names as in s3vault (`[a-z0-9_-]`, 1-64).
pub fn valid_tenant(t: &str) -> bool {
    !t.is_empty() && t.len() <= 64 && t.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Create a random-name private bucket (D2 lifecycle, no object lock) and its bucket-scoped key for a tenant.
/// The state is saved before the key secret is returned.
pub fn provision_tenant(b2: &B2, state_path: &Path, tenant: &str, max_buckets: usize) -> Result<(TenantEntry, Creds)> {
    if !valid_tenant(tenant) {
        bail!("tenant names are 1-64 of [a-z0-9_-]");
    }
    b2.require(ADMIN_CAPS)?;
    let mut state = State::load(state_path)?;
    if let Some(t) = state.tenants.get(tenant)
        && t.status != Status::Deleted
    {
        bail!("tenant {tenant} is already provisioned ({:?})", t.status);
    }
    let existing = b2.list_buckets()?;
    if existing.len() >= max_buckets {
        bail!("the account has {} buckets, the limit is {max_buckets}: ask Backblaze for more, or use the shared overflow bucket (docs/PROVISIONING.md)", existing.len());
    }
    let mut bucket = None;
    for _ in 0..5 {
        match b2.create_bucket(&random_name(BUCKET_NAME_LEN), live_lifecycle()) {
            Ok(b) => {
                bucket = Some(b);
                break;
            }
            Err(e) if is_b2(&e, "duplicate_bucket_name") => continue,
            Err(e) => return Err(e),
        }
    }
    let bucket = bucket.ok_or_else(|| anyhow!("no free random bucket name after 5 tries"))?;
    let key_name = random_name(KEY_NAME_LEN);
    let creds = match b2.create_key(&key_name, SCOPED_CAPS, &bucket.bucket_id) {
        Ok(c) => c,
        Err(e) => {
            // No key: remove the empty bucket again so nothing is left unaccounted for.
            let _ = b2.delete_bucket(&bucket.bucket_id);
            return Err(e);
        }
    };
    let t = now();
    let entry = TenantEntry {
        bucket_name: bucket.bucket_name,
        bucket_id: bucket.bucket_id,
        keys: vec![KeyEntry { id: creds.key_id.clone(), name: key_name, created: t.clone() }],
        status: Status::Active,
        created: t,
        retired: None,
        deleted: None,
    };
    state.tenants.insert(tenant.to_string(), entry.clone());
    state.save(state_path)?;
    Ok((entry, creds))
}

/// A new bucket-scoped key for an active tenant; the old keys stay valid until `revoke_old_keys`.
pub fn rotate_key(b2: &B2, state_path: &Path, tenant: &str) -> Result<Creds> {
    b2.require(ADMIN_CAPS)?;
    let mut state = State::load(state_path)?;
    let e = state.get(tenant)?;
    if e.status != Status::Active {
        bail!("tenant {tenant} is {:?}", e.status);
    }
    let bucket_id = e.bucket_id.clone();
    let name = random_name(KEY_NAME_LEN);
    let creds = b2.create_key(&name, SCOPED_CAPS, &bucket_id)?;
    let e = state.tenants.get_mut(tenant).expect("checked");
    e.keys.push(KeyEntry { id: creds.key_id.clone(), name, created: now() });
    state.save(state_path)?;
    Ok(creds)
}

/// Keys of the account restricted to this bucket (including any not recorded in the state).
fn bucket_keys(b2: &B2, bucket_id: &str) -> Result<Vec<KeyInfo>> {
    Ok(b2
        .list_keys()?
        .into_iter()
        .filter(|k| k.bucket_ids.as_ref().is_some_and(|b| b.iter().any(|x| x == bucket_id)))
        .collect())
}

/// Delete every key of the tenant's bucket except the newest one in the state. Returns the number deleted.
pub fn revoke_old_keys(b2: &B2, state_path: &Path, tenant: &str) -> Result<usize> {
    b2.require(ADMIN_CAPS)?;
    let mut state = State::load(state_path)?;
    let e = state.get(tenant)?;
    let keep = e.keys.last().map(|k| k.id.clone()).context("no current key")?;
    let mut n = 0;
    for k in bucket_keys(b2, &e.bucket_id)? {
        if k.application_key_id != keep {
            b2.delete_key(&k.application_key_id)?;
            n += 1;
        }
    }
    let e = state.tenants.get_mut(tenant).expect("checked");
    e.keys.retain(|k| k.id == keep);
    state.save(state_path)?;
    Ok(n)
}

/// After the tenant's erasure on the proxy: revoke every key of its bucket and let B2 drain it
/// (hide after 1 day, delete 1 day after hiding). Returns the number of keys deleted.
pub fn retire_tenant(b2: &B2, state_path: &Path, tenant: &str) -> Result<usize> {
    b2.require(ADMIN_CAPS)?;
    let mut state = State::load(state_path)?;
    let e = state.get(tenant)?.clone();
    if e.status == Status::Deleted {
        bail!("tenant {tenant} is already deleted");
    }
    let mut n = 0;
    for k in bucket_keys(b2, &e.bucket_id)? {
        b2.delete_key(&k.application_key_id)?;
        n += 1;
    }
    b2.update_lifecycle(&e.bucket_id, drain_lifecycle())?;
    let e = state.tenants.get_mut(tenant).expect("checked");
    e.keys.clear();
    e.status = Status::Retired;
    e.retired = Some(now());
    state.save(state_path)?;
    Ok(n)
}

/// Delete a retired tenant's bucket. With `purge`, every remaining file version is deleted first
/// (fine for small buckets; large ones are drained by the retire lifecycle). Returns versions deleted.
pub fn deprovision_tenant(b2: &B2, state_path: &Path, tenant: &str, purge: bool) -> Result<u64> {
    b2.require(ADMIN_CAPS)?;
    let mut state = State::load(state_path)?;
    let e = state.get(tenant)?.clone();
    if e.status != Status::Retired {
        bail!("tenant {tenant} is {:?}: retire it first (revokes its keys)", e.status);
    }
    let mut deleted = 0;
    if purge {
        let mut start = None;
        loop {
            let (files, next) = b2.list_file_versions(&e.bucket_id, start)?;
            for (name, id) in files {
                b2.delete_file_version(&name, &id)?;
                deleted += 1;
            }
            match next {
                Some(n) => start = Some(n),
                None => break,
            }
        }
    }
    match b2.delete_bucket(&e.bucket_id) {
        Ok(()) => {}
        Err(err) if is_b2(&err, "cannot_delete_non_empty_bucket") => {
            bail!("the bucket still holds file versions: wait for the drain lifecycle (2 days after retire) or use --purge")
        }
        Err(err) if is_b2(&err, "bad_bucket_id") => {} // already gone
        Err(err) => return Err(err),
    }
    let e = state.tenants.get_mut(tenant).expect("checked");
    e.status = Status::Deleted;
    e.deleted = Some(now());
    state.save(state_path)?;
    Ok(deleted)
}

/// The state checked against the account: per tenant its bucket, status, key ids (4 characters), whether the
/// bucket exists and has the expected lifecycle and settings; plus the account's other buckets (count only).
pub fn list(b2: &B2, state_path: &Path, max_buckets: usize) -> Result<Value> {
    let state = State::load(state_path)?;
    let buckets = b2.list_buckets()?;
    let keys = b2.list_keys()?;
    let mut tenants = serde_json::Map::new();
    for (name, e) in &state.tenants {
        let remote = buckets.iter().find(|b| b.bucket_id == e.bucket_id);
        let want = match e.status {
            Status::Active => Some(live_lifecycle()),
            Status::Retired => Some(drain_lifecycle()),
            Status::Deleted => None,
        };
        let remote_keys: Vec<String> = keys
            .iter()
            .filter(|k| k.bucket_ids.as_ref().is_some_and(|b| b.contains(&e.bucket_id)))
            .map(|k| short(&k.application_key_id))
            .collect();
        tenants.insert(
            name.clone(),
            json!({
                "bucket": e.bucket_name,
                "status": e.status,
                "created": e.created,
                "keys_in_state": e.keys.iter().map(|k| short(&k.id)).collect::<Vec<_>>(),
                "keys_in_b2": remote_keys,
                "bucket_exists": remote.is_some(),
                "private": remote.map(|b| b.bucket_type == "allPrivate"),
                "lifecycle_ok": match (remote, want) {
                    (Some(b), Some(w)) => Some(lifecycle_eq(&b.lifecycle_rules, &w)),
                    _ => None,
                },
                "object_lock": remote.map(|b| b.file_lock_configuration["value"]["isFileLockEnabled"].as_bool().unwrap_or(false)),
            }),
        );
    }
    let managed: Vec<&String> = state.tenants.values().map(|e| &e.bucket_id).collect();
    Ok(json!({
        "tenants": tenants,
        "account_buckets": buckets.len(),
        "bucket_limit": max_buckets,
        "unmanaged_buckets": buckets.iter().filter(|b| !managed.contains(&&b.bucket_id)).count(),
    }))
}

fn lifecycle_eq(have: &Value, want: &Value) -> bool {
    let norm = |v: &Value| -> Vec<(String, Option<u64>, Option<u64>)> {
        let mut r: Vec<_> = v
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|x| {
                        (
                            x["fileNamePrefix"].as_str().unwrap_or("").to_string(),
                            x["daysFromHidingToDeleting"].as_u64(),
                            x["daysFromUploadingToHiding"].as_u64(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        r.sort();
        r
    };
    norm(have) == norm(want)
}

/// The scope of a key, for a check: bucket names, capabilities and name prefix (never the key).
pub fn describe_scope(b2: &B2) -> Value {
    json!({
        "buckets": b2.buckets.iter().map(|(_, n)| n.clone()).collect::<Vec<_>>(),
        "capabilities": b2.capabilities,
        "name_prefix": b2.name_prefix,
        "writeKeys": b2.capabilities.iter().any(|c| c == "writeKeys"),
    })
}

/// The proxy's store credentials file (TOML, as `credentials_file` expects).
pub fn credentials_toml(c: &Creds) -> Zeroizing<String> {
    Zeroizing::new(format!("access_key_id = \"{}\"\nsecret_access_key = \"{}\"\n", c.key_id, c.key.as_str()))
}

/// Header line of a sealed credentials file.
pub const SEALED_HEADER: &str = "s3vault-sealed-creds v1 rsa-oaep-sha256";

/// Encrypt `plain` to the proxy's RSA public key (PEM) with `openssl pkeyutl` (OAEP, SHA-256, MGF1-SHA-256).
/// Output: the header line, then the base64 ciphertext. Open on the proxy with
/// `sed 1d | base64 -d | openssl pkeyutl -decrypt -inkey KEY -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256`.
pub fn seal_for(recipient_pem: &Path, plain: &[u8]) -> Result<String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("openssl")
        .args(["pkeyutl", "-encrypt", "-pubin", "-inkey"])
        .arg(recipient_pem)
        .args(["-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256", "-pkeyopt", "rsa_mgf1_md:sha256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("run openssl")?;
    child.stdin.take().expect("piped").write_all(plain)?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("openssl pkeyutl failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(format!("{SEALED_HEADER}\n{}\n", data_encoding::BASE64.encode(&out.stdout)))
}

/// The `[stores.<name>]` block for the proxy's config (no secrets).
pub fn store_snippet(b2: &B2, store: &str, bucket: &str, credentials_file: &str) -> String {
    format!(
        "[stores.{store}]\nendpoint = \"{}\"\nregion = \"{}\"\nbucket = \"{bucket}\"\ncredentials_file = \"{credentials_file}\"\nprefix = \"o/\"\nread_timeout_secs = 120\n",
        b2.s3_api_url,
        b2.region()
    )
}
