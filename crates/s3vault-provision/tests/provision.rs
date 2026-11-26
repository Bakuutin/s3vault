//! Provisioning against an in-process fake of the B2 native API (v4): authorize, buckets, keys, file
//! versions, with capability and bucket-scope checks and the 100-bucket limit.

use s3vault_provision::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct FKey {
    secret: String,
    name: String,
    caps: Vec<String>,
    buckets: Option<Vec<String>>,
}

#[derive(Clone)]
struct FBucket {
    name: String,
    btype: String,
    lifecycle: Value,
    lock: bool,
    files: Vec<(String, String)>,
}

#[derive(Default)]
struct Fake {
    keys: BTreeMap<String, FKey>,
    tokens: BTreeMap<String, String>,
    buckets: BTreeMap<String, FBucket>,
    next: u64,
    limit: usize,
}

impl Fake {
    fn id(&mut self, p: &str) -> String {
        self.next += 1;
        format!("{p}{:012}", self.next)
    }
}

type Shared = Arc<Mutex<Fake>>;

fn err(status: u16, code: &str) -> (u16, Value) {
    (status, json!({"status": status, "code": code, "message": code}))
}

fn handle(f: &Shared, path: &str, auth: &str, body: &Value, base: &str) -> (u16, Value) {
    let mut s = f.lock().unwrap();
    if path == "/b2api/v4/b2_authorize_account" {
        let raw = auth.strip_prefix("Basic ").unwrap_or("");
        let dec = String::from_utf8(data_encoding::BASE64.decode(raw.as_bytes()).unwrap_or_default()).unwrap_or_default();
        let Some((id, sec)) = dec.split_once(':') else { return err(401, "bad_auth_token") };
        let Some(k) = s.keys.get(id).cloned() else { return err(401, "bad_auth_token") };
        if k.secret != sec {
            return err(401, "bad_auth_token");
        }
        let tok = s.id("tok");
        s.tokens.insert(tok.clone(), id.to_string());
        let buckets: Vec<Value> = k
            .buckets
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|b| json!({"id": b, "name": s.buckets.get(b).map(|x| x.name.clone())}))
            .collect();
        return (200, json!({
            "accountId": "acc1",
            "authorizationToken": tok,
            "apiInfo": {"storageApi": {
                "apiUrl": base, "s3ApiUrl": "https://s3.eu-central-003.backblazeb2.com",
                "allowed": {"buckets": buckets, "capabilities": k.caps, "namePrefix": null}
            }}
        }));
    }
    let Some(kid) = s.tokens.get(auth).cloned() else { return err(401, "bad_auth_token") };
    let k = s.keys[&kid].clone();
    let has = |c: &str| k.caps.iter().any(|x| x == c);
    let in_scope = |b: &str| k.buckets.as_ref().is_none_or(|l| l.iter().any(|x| x == b));
    let op = path.trim_start_matches("/b2api/v4/");
    match op {
        "b2_list_buckets" => {
            if !has("listBuckets") {
                return err(401, "unauthorized");
            }
            let list: Vec<Value> = s
                .buckets
                .iter()
                .filter(|(id, _)| in_scope(id))
                .map(|(id, b)| json!({"bucketId": id, "bucketName": b.name, "bucketType": b.btype,
                    "lifecycleRules": b.lifecycle, "fileLockConfiguration": {"value": {"isFileLockEnabled": b.lock}}}))
                .collect();
            (200, json!({"buckets": list}))
        }
        "b2_create_bucket" => {
            if !has("writeBuckets") {
                return err(401, "unauthorized");
            }
            let name = body["bucketName"].as_str().unwrap_or("").to_string();
            if s.buckets.values().any(|b| b.name == name) {
                return err(400, "duplicate_bucket_name");
            }
            if s.buckets.len() >= s.limit {
                return err(400, "too_many_buckets");
            }
            let id = s.id("bkt");
            let b = FBucket {
                name: name.clone(),
                btype: body["bucketType"].as_str().unwrap_or("").into(),
                lifecycle: body["lifecycleRules"].clone(),
                lock: body["fileLockEnabled"].as_bool().unwrap_or(false),
                files: vec![],
            };
            s.buckets.insert(id.clone(), b.clone());
            (200, json!({"bucketId": id, "bucketName": name, "bucketType": b.btype, "lifecycleRules": b.lifecycle}))
        }
        "b2_update_bucket" => {
            let id = body["bucketId"].as_str().unwrap_or("");
            if !has("writeBuckets") || !in_scope(id) {
                return err(401, "unauthorized");
            }
            match s.buckets.get_mut(id) {
                Some(b) => {
                    b.lifecycle = body["lifecycleRules"].clone();
                    (200, json!({"bucketId": id}))
                }
                None => err(400, "bad_bucket_id"),
            }
        }
        "b2_delete_bucket" => {
            let id = body["bucketId"].as_str().unwrap_or("").to_string();
            if !has("deleteBuckets") || !in_scope(&id) {
                return err(401, "unauthorized");
            }
            match s.buckets.get(&id) {
                None => err(400, "bad_bucket_id"),
                Some(b) if !b.files.is_empty() => err(400, "cannot_delete_non_empty_bucket"),
                Some(_) => {
                    s.buckets.remove(&id);
                    (200, json!({"bucketId": id}))
                }
            }
        }
        "b2_create_key" => {
            if !has("writeKeys") {
                return err(401, "unauthorized");
            }
            let id = s.id("004k");
            let secret = s.id("SECRET");
            let caps: Vec<String> = serde_json::from_value(body["capabilities"].clone()).unwrap();
            let buckets: Option<Vec<String>> = serde_json::from_value(body["bucketIds"].clone()).ok();
            s.keys.insert(id.clone(), FKey { secret: secret.clone(), name: body["keyName"].as_str().unwrap().into(), caps: caps.clone(), buckets: buckets.clone() });
            (200, json!({"applicationKeyId": id, "applicationKey": secret, "capabilities": caps, "bucketIds": buckets, "keyName": body["keyName"]}))
        }
        "b2_list_keys" => {
            if !has("listKeys") {
                return err(401, "unauthorized");
            }
            let keys: Vec<Value> = s
                .keys
                .iter()
                .map(|(id, k)| json!({"applicationKeyId": id, "keyName": k.name, "capabilities": k.caps, "bucketIds": k.buckets}))
                .collect();
            (200, json!({"keys": keys, "nextApplicationKeyId": null}))
        }
        "b2_delete_key" => {
            if !has("deleteKeys") {
                return err(401, "unauthorized");
            }
            let id = body["applicationKeyId"].as_str().unwrap_or("");
            s.keys.remove(id);
            s.tokens.retain(|_, v| v != id);
            (200, json!({"applicationKeyId": id}))
        }
        "b2_list_file_versions" => {
            let id = body["bucketId"].as_str().unwrap_or("");
            if !has("listFiles") || !in_scope(id) {
                return err(401, "unauthorized");
            }
            let files: Vec<Value> = s.buckets[id].files.iter().map(|(n, i)| json!({"fileName": n, "fileId": i})).collect();
            (200, json!({"files": files, "nextFileName": null, "nextFileId": null}))
        }
        "b2_delete_file_version" => {
            if !has("deleteFiles") {
                return err(401, "unauthorized");
            }
            let fid = body["fileId"].as_str().unwrap_or("");
            for b in s.buckets.values_mut() {
                b.files.retain(|(_, i)| i != fid);
            }
            (200, json!({"fileId": fid}))
        }
        _ => err(404, "not_found"),
    }
}

fn start() -> (String, Shared) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let f: Shared = Arc::new(Mutex::new(Fake { limit: 100, ..Default::default() }));
    let (f2, b2) = (f.clone(), base.clone());
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(c) = c else { continue };
            let (f, base) = (f2.clone(), b2.clone());
            std::thread::spawn(move || {
                let mut r = BufReader::new(c.try_clone().unwrap());
                let mut line = String::new();
                if r.read_line(&mut line).is_err() {
                    return;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let (mut len, mut auth) = (0usize, String::new());
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    let h = h.trim_end();
                    if h.is_empty() {
                        break;
                    }
                    let (k, v) = h.split_once(':').unwrap();
                    match k.to_ascii_lowercase().as_str() {
                        "content-length" => len = v.trim().parse().unwrap(),
                        "authorization" => auth = v.trim().to_string(),
                        _ => {}
                    }
                }
                let mut body = vec![0; len];
                r.read_exact(&mut body).unwrap();
                let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let (st, v) = handle(&f, &path, &auth, &body, &base);
                let txt = v.to_string();
                let mut c = c;
                let _ = write!(c, "HTTP/1.1 {st} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{txt}", txt.len());
            });
        }
    });
    (base, f)
}

fn add_key(f: &Shared, caps: &[&str], buckets: Option<Vec<String>>) -> Creds {
    let mut s = f.lock().unwrap();
    let id = s.id("004a");
    let secret = s.id("ADMINSECRET");
    s.keys.insert(id.clone(), FKey { secret: secret.clone(), name: "x".into(), caps: caps.iter().map(|c| c.to_string()).collect(), buckets });
    Creds { key_id: id, key: zeroize::Zeroizing::new(secret) }
}

fn admin(base: &str, f: &Shared) -> B2 {
    B2::authorize(base, &add_key(f, ADMIN_CAPS, None)).unwrap()
}

#[test]
fn provision_creates_private_random_bucket_and_scoped_key() {
    let (base, f) = start();
    let dir = tempfile::tempdir().unwrap();
    let st = dir.path().join("state.json");
    let b2 = admin(&base, &f);
    let (e, creds) = provision_tenant(&b2, &st, "owner", 100).unwrap();
    let (e2, creds2) = provision_tenant(&b2, &st, "system", 100).unwrap();
    assert_ne!(e.bucket_name, e2.bucket_name);
    for name in [&e.bucket_name, &e2.bucket_name] {
        assert_eq!(name.len(), BUCKET_NAME_LEN);
        assert!(!name.contains("owner") && !name.contains("system") && !name.contains("s3v"));
    }
    {
        let s = f.lock().unwrap();
        let b = &s.buckets[&e.bucket_id];
        assert_eq!(b.btype, "allPrivate");
        assert!(!b.lock);
        assert_eq!(b.lifecycle, live_lifecycle());
        let k = &s.keys[&creds.key_id];
        assert_eq!(k.caps, SCOPED_CAPS.iter().map(|c| c.to_string()).collect::<Vec<_>>());
        assert_eq!(k.buckets, Some(vec![e.bucket_id.clone()]));
        assert!(!k.caps.iter().any(|c| c == "writeKeys"));
        assert_eq!(k.name.len(), KEY_NAME_LEN);
        assert!(!k.name.contains("owner"));
    }
    // The scoped key sees its own bucket only and cannot manage buckets or keys.
    let scoped = B2::authorize(&base, &creds).unwrap();
    assert_eq!(scoped.buckets, vec![(e.bucket_id.clone(), Some(e.bucket_name.clone()))]);
    assert_eq!(scoped.list_buckets().unwrap().len(), 1);
    assert!(scoped.require(ADMIN_CAPS).is_err());
    assert!(scoped.create_bucket("abcdefgh", live_lifecycle()).is_err());
    assert!(scoped.list_file_versions(&e2.bucket_id, None).is_err());
    let other = B2::authorize(&base, &creds2).unwrap();
    assert!(other.list_file_versions(&e.bucket_id, None).is_err());
    // State on disk: mode 600, both tenants; a second provisioning is refused.
    assert_eq!(std::fs::metadata(&st).unwrap().permissions().mode() & 0o777, 0o600);
    let s = State::load(&st).unwrap();
    assert_eq!(s.tenants.len(), 2);
    assert!(provision_tenant(&b2, &st, "owner", 100).is_err());
    assert!(provision_tenant(&b2, &st, "Bad/Name", 100).is_err());
    let v = list(&b2, &st, 100).unwrap();
    assert_eq!(v["tenants"]["owner"]["lifecycle_ok"], json!(true));
    assert_eq!(v["tenants"]["owner"]["private"], json!(true));
    assert_eq!(v["tenants"]["owner"]["keys_in_b2"].as_array().unwrap().len(), 1);
    assert_eq!(v["unmanaged_buckets"], json!(0));
    // Output: the TOML the proxy reads, and its store block.
    let toml = credentials_toml(&creds);
    assert!(toml.contains(&format!("access_key_id = \"{}\"", creds.key_id)));
    let snip = store_snippet(&b2, "t-owner", &e.bucket_name, "/etc/s3vault/secrets/store-owner.toml");
    assert!(snip.contains("region = \"eu-central-003\"") && snip.contains(&e.bucket_name));
    assert!(format!("{creds:?}").len() < 16);
}

#[test]
fn bucket_limit_and_missing_capabilities_refuse() {
    let (base, f) = start();
    let dir = tempfile::tempdir().unwrap();
    let st = dir.path().join("state.json");
    let b2 = admin(&base, &f);
    {
        let mut s = f.lock().unwrap();
        for i in 0..99 {
            let id = s.id("bkt");
            s.buckets.insert(id, FBucket { name: format!("restic-{i}"), btype: "allPrivate".into(), lifecycle: json!([]), lock: false, files: vec![] });
        }
    }
    let v = list(&b2, &st, 100).unwrap();
    assert_eq!(v["unmanaged_buckets"], json!(99));
    provision_tenant(&b2, &st, "a", 100).unwrap();
    let e = provision_tenant(&b2, &st, "b", 100).unwrap_err();
    assert!(e.to_string().contains("limit"), "{e}");
    let weak = B2::authorize(&base, &add_key(&f, &["listBuckets", "writeBuckets", "listKeys"], None)).unwrap();
    let e = provision_tenant(&weak, &st, "c", 1000).unwrap_err();
    assert!(e.to_string().contains("writeKeys"), "{e}");
}

#[test]
fn rotate_revoke_retire_deprovision() {
    let (base, f) = start();
    let dir = tempfile::tempdir().unwrap();
    let st = dir.path().join("state.json");
    let b2 = admin(&base, &f);
    let (e, old) = provision_tenant(&b2, &st, "owner", 100).unwrap();
    let (keep_e, keep) = provision_tenant(&b2, &st, "other", 100).unwrap();
    let new = rotate_key(&b2, &st, "owner").unwrap();
    assert!(B2::authorize(&base, &old).is_ok() && B2::authorize(&base, &new).is_ok());
    assert_eq!(revoke_old_keys(&b2, &st, "owner").unwrap(), 1);
    assert!(B2::authorize(&base, &old).is_err());
    assert!(B2::authorize(&base, &new).is_ok());
    // A key made outside the tool for the same bucket is revoked by retire as well.
    let stray = add_key(&f, SCOPED_CAPS, Some(vec![e.bucket_id.clone()]));
    f.lock().unwrap().buckets.get_mut(&e.bucket_id).unwrap().files =
        vec![("o/tag/a".into(), "f1".into()), ("o/tag/a".into(), "f2".into())];
    assert!(deprovision_tenant(&b2, &st, "owner", true).is_err(), "must retire first");
    assert_eq!(retire_tenant(&b2, &st, "owner").unwrap(), 2);
    assert!(B2::authorize(&base, &new).is_err() && B2::authorize(&base, &stray).is_err());
    assert_eq!(f.lock().unwrap().buckets[&e.bucket_id].lifecycle, drain_lifecycle());
    assert!(rotate_key(&b2, &st, "owner").is_err());
    let v = list(&b2, &st, 100).unwrap();
    assert_eq!(v["tenants"]["owner"]["status"], json!("retired"));
    assert_eq!(v["tenants"]["owner"]["lifecycle_ok"], json!(true));
    let err = deprovision_tenant(&b2, &st, "owner", false).unwrap_err();
    assert!(err.to_string().contains("drain"), "{err}");
    assert_eq!(deprovision_tenant(&b2, &st, "owner", true).unwrap(), 2);
    assert!(!f.lock().unwrap().buckets.contains_key(&e.bucket_id));
    assert_eq!(State::load(&st).unwrap().tenants["owner"].status, Status::Deleted);
    // The other tenant is untouched.
    assert!(B2::authorize(&base, &keep).is_ok());
    assert!(f.lock().unwrap().buckets.contains_key(&keep_e.bucket_id));
    // A deleted tenant name may be provisioned again (new random bucket).
    let (again, _) = provision_tenant(&b2, &st, "owner", 100).unwrap();
    assert_ne!(again.bucket_name, e.bucket_name);
}

#[test]
fn sealed_credentials_open_with_the_recipient_key() {
    if std::process::Command::new("openssl").arg("version").output().is_err() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("r.key");
    let pubk = dir.path().join("r.pub");
    let ok = std::process::Command::new("openssl")
        .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out"])
        .arg(&key)
        .output()
        .unwrap()
        .status
        .success()
        && std::process::Command::new("openssl").args(["pkey", "-pubout", "-in"]).arg(&key).arg("-out").arg(&pubk).output().unwrap().status.success();
    assert!(ok);
    let creds = Creds { key_id: "004abcdefghijklmnopqrstu".into(), key: zeroize::Zeroizing::new("K".repeat(31)) };
    let plain = credentials_toml(&creds);
    let sealed = seal_for(&pubk, plain.as_bytes()).unwrap();
    assert!(sealed.starts_with(SEALED_HEADER));
    assert!(!sealed.contains(&creds.key_id) && !sealed.contains(creds.key.as_str()));
    let b64 = sealed.lines().nth(1).unwrap();
    let ct = dir.path().join("ct");
    std::fs::write(&ct, data_encoding::BASE64.decode(b64.as_bytes()).unwrap()).unwrap();
    let out = std::process::Command::new("openssl")
        .args(["pkeyutl", "-decrypt", "-inkey"])
        .arg(&key)
        .args(["-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256", "-pkeyopt", "rsa_mgf1_md:sha256", "-in"])
        .arg(&ct)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8(out.stdout).unwrap(), plain.as_str());
}

#[test]
fn random_names_are_uniform_lowercase() {
    let mut first = std::collections::BTreeSet::new();
    for _ in 0..2000 {
        let n = random_name(BUCKET_NAME_LEN);
        assert_eq!(n.len(), BUCKET_NAME_LEN);
        assert!(n.as_bytes()[0].is_ascii_lowercase());
        assert!(n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
        first.insert(n.as_bytes()[0]);
    }
    assert_eq!(first.len(), 26);
    assert_eq!(short("0030123456789abc0000000042"), "…0042");
}
