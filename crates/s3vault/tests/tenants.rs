//! Format v2 with per-tenant keys (decisions D1, D3, D4): crypto-shredding across every tier, the erasure
//! ledger and its replay after restores, object erasure, per-tenant snapshot restore, pending tenants and
//! the migration of v1 objects. A real S3 client talks to s3vault over in-process S3 servers (s3s-fs);
//! the key service's tenant and ledger files are edited the way `s3vault-keyd` edits them.

use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use s3vault::config::Config;
use s3vault::index::{Index, LIVE, ObjRow, TOMBSTONE};
use s3vault_format::keyring::Keyring;
use s3vault_format::keys2::{
    Bundle, MasterV2, TenantKeyring, open_tenant_escrow, prune_escrow_dir, seal_tenant_escrow,
};
use s3vault_format::ledger::{self, Ledger};
use s3vault_format::object;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

const AK: &str = "backend-ak";
const SK: &str = "backend-secret-key";
const TOKEN: &str = "test-admin-token-0123456789abcdef0123456789";

async fn start_fs_s3(root: &Path) -> SocketAddr {
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
            tokio::spawn(
                http.serve_connection(TokioIo::new(sock), service.clone())
                    .into_owned(),
            );
        }
    });
    addr
}

fn client(endpoint: &str, ak: &str, sk: &str) -> Client {
    Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .endpoint_url(endpoint)
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new(ak, sk, None, None, "test"))
            .force_path_style(true)
            .build(),
    )
}

struct Env {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    store_root: PathBuf,
    running: Option<s3vault::Running>,
    c: Client,
}

impl Env {
    fn vault(&self) -> &Arc<s3vault::vault::Vault> {
        &self.running.as_ref().unwrap().vault
    }
    fn admin(&self) -> String {
        format!("http://{}", self.running.as_ref().unwrap().admin_addr.unwrap())
    }
    async fn post(&self, path: &str) -> serde_json::Value {
        let r = reqwest::Client::new()
            .post(format!("{}{path}", self.admin()))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        serde_json::from_slice(&r.bytes().await.unwrap()).unwrap()
    }
    async fn get_text(&self, path: &str) -> String {
        reqwest::Client::new()
            .get(format!("{}{path}", self.admin()))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    }
    fn keys_dir(&self) -> PathBuf {
        self.dir.join("keyd")
    }
    fn master(&self) -> Arc<MasterV2> {
        Arc::new(
            MasterV2::parse(&std::fs::read_to_string(self.keys_dir().join("keyring")).unwrap())
                .unwrap(),
        )
    }
    fn tenants(&self) -> TenantKeyring {
        TenantKeyring::parse(&std::fs::read_to_string(self.keys_dir().join("tenants")).unwrap())
            .unwrap()
    }
    fn ledger(&self) -> Ledger {
        Ledger::parse(&std::fs::read_to_string(self.keys_dir().join("ledger.jsonl")).unwrap())
            .unwrap()
    }
    /// What `s3vault-keyd tenant-erase` does: ledger entry, key removed.
    fn keyd_erase(&self, name: &str) -> ledger::Entry {
        let m = self.master();
        let mut tk = self.tenants();
        let mut l = self.ledger();
        let e = tk.erase(name, 1000).unwrap().clone();
        let entry = l
            .append(
                ledger::TENANT_ERASED,
                &e.id_hex(),
                &m.tenant_tag(&e.id),
                serde_json::json!({"erased_at": 1000}),
                1000,
            )
            .clone();
        std::fs::write(self.keys_dir().join("ledger.jsonl"), l.to_text()).unwrap();
        std::fs::write(self.keys_dir().join("tenants"), tk.to_text().as_str()).unwrap();
        entry
    }
    fn tenant(&self, bucket: &str) -> Arc<s3vault::vault::TenantRt> {
        let u = self.vault().unlocked().unwrap();
        u.tenant_loaded(&self.vault().buckets[bucket].tenant).unwrap()
    }
}

fn write(p: &Path, s: &str) {
    std::fs::write(p, s).unwrap();
}

/// Tenants `t1` (buckets `data`, `data2`) and `t2` (bucket `plain`); `pending` lists tenants left pending.
async fn setup_with(pending: &[&str]) -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let store_root = dir.join("store");
    let store = start_fs_s3(&store_root).await;
    write(
        &dir.join("backend.toml"),
        &format!("access_key_id = \"{AK}\"\nsecret_access_key = \"{SK}\"\n"),
    );
    write(&dir.join("app.secret"), "app-secret\n");
    write(&dir.join("admin.token"), &format!("{TOKEN}\n"));
    let kd = dir.join("keyd");
    std::fs::create_dir_all(&kd).unwrap();
    let mut m = MasterV2::generate(None);
    m.confirm_escrow(&m.escrow_digest(), "test", 1).unwrap();
    let mut tk = TenantKeyring::default();
    for t in ["t1", "t2"] {
        tk.create(t, 1).unwrap();
    }
    let mut copy = tk.clone();
    for p in pending {
        copy.tenants.remove(*p);
    }
    tk.confirm_escrow(&copy, "d", "test", 1).unwrap();
    write(&kd.join("keyring"), &m.to_text());
    write(&kd.join("tenants"), &tk.to_text());
    write(&kd.join("ledger.jsonl"), "");
    let cfg_text = format!(
        r#"
[server]
listen = ["127.0.0.1:0"]
admin_listen = "127.0.0.1:0"
admin_token_file = "{d}/admin.token"
data_dir = "{d}/data"
memory_spool_max = 100000
index_snapshot_secs = 0

[keys]
source = "file"
file = "{d}/keyd/keyring"
tenants_file = "{d}/keyd/tenants"
ledger_file = "{d}/keyd/ledger.jsonl"
retry_secs = 1

[stores.main]
endpoint = "http://{store}"
bucket = "cipher"
credentials_file = "{d}/backend.toml"

[[buckets]]
name = "data"
store = "main"
tenant = "t1"

[[buckets]]
name = "data2"
store = "main"
tenant = "t1"

[[buckets]]
name = "plain"
store = "main"
tenant = "t2"

[[clients]]
name = "app"
access_key_id = "APPKEY"
secret_file = "{d}/app.secret"
buckets = ["data", "data2", "plain"]
"#,
        d = dir.display()
    );
    let cfg: Config = toml::from_str(&cfg_text).unwrap();
    cfg.validate().unwrap();
    client(&format!("http://{store}"), AK, SK)
        .create_bucket()
        .bucket("cipher")
        .send()
        .await
        .unwrap();
    let running = s3vault::start(cfg).await.unwrap();
    for _ in 0..100 {
        if !running.vault.is_locked() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!running.vault.is_locked(), "{:?}", running.vault.last_unlock_error.read().unwrap());
    let c = client(&format!("http://{}", running.s3_addrs[0]), "APPKEY", "app-secret");
    Env {
        _tmp: tmp,
        dir,
        store_root,
        running: Some(running),
        c,
    }
}

async fn put(c: &Client, b: &str, k: &str, body: Vec<u8>) {
    c.put_object()
        .bucket(b)
        .key(k)
        .body(ByteStream::from(body))
        .send()
        .await
        .unwrap();
}

async fn get(c: &Client, b: &str, k: &str) -> Result<Vec<u8>, u16> {
    match c.get_object().bucket(b).key(k).send().await {
        Ok(o) => Ok(o.body.collect().await.unwrap().into_bytes().to_vec()),
        Err(aws_sdk_s3::error::SdkError::ServiceError(se)) => Err(se.raw().status().as_u16()),
        Err(e) => panic!("{e:?}"),
    }
}

fn data(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + seed as usize) % 251) as u8).collect()
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            if e.path().is_dir() {
                stack.push(e.path());
            } else {
                out.push(e.path());
            }
        }
    }
    out.sort();
    out
}

/// Stored objects (ciphertext files) of the s3s-fs store: names below `cipher/o/`.
fn stored(env_root: &Path, tag: &str) -> Vec<PathBuf> {
    files_under(&env_root.join("cipher").join("o").join(tag))
        .into_iter()
        .filter(|p| !p.to_string_lossy().contains(".s3s"))
        .collect()
}

fn copy_tree(from: &Path, to: &Path) {
    for f in files_under(from) {
        let rel = f.strip_prefix(from).unwrap();
        let dst = to.join(rel);
        std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
        std::fs::copy(&f, &dst).unwrap();
    }
}

/// D1 + D4: erasing a tenant makes its data unreadable in every tier (store versions, follower copy,
/// snapshots, staging, escrow after R_tk), purges what the proxy controls, writes a proof, and a replay of
/// the ledger after restores (store, follower, an old key-service backup) never brings the tenant back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tenant_erasure_shreds_every_tier_and_replay_after_restore() {
    let mut env = setup_with(&[]).await;
    let c = env.c.clone();
    put(&c, "data", "a", data(200_000, 1)).await;
    put(&c, "data", "b", data(5_000, 2)).await;
    put(&c, "data2", "c", data(10, 3)).await;
    put(&c, "plain", "p", data(70_000, 4)).await;
    // a multipart upload in progress (staged on the proxy's disk under the tenant's staging key)
    let up = c.create_multipart_upload().bucket("data").key("mp").send().await.unwrap();
    c.upload_part()
        .bucket("data")
        .key("mp")
        .upload_id(up.upload_id().unwrap())
        .part_number(1)
        .body(ByteStream::from(data(6_000_000, 5)))
        .send()
        .await
        .unwrap();
    let t1 = env.tenant("data");
    let t2 = env.tenant("plain");
    let (id1, tag1, tag2) = (t1.keys.id_hex(), t1.keys.tag.clone(), t2.keys.tag.clone());
    let staging = env.dir.join("data/staging").join(&id1);
    assert!(!files_under(&staging).is_empty());
    // per-tenant index snapshots
    let snap = env.post("/snapshot").await;
    assert_eq!(snap["tenants"], 2, "{snap}");
    // Names: every t1 object lives under its own tag folder; the store sees only ciphertext.
    let t1_files = stored(&env.store_root, &tag1);
    assert_eq!(t1_files.len(), 4, "a, b, c and the snapshot: {t1_files:?}");
    for f in &t1_files {
        let b = std::fs::read(f).unwrap();
        assert_eq!(&b[..8], b"S3VAULT2");
    }
    // An old object version (as B2 keeps it after an overwrite), and the follower copy.
    let a_name = env.vault().store_name(&t1, &env.vault().buckets["data"].store, "data", "a");
    let version = env.dir.join("b2-version-of-a");
    std::fs::copy(env.store_root.join("cipher").join(&a_name), &version).unwrap();
    put(&c, "data", "a", data(1_000, 9)).await;
    let follower = env.dir.join("follower");
    copy_tree(&env.store_root.join("cipher"), &follower.join("cipher"));
    // an escrow copy of the tenant keyring issued before the erasure (holds K_t)
    let master = env.master();
    let escrow_dir = env.dir.join("escrow");
    std::fs::create_dir_all(&escrow_dir).unwrap();
    let day = 86_400;
    let t_erase = 1_000_000_000u64;
    std::fs::write(
        escrow_dir.join(s3vault_format::keys2::escrow_file_name(t_erase - 5 * day)),
        seal_tenant_escrow(&master, &env.tenants(), t_erase - 5 * day),
    )
    .unwrap();
    let old_tenants_text = std::fs::read_to_string(env.keys_dir().join("tenants")).unwrap();
    drop(t1);

    // --- the proxy refuses to erase before the key service has
    let early = env.post("/tenant/erase?tenant=t1&confirm=t1").await;
    assert!(early["error"].as_str().unwrap().contains("still active"), "{early}");
    let wrong = env.post("/tenant/erase?tenant=t1&confirm=t2").await;
    assert!(wrong["error"].is_string());

    // --- erase: key service first, then the proxy
    let keyd_entry = env.keyd_erase("t1");
    std::fs::write(
        escrow_dir.join(s3vault_format::keys2::escrow_file_name(t_erase)),
        seal_tenant_escrow(&master, &env.tenants(), t_erase),
    )
    .unwrap();
    let res = env.post("/tenant/erase?tenant=t1&confirm=t1").await;
    let proof = &res["proof"];
    assert_eq!(proof["tenant_id"], id1, "{res}");
    assert_eq!(proof["keyd_ledger_entry"], keyd_entry.hash);
    assert_eq!(proof["index_partition_removed"], true);
    assert_eq!(proof["staging_removed"], true);
    assert_eq!(proof["purge"]["remaining_after"], 0);
    assert_eq!(proof["index_rows"]["live"], 4, "a, b, c and the snapshot row");
    assert!(proof["manifest_names"].as_u64().unwrap() >= 4);
    assert_eq!(proof["k_t_fingerprint"].as_str().unwrap().len(), 16);

    // live tier: refused, nothing left in the store, no index partition, no staging
    assert_eq!(get(&c, "data", "b").await, Err(403));
    assert_eq!(get(&c, "data2", "c").await, Err(403));
    assert!(stored(&env.store_root, &tag1).is_empty());
    assert!(!env.vault().tenant_index_path(&id1).exists());
    assert!(!staging.exists());
    // the other tenant is untouched
    assert_eq!(get(&c, "plain", "p").await.unwrap(), data(70_000, 4));
    assert_eq!(stored(&env.store_root, &tag2).len(), 2, "p and t2's snapshot");

    // every other tier: the follower copy, the old version and the old snapshot do not open any more
    let b = Bundle::parse(&format!(
        "%master\n{}%tenants\n{}%ledger\n{}",
        master.to_text().as_str(),
        env.tenants().to_text().as_str(),
        env.ledger().to_text()
    ))
    .unwrap();
    let m2 = Arc::new(b.master);
    assert!(m2.tenant_keys(&b.tenants.tenants["t1"]).is_err(), "K_t is gone");
    let k2 = m2.tenant_keys(&b.tenants.tenants["t2"]).unwrap();
    let follower_t1 = stored(&follower, &tag1);
    assert_eq!(follower_t1.len(), 4);
    for f in follower_t1.iter().chain(std::iter::once(&version)) {
        let bytes = std::fs::read(f).unwrap();
        assert!(object::open_head_v2(&k2, &bytes).is_err());
        // with the root only the opaque tenant id remains
        assert_eq!(hex::encode(object::open_tenant_box(&m2, &bytes).unwrap()), id1);
    }

    // escrow (D3): the pre-erasure copy still holds K_t, so it is destroyed within 30 days; the newest
    // copy (issued at the erasure) never holds it.
    let (_, before) = open_tenant_escrow(&master, &std::fs::read(escrow_dir.join(s3vault_format::keys2::escrow_file_name(t_erase - 5 * day))).unwrap()).unwrap();
    assert!(before.tenants["t1"].k_t.is_some());
    assert!(prune_escrow_dir(&escrow_dir, t_erase + 10 * day, 30 * day).unwrap().is_empty());
    let pruned = prune_escrow_dir(&escrow_dir, t_erase + 26 * day, 30 * day).unwrap();
    assert_eq!(pruned.len(), 1, "older than 30 days at erasure + 25 days");
    let left = files_under(&escrow_dir);
    assert_eq!(left.len(), 1);
    let (_, newest) = open_tenant_escrow(&master, &std::fs::read(&left[0]).unwrap()).unwrap();
    assert!(newest.tenants["t1"].k_t.is_none());

    // --- restore 1: the store from the follower copy (or B2 versions re-promoted): replay removes t1 again
    copy_tree(&follower.join("cipher"), &env.store_root.join("cipher"));
    assert_eq!(stored(&env.store_root, &tag1).len(), 4);
    let dry = env.post("/ledger/replay?dry_run=1").await;
    assert_eq!(dry["tenant_objects_found"], 4, "{dry}");
    assert_eq!(stored(&env.store_root, &tag1).len(), 4, "dry run deletes nothing");
    let rep = env.post("/ledger/replay").await;
    assert_eq!(rep["tenant_objects_deleted"], 4, "{rep}");
    assert!(stored(&env.store_root, &tag1).is_empty());
    assert_eq!(get(&c, "plain", "p").await.unwrap(), data(70_000, 4));
    // --- restore 2: the follower itself (a directory copy), replayed without any key
    let entries: Vec<ledger::Entry> = env.ledger().entries;
    let r = s3vault::erasure::replay(
        &entries,
        &s3vault::erasure::ReplayTarget::Dir {
            dir: follower.join("cipher"),
            prefix: "o/".into(),
        },
        false,
    )
    .await
    .unwrap();
    assert_eq!(r.tenant_objects_deleted, 4);
    assert!(stored(&follower, &tag1).is_empty());
    assert_eq!(stored(&follower, &tag2).len(), 2);
    // --- restore 3: the key service from an old backup (t1 active again, ledger without the erasure):
    // the proxy keeps its ledger copy and refuses the tenant.
    std::fs::write(env.keys_dir().join("tenants"), &old_tenants_text).unwrap();
    std::fs::write(env.keys_dir().join("ledger.jsonl"), "").unwrap();
    let refreshed = env.post("/unlock").await;
    assert_eq!(refreshed["refreshed"], true, "{refreshed}");
    let st: Vec<serde_json::Value> = serde_json::from_value(refreshed["tenants"].clone()).unwrap();
    assert_eq!(st.iter().find(|t| t["name"] == "t1").unwrap()["status"], "erased");
    assert_eq!(get(&c, "data", "b").await, Err(403));
    // the proof is shown by the verify call (outbox entry), and nothing is left
    let v: serde_json::Value = serde_json::from_str(&env.get_text(&format!("/tenant/verify-erasure?id={id1}")).await).unwrap();
    assert_eq!(v["objects_remaining_per_store"]["main"], 0, "{v}");
    assert_eq!(v["index_partition_present"], false);
    assert_eq!(v["proofs"].as_array().unwrap().len(), 1);
    // the outbox is a valid chain for `s3vault-keyd ledger-import`
    let outbox = Ledger::parse(&env.get_text("/ledger/outbox").await).unwrap();
    assert_eq!(outbox.entries[0].kind, ledger::ERASURE_PROOF);
    env.running.take().unwrap().shutdown().await;
}

/// D4: erasing one object records the hash of its head, so a replay removes exactly that version from a
/// restored store, and never a later write of the same key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn object_erasure_and_replay() {
    let mut env = setup_with(&[]).await;
    let c = env.c.clone();
    put(&c, "plain", "x", data(3_000, 1)).await;
    put(&c, "plain", "y", data(3_000, 2)).await;
    let t2 = env.tenant("plain");
    let x_name = env.vault().store_name(&t2, &env.vault().buckets["plain"].store, "plain", "x");
    let x_path = env.store_root.join("cipher").join(&x_name);
    let saved = env.dir.join("x-version");
    std::fs::copy(&x_path, &saved).unwrap();
    assert!(env.post("/object/erase?bucket=plain&key=x").await["error"].is_string(), "confirm needed");
    let e = env.post("/object/erase?bucket=plain&key=x&confirm=1").await;
    assert_eq!(e["outbox_entry"]["kind"], ledger::OBJECT_ERASED, "{e}");
    assert_eq!(get(&c, "plain", "x").await, Err(404));
    // restore the erased version: replay deletes it
    std::fs::copy(&saved, &x_path).unwrap();
    let rep = env.post("/ledger/replay").await;
    assert_eq!(rep["object_versions_deleted"], 1, "{rep}");
    assert!(!x_path.exists());
    // a later, legitimate write of the same key is not touched by a replay
    put(&c, "plain", "x", data(10, 7)).await;
    let rep = env.post("/ledger/replay").await;
    assert_eq!(rep["object_versions_deleted"], 0, "{rep}");
    assert_eq!(get(&c, "plain", "x").await.unwrap(), data(10, 7));
    assert_eq!(get(&c, "plain", "y").await.unwrap(), data(3_000, 2));
    env.running.take().unwrap().shutdown().await;
}

/// D1: one tenant's index is restored from its own snapshot alone; the other tenant is not read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_tenant_snapshot_restore() {
    let mut env = setup_with(&[]).await;
    let c = env.c.clone();
    for i in 0..20 {
        put(&c, "data", &format!("k/{i:02}"), data(100 + i, i as u8)).await;
    }
    put(&c, "data2", "z", data(5, 1)).await;
    c.delete_object().bucket("data").key("k/03").send().await.unwrap();
    for i in 0..5 {
        put(&c, "plain", &format!("p/{i}"), data(50, i as u8)).await;
    }
    env.post("/snapshot").await;
    // written after the snapshot: read from its header
    put(&c, "data", "late", data(7, 7)).await;
    let t1 = env.tenant("data");
    let fresh = Index::open(&env.dir.join("t1-restored.db"), Some(&t1.keys.index_key)).unwrap();
    let rep = s3vault::background::rebuild(env.vault().clone(), &t1.keys, &fresh, true, 4)
        .await
        .unwrap();
    assert_eq!(rep.snapshot_rows, 20, "19 live + data2/z (the deleted key is gone in a bucket without fallback): {rep:?}");
    assert_eq!(rep.errors, 0);
    assert_eq!(rep.listed, 22, "only t1's prefix is listed: 20 objects, late, the snapshot");
    for b in ["data", "data2"] {
        assert_eq!(fresh.counts(b).unwrap(), t1.index.counts(b).unwrap(), "{b}");
    }
    assert_eq!(fresh.counts("plain").unwrap(), (0, 0, 0));
    assert!(fresh.get("data", "late").unwrap().is_some());
    // export manifest of one tenant's bucket
    let m: serde_json::Value = serde_json::from_str(&env.get_text("/manifest?bucket=data").await).unwrap();
    assert_eq!(m["items"].as_array().unwrap().len(), 20);
    env.running.take().unwrap().shutdown().await;
}

/// D1/D3: a tenant whose escrow copy is not confirmed is never served; confirming activates it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_tenant_is_not_served_until_escrowed() {
    let mut env = setup_with(&["t2"]).await;
    let c = env.c.clone();
    let err = c
        .put_object()
        .bucket("plain")
        .key("k")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        match err {
            aws_sdk_s3::error::SdkError::ServiceError(se) => se.raw().status().as_u16(),
            _ => 0,
        },
        503
    );
    put(&c, "data", "ok", b"x".to_vec()).await;
    // the owner confirms an escrow copy holding t2
    let mut tk = env.tenants();
    let copy = tk.clone();
    assert_eq!(tk.confirm_escrow(&copy, "dd", "mac", 2).unwrap(), ["t2"]);
    std::fs::write(env.keys_dir().join("tenants"), tk.to_text().as_str()).unwrap();
    env.post("/unlock").await;
    put(&c, "plain", "k", b"y".to_vec()).await;
    assert_eq!(get(&c, "plain", "k").await.unwrap(), b"y");
    env.running.take().unwrap().shutdown().await;
}

/// D1 migration: v1 objects (sealed under the legacy keyring) are re-encrypted as v2 objects of their
/// bucket's tenant with the same bytes, ETag, metadata, generation and origin; a second pass with
/// `delete_v1` removes the v1 objects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migrate_v1_objects_to_v2() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let store_root = dir.join("store");
    let store = start_fs_s3(&store_root).await;
    write(
        &dir.join("backend.toml"),
        &format!("access_key_id = \"{AK}\"\nsecret_access_key = \"{SK}\"\n"),
    );
    client(&format!("http://{store}"), AK, SK)
        .create_bucket()
        .bucket("cipher")
        .send()
        .await
        .unwrap();
    let legacy = Keyring::generate();
    let cfg_text = format!(
        r#"
[server]
listen = []
data_dir = "{d}/data"
memory_spool_max = 100000
[keys]
source = "file"
file = "{d}/keyring"
[stores.main]
endpoint = "http://{store}"
bucket = "cipher"
credentials_file = "{d}/backend.toml"
[[buckets]]
name = "media"
store = "main"
tenant = "owner"
[[buckets]]
name = "scratch"
store = "main"
tenant = "owner"
"#,
        d = dir.display()
    );
    let cfg: Config = toml::from_str(&cfg_text).unwrap();
    // a v1 deployment: objects in the store, rows in a v1 index
    std::fs::create_dir_all(dir.join("data")).unwrap();
    let old = Index::open(&dir.join("data/index.db"), Some(&legacy.index_db_key())).unwrap();
    old.meta_set("keyring_fingerprint", &legacy.fingerprint()).unwrap();
    let remote = s3vault::remote::Remote::from_cfg("v1", &cfg.stores["main"], None).unwrap();
    let mut expected = Vec::new();
    for (i, (b, k, n)) in [("media", "audio/1/000001.opus", 70_000usize), ("media", "audio/1/000002.opus", 0), ("scratch", "s", 5)]
        .into_iter()
        .enumerate()
    {
        let plain = data(n, i as u8);
        let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&plain));
        let h = object::Header {
            v: 1,
            bucket: b.into(),
            key: k.into(),
            size: n as u64,
            etag: format!("etag{i}"),
            sha256: sha.clone(),
            content_type: Some("audio/ogg".into()),
            meta: [("m".to_string(), "v".to_string())].into(),
            generation: 100 + i as u64,
            mtime_ms: 1_700_000_000_000,
            tombstone: false,
        };
        let (ct, seal) = object::seal_all(&legacy, &h, &plain).unwrap();
        let name = format!("o/{}", object::store_name(&legacy.name_key(), b, k));
        let len = ct.len() as u64;
        remote.put(&name, reqwest::Body::from(ct), len).await.unwrap();
        old.upsert(&ObjRow {
            bucket: b.into(),
            key: k.into(),
            state: LIVE,
            size: n as u64,
            etag: h.etag.clone(),
            sha256: sha,
            content_type: h.content_type.clone(),
            meta: serde_json::to_string(&h.meta).unwrap(),
            generation: h.generation,
            kid: seal.kid,
            salt: seal.salt,
            hlen: seal.header_sealed_len,
            ad: seal.ad,
            mtime_ms: h.mtime_ms,
            origin: 1,
        })
        .unwrap();
        expected.push((b, k, plain, name));
    }
    let mut tomb = old.get("media", "audio/1/000002.opus").unwrap().unwrap();
    tomb.key = "gone".into();
    tomb.state = TOMBSTONE;
    old.upsert(&tomb).unwrap();
    // the key service after upgrade-v2: a new escrowed root, the v1 keys as legacy, tenant `owner`
    let mut m = MasterV2::generate(Some(Keyring::parse(&legacy.to_text()).unwrap()));
    m.confirm_escrow(&m.escrow_digest(), "mac", 1).unwrap();
    let mut tk = TenantKeyring::default();
    tk.create("owner", 1).unwrap();
    let copy = tk.clone();
    tk.confirm_escrow(&copy, "d", "mac", 1).unwrap();
    let bundle_text = format!("%master\n{}%tenants\n{}%ledger\n", m.to_text().as_str(), tk.to_text().as_str());
    let vault = s3vault::vault::Vault::new(cfg).unwrap();
    vault.unlock(Bundle::parse(&bundle_text).unwrap()).unwrap();
    let b = Bundle::parse(&bundle_text).unwrap();
    let lk = s3vault::background::legacy_keyring(&b).unwrap();
    assert_eq!(lk.fingerprint(), legacy.fingerprint());
    let rep = s3vault::migrate::migrate_v2(&vault, &lk, &old, false).await.unwrap();
    assert_eq!((rep.migrated_live, rep.migrated_tombstones, rep.errors, rep.sha_mismatch), (3, 1, 0, 0), "{rep:?}");
    for (b, k, plain, v1name) in &expected {
        assert_eq!(&s3vault::background::read_all(&vault, b, k).await.unwrap(), plain, "{b}/{k}");
        let u = vault.unlocked().unwrap();
        let t = u.tenant("owner").unwrap();
        let new = t.index.get(b, k).unwrap().unwrap();
        let oldr = old.get(b, k).unwrap().unwrap();
        assert_eq!((new.etag, new.generation, new.origin, new.meta, new.mtime_ms), (oldr.etag, oldr.generation, oldr.origin, oldr.meta, oldr.mtime_ms));
        assert!(store_root.join("cipher").join(v1name).exists(), "v1 kept until --delete-v1");
    }
    let t = vault.unlocked().unwrap().tenant("owner").unwrap();
    assert_eq!(t.index.get("media", "gone").unwrap().unwrap().state, TOMBSTONE);
    // second pass: nothing re-encrypted, v1 objects deleted
    let rep2 = s3vault::migrate::migrate_v2(&vault, &lk, &old, true).await.unwrap();
    assert_eq!((rep2.already_v2, rep2.v1_deleted, rep2.migrated_live), (4, 4, 0), "{rep2:?}");
    for (b, k, plain, v1name) in &expected {
        assert!(!store_root.join("cipher").join(v1name).exists());
        assert_eq!(&s3vault::background::read_all(&vault, b, k).await.unwrap(), plain);
    }
}
