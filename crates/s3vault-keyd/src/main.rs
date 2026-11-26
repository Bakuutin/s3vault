//! s3vault-keyd: a tiny key service.
//!
//! It holds the master keyring (`DIR/keyring`), the tenant keyring (`DIR/tenants`), the erasure ledger
//! (`DIR/ledger.jsonl`), sealed escrow copies of the tenant keyring (`DIR/escrow/`) and a pre-shared key
//! (`DIR/psk`). It hands the keys to proxies that connect from an allow-listed address and prove the PSK
//! (see `s3vault_format::keyproto`): protocol v2 clients get the bundle (master, tenants, ledger), v1
//! clients the legacy v1 keyring (rollback to a v1 proxy). It never prints key material. The files are
//! re-read for every request, so no change needs a restart.
//!
//! ```text
//! s3vault-keyd init --dir DIR                 create a v2 master keyring and the psk (refuses to overwrite)
//! s3vault-keyd upgrade-v2 --dir DIR           v1 keyring -> v2 master with a new random root; the v1 keys
//!                                             are kept as legacy keys (migration, rollback); keyring.v1.<t> backup
//! s3vault-keyd serve --dir DIR --listen ADDR --allow IP[,IP...]
//! s3vault-keyd rotate --dir DIR               v2: next KEK generation (deterministic, no new escrow)
//!                                             v1: add a key as pending (used only after escrow-confirm)
//! s3vault-keyd escrow-export --dir DIR        write the master keyring to stdout (refuses a terminal)
//! s3vault-keyd escrow-digest --file COPY      non-secret digest of a master keyring copy
//! s3vault-keyd escrow-confirm --dir DIR --digest D --place P
//! s3vault-keyd fingerprint --dir DIR          non-secret fingerprint, escrow state, tenants, ledger head
//!
//! s3vault-keyd tenant-create --dir DIR --name N   new tenant, pending until its escrow copy is confirmed
//! s3vault-keyd tenant-erase --dir DIR --name N    destroy K_t, ledger entry, new escrow copy
//! s3vault-keyd tenant-list --dir DIR
//! s3vault-keyd escrow-cat --dir DIR [--file NAME] write the newest (or named) sealed tenant escrow copy to stdout
//! s3vault-keyd tenant-escrow-confirm --dir DIR --digest D --place P
//!                                             the newest copy is held at P (digest as computed there);
//!                                             pending tenants in it become active
//! s3vault-keyd escrow-prune --dir DIR [--max-age-days 30]   delete escrow copies older than the limit
//! s3vault-keyd ledger-import --dir DIR < OUTBOX   import a proxy's outbox (object erasures, proofs)
//! s3vault-keyd ledger-show --dir DIR          verify and print the ledger (no secrets)
//! s3vault-keyd fetch --addr ADDR --psk FILE   test client: fetch and print the fingerprint only
//! ```

use s3vault_format::keyproto;
use s3vault_format::keyring::Keyring;
use s3vault_format::keys2::{
    Bundle, MasterV2, TenantKeyring, escrow_file_digest, escrow_file_name, escrow_file_time,
    open_tenant_escrow, prune_escrow_dir, seal_tenant_escrow,
};
use s3vault_format::ledger::{self, Ledger};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use zeroize::Zeroizing;

fn usage() -> ! {
    eprintln!("usage: see the header of crates/s3vault-keyd/src/main.rs or README.md");
    std::process::exit(2)
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn need(args: &[String], name: &str) -> String {
    arg(args, name).unwrap_or_else(|| usage())
}

fn log(msg: &str) {
    eprintln!("{} s3vault-keyd: {msg}", now_secs());
}

fn harden() {
    unsafe {
        let rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &rl);
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn die(e: impl std::fmt::Display) -> ! {
    eprintln!("{e}");
    std::process::exit(1)
}

fn write_secret(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// Replace a file atomically (write `<name>.new` mode 600, fsync, rename).
fn replace_file(path: &Path, data: &[u8]) {
    let tmp = path.with_extension("new");
    let _ = fs::remove_file(&tmp);
    write_secret(&tmp, data).unwrap_or_else(|e| die(format!("write {}: {e}", tmp.display())));
    fs::rename(&tmp, path).unwrap_or_else(|e| die(format!("rename {}: {e}", path.display())));
}

enum Master {
    V1(Keyring),
    V2(MasterV2),
}

fn read_master(dir: &Path) -> Result<Master, String> {
    let text = Zeroizing::new(
        fs::read_to_string(dir.join("keyring")).map_err(|e| format!("read keyring: {e}"))?,
    );
    if text.trim_start().starts_with("s3vault-keyring v2") {
        MasterV2::parse(&text).map(Master::V2).map_err(|e| e.to_string())
    } else {
        Keyring::parse(&text).map(Master::V1).map_err(|e| e.to_string())
    }
}

fn read_v2(dir: &Path) -> MasterV2 {
    match read_master(dir).unwrap_or_else(|e| die(e)) {
        Master::V2(m) => m,
        Master::V1(_) => die("this needs a v2 master keyring (run upgrade-v2 first)"),
    }
}

fn read_tenants(dir: &Path) -> Result<TenantKeyring, String> {
    match fs::read_to_string(dir.join("tenants")) {
        Ok(t) => {
            let t = Zeroizing::new(t);
            TenantKeyring::parse(&t).map_err(|e| e.to_string())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TenantKeyring::default()),
        Err(e) => Err(format!("read tenants: {e}")),
    }
}

fn read_ledger(dir: &Path) -> Result<Ledger, String> {
    match fs::read_to_string(dir.join("ledger.jsonl")) {
        Ok(t) => Ledger::parse(&t).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Ledger::default()),
        Err(e) => Err(format!("read ledger: {e}")),
    }
}

fn read_psk(path: &Path) -> Result<s3vault_format::keyring::Key32, String> {
    let text = Zeroizing::new(fs::read_to_string(path).map_err(|e| format!("read psk: {e}"))?);
    keyproto::parse_psk(&text).map_err(|e| e.to_string())
}

/// Write a new sealed escrow copy of the tenant keyring; returns (file name, digest).
fn issue_escrow(dir: &Path, m: &MasterV2, tk: &TenantKeyring) -> (String, String) {
    let edir = dir.join("escrow");
    fs::create_dir_all(&edir).unwrap_or_else(|e| die(e));
    let mut t = now_secs();
    while edir.join(escrow_file_name(t)).exists() {
        t += 1;
    }
    let sealed = seal_tenant_escrow(m, tk, t);
    let name = escrow_file_name(t);
    write_secret(&edir.join(&name), &sealed).unwrap_or_else(|e| die(e));
    (name, escrow_file_digest(&sealed))
}

fn newest_escrow(dir: &Path) -> Option<(String, PathBuf)> {
    let mut v: Vec<(u64, String, PathBuf)> = fs::read_dir(dir.join("escrow"))
        .ok()?
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            escrow_file_time(&n).map(|t| (t, n, e.path()))
        })
        .collect();
    v.sort();
    v.pop().map(|(_, n, p)| (n, p))
}

fn refuse_tty() {
    if unsafe { libc::isatty(1) } == 1 {
        die("refusing to write key material to a terminal; redirect stdout to the copy");
    }
}

const ESCROW_STEPS: &str = "next: escrow-cat > copy on the owner's device; `s3vault tenant-escrow-check --file copy \
--keyring <master copy>` there; then tenant-escrow-confirm --digest <digest> --place <where>";

fn main() {
    harden();
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or_else(|| usage());
    let dir = || PathBuf::from(need(&args, "--dir"));
    match cmd {
        "init" => {
            let dir = dir();
            fs::create_dir_all(&dir).expect("create dir");
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod 700");
            }
            let m = MasterV2::generate(None);
            if let Err(e) = write_secret(&dir.join("keyring"), m.to_text().as_bytes()) {
                die(format!("keyring: {e} (refusing to overwrite an existing keyring)"));
            }
            if let Err(e) = write_secret(&dir.join("psk"), keyproto::generate_psk_text().as_bytes())
            {
                die(format!("psk: {e}"));
            }
            println!(
                "created master keyring v2 (fingerprint {}) and psk in {}. Not usable until escrowed: \
                 escrow-export, escrow-digest where the copy is, escrow-confirm --digest {}",
                m.fingerprint(),
                dir.display(),
                m.escrow_digest()
            );
        }
        "upgrade-v2" => {
            let dir = dir();
            let v1 = match read_master(&dir).unwrap_or_else(|e| die(e)) {
                Master::V1(k) => k,
                Master::V2(_) => die("the keyring is already v2"),
            };
            let backup = dir.join(format!("keyring.v1.{}", now_secs()));
            write_secret(&backup, v1.to_text().as_bytes()).unwrap_or_else(|e| die(e));
            let lfp = v1.fingerprint();
            let m = MasterV2::generate(Some(v1));
            replace_file(&dir.join("keyring"), m.to_text().as_bytes());
            if !dir.join("tenants").exists() {
                replace_file(&dir.join("tenants"), TenantKeyring::default().to_text().as_bytes());
            }
            println!(
                "upgraded: master v2 fingerprint {} (legacy v1 keys {lfp} kept; backup {}). v1 clients still \
                 get the legacy keyring. The new root is NOT escrowed yet: escrow-export, escrow-digest where \
                 the copy is, escrow-confirm --digest {}",
                m.fingerprint(),
                backup.display(),
                m.escrow_digest()
            );
        }
        "rotate" => {
            let dir = dir();
            match read_master(&dir).unwrap_or_else(|e| die(e)) {
                Master::V2(mut m) => {
                    let g = m.rotate();
                    replace_file(&dir.join("keyring"), m.to_text().as_bytes());
                    println!(
                        "KEK generation {g} is active (derived from the escrowed root: no new escrow needed)"
                    );
                }
                Master::V1(mut kr) => {
                    let kid = kr.rotate().unwrap_or_else(|e| die(e));
                    replace_file(&dir.join("keyring"), kr.to_text().as_bytes());
                    println!(
                        "added key {kid} as PENDING (writes stay on key {}); escrow-export, escrow-digest, \
                         escrow-confirm --digest {} activates it",
                        kr.active_kid,
                        kr.escrow_digest()
                    );
                }
            }
        }
        "escrow-export" => {
            let dir = dir();
            refuse_tty();
            let text = Zeroizing::new(
                fs::read_to_string(dir.join("keyring")).unwrap_or_else(|e| die(e)),
            );
            read_master(&dir).unwrap_or_else(|e| die(e));
            let mut out = std::io::stdout().lock();
            out.write_all(text.as_bytes()).unwrap_or_else(|e| die(e));
            out.flush().unwrap_or_else(|e| die(e));
            log("escrow-export: master keyring written to stdout");
        }
        "escrow-digest" => {
            let file = PathBuf::from(need(&args, "--file"));
            let text = Zeroizing::new(fs::read_to_string(&file).unwrap_or_else(|e| die(e)));
            if text.trim_start().starts_with("s3vault-keyring v2") {
                let m = MasterV2::parse(&text).unwrap_or_else(|e| die(e));
                println!("digest {} fingerprint {} (master v2)", m.escrow_digest(), m.fingerprint());
            } else {
                let kr = Keyring::parse(&text).unwrap_or_else(|e| die(e));
                println!(
                    "digest {} fingerprint {} kids {:?} (v1)",
                    kr.escrow_digest(),
                    kr.fingerprint(),
                    kr.kids()
                );
            }
        }
        "escrow-confirm" => {
            let dir = dir();
            let digest = need(&args, "--digest");
            let place = need(&args, "--place");
            match read_master(&dir).unwrap_or_else(|e| die(e)) {
                Master::V2(mut m) => {
                    m.confirm_escrow(&digest, &place, now_secs()).unwrap_or_else(|e| die(e));
                    replace_file(&dir.join("keyring"), m.to_text().as_bytes());
                    println!("escrow of the master root recorded ({place}); places {:?}", m.escrow_places());
                }
                Master::V1(mut kr) => {
                    let before = kr.active_kid;
                    kr.confirm_escrow(&digest, &place, now_secs()).unwrap_or_else(|e| die(e));
                    replace_file(&dir.join("keyring"), kr.to_text().as_bytes());
                    println!("escrow recorded ({place}); active key {before} -> {}", kr.active_kid);
                }
            }
        }
        "fingerprint" => {
            let dir = dir();
            match read_master(&dir).unwrap_or_else(|e| die(e)) {
                Master::V1(kr) => println!(
                    "v1 fingerprint {} active_kid {} write_kid {} pending {:?} kids {:?} escrowed at {:?}",
                    kr.fingerprint(),
                    kr.active_kid,
                    kr.write_kid(),
                    kr.pending_kid,
                    kr.kids(),
                    kr.escrow_places()
                ),
                Master::V2(m) => {
                    let tk = read_tenants(&dir).unwrap_or_else(|e| die(e));
                    let l = read_ledger(&dir).unwrap_or_else(|e| die(e));
                    println!(
                        "v2 fingerprint {} active generation {} root escrowed {} at {:?}; legacy v1 {}; \
                         tenants {} (escrow copies confirmed {}); ledger entries {} head {}",
                        m.fingerprint(),
                        m.active,
                        m.is_escrowed(),
                        m.escrow_places(),
                        m.legacy.as_ref().map(|l| l.fingerprint()).unwrap_or_else(|| "none".into()),
                        tk.tenants.len(),
                        tk.escrows.len(),
                        l.entries.len(),
                        &l.head().1[..16]
                    );
                }
            }
        }
        "tenant-create" => {
            let dir = dir();
            let name = need(&args, "--name");
            let m = read_v2(&dir);
            let mut tk = read_tenants(&dir).unwrap_or_else(|e| die(e));
            let e = tk.create(&name, now_secs()).unwrap_or_else(|e| die(e)).clone();
            replace_file(&dir.join("tenants"), tk.to_text().as_bytes());
            let (file, digest) = issue_escrow(&dir, &m, &tk);
            println!(
                "tenant {name} id {} tag {} created PENDING (not served for writes until its escrow copy is \
                 confirmed). escrow copy {file} digest {digest}\n{ESCROW_STEPS}",
                e.id_hex(),
                m.tenant_tag(&e.id)
            );
        }
        "tenant-erase" => {
            let dir = dir();
            let name = need(&args, "--name");
            let m = Arc::new(read_v2(&dir));
            let mut tk = read_tenants(&dir).unwrap_or_else(|e| die(e));
            let mut l = read_ledger(&dir).unwrap_or_else(|e| die(e));
            let before = tk
                .tenants
                .get(&name)
                .cloned()
                .unwrap_or_else(|| die(format!("no tenant {name}")));
            let fp = m.tenant_keys(&before).map(|k| k.fingerprint.clone()).ok();
            let now = now_secs();
            let e = tk.erase(&name, now).unwrap_or_else(|e| die(e)).clone();
            let tag = m.tenant_tag(&e.id);
            let entry = l
                .append(
                    ledger::TENANT_ERASED,
                    &e.id_hex(),
                    &tag,
                    serde_json::json!({"k_t_fingerprint": fp, "erased_at": now, "created": e.created}),
                    now,
                )
                .clone();
            // Ledger first (an erasure is never lost), then the key removal.
            replace_file(&dir.join("ledger.jsonl"), l.to_text().as_bytes());
            replace_file(&dir.join("tenants"), tk.to_text().as_bytes());
            let (file, digest) = issue_escrow(&dir, &m, &tk);
            println!(
                "tenant {name} ({}) ERASED: K_t destroyed here. ledger entry {} (seq {}). new escrow copy {file} \
                 digest {digest}: copy it to the owner's device and confirm it; escrow copies older than this \
                 one are destroyed within 30 days (escrow-prune). next on the proxy: \
                 POST /tenant/erase?tenant={name}&confirm={name}",
                e.id_hex(),
                entry.hash,
                entry.seq
            );
        }
        "tenant-list" => {
            let dir = dir();
            let m = read_v2(&dir);
            let tk = read_tenants(&dir).unwrap_or_else(|e| die(e));
            for t in tk.tenants.values() {
                println!(
                    "{} {} tag {} {} created {} erased {:?}",
                    t.name,
                    t.id_hex(),
                    m.tenant_tag(&t.id),
                    t.status.as_str(),
                    t.created,
                    t.erased_at
                );
            }
            for r in &tk.escrows {
                println!("escrow copy {} confirmed at {} ({})", r.digest, r.at, r.place);
            }
        }
        "escrow-cat" => {
            let dir = dir();
            refuse_tty();
            let path = match arg(&args, "--file") {
                Some(f) => {
                    if f.contains('/') || escrow_file_time(&f).is_none() {
                        die("--file takes a name from escrow/ (tenants-<time>.sealed)");
                    }
                    dir.join("escrow").join(f)
                }
                None => newest_escrow(&dir).unwrap_or_else(|| die("no escrow copy")).1,
            };
            let b = fs::read(&path).unwrap_or_else(|e| die(e));
            std::io::stdout().lock().write_all(&b).unwrap_or_else(|e| die(e));
            log(&format!(
                "escrow-cat: {} (digest {}) written to stdout",
                path.display(),
                escrow_file_digest(&b)
            ));
        }
        "tenant-escrow-confirm" => {
            let dir = dir();
            let digest = need(&args, "--digest");
            let place = need(&args, "--place");
            let m = read_v2(&dir);
            let (name, path) = newest_escrow(&dir).unwrap_or_else(|| die("no escrow copy"));
            let b = fs::read(&path).unwrap_or_else(|e| die(e));
            if escrow_file_digest(&b) != digest.trim() {
                die(format!(
                    "the digest does not match the newest escrow copy {name}: copy it again (a tenant changed?)"
                ));
            }
            let (_, copy) = open_tenant_escrow(&m, &b).unwrap_or_else(|e| die(e));
            let mut tk = read_tenants(&dir).unwrap_or_else(|e| die(e));
            let act = tk
                .confirm_escrow(&copy, &digest, &place, now_secs())
                .unwrap_or_else(|e| die(e));
            replace_file(&dir.join("tenants"), tk.to_text().as_bytes());
            println!("escrow copy {name} recorded at {place}; activated {act:?}");
        }
        "escrow-prune" => {
            let dir = dir();
            let days: u64 = arg(&args, "--max-age-days")
                .and_then(|d| d.parse().ok())
                .unwrap_or(30);
            let del = prune_escrow_dir(&dir.join("escrow"), now_secs(), days * 86_400)
                .unwrap_or_else(|e| die(e));
            println!("deleted {} escrow copies older than {days} days: {del:?}", del.len());
        }
        "ledger-import" => {
            let dir = dir();
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text).unwrap_or_else(|e| die(e));
            let outbox = Ledger::parse(&text).unwrap_or_else(|e| die(format!("outbox: {e}")));
            let mut l = read_ledger(&dir).unwrap_or_else(|e| die(e));
            let mut n = 0;
            for e in &outbox.entries {
                if e.kind != ledger::OBJECT_ERASED && e.kind != ledger::ERASURE_PROOF {
                    die(format!("outbox entry {} has kind {}: refused", e.seq, e.kind));
                }
                if l.has_source(&e.hash) {
                    continue;
                }
                let mut detail = e.detail.clone();
                if let Some(o) = detail.as_object_mut() {
                    o.insert("src_hash".into(), e.hash.clone().into());
                    o.insert("src_seq".into(), e.seq.into());
                }
                l.append(&e.kind, &e.tenant_id, &e.tenant_tag, detail, e.at);
                n += 1;
            }
            replace_file(&dir.join("ledger.jsonl"), l.to_text().as_bytes());
            println!("imported {n} entries; ledger has {} (head {})", l.entries.len(), l.head().1);
        }
        "ledger-show" => {
            let dir = dir();
            let l = read_ledger(&dir).unwrap_or_else(|e| die(e));
            print!("{}", l.to_text());
            eprintln!("ledger verified: {} entries, head {}", l.entries.len(), l.head().1);
        }
        "fetch" => {
            let addr = need(&args, "--addr");
            let psk = read_psk(Path::new(&need(&args, "--psk"))).unwrap_or_else(|e| die(e));
            let mut s = TcpStream::connect(&addr).expect("connect");
            s.set_read_timeout(Some(Duration::from_secs(10))).ok();
            match keyproto::client_fetch_with(&mut s, &psk, keyproto::MAGIC2) {
                Ok(text) => {
                    let b = Bundle::parse(std::str::from_utf8(&text).unwrap_or(""))
                        .unwrap_or_else(|e| die(e));
                    println!(
                        "ok: master {} tenants {} ledger {}",
                        b.master.fingerprint(),
                        b.tenants.tenants.len(),
                        b.ledger.entries.len()
                    );
                }
                Err(e) => die(format!("fetch failed: {e}")),
            }
        }
        "serve" => serve(&args),
        _ => usage(),
    }
}

/// The payload for a protocol version: v1 gets the (legacy) v1 keyring, v2 the bundle.
fn payload(dir: &Path, version: u8) -> Result<(Zeroizing<Vec<u8>>, String), String> {
    match (read_master(dir)?, version) {
        (Master::V1(kr), 1) => Ok((
            Zeroizing::new(kr.to_text().as_bytes().to_vec()),
            format!("v1 keyring {}", kr.fingerprint()),
        )),
        (Master::V1(_), _) => Err("a v2 client needs a v2 master keyring".into()),
        (Master::V2(m), 1) => {
            let t = m.legacy_text().ok_or("no legacy keys for a v1 client")?;
            let fp = m.legacy.as_ref().map(|l| l.fingerprint()).unwrap_or_default();
            Ok((Zeroizing::new(t.as_bytes().to_vec()), format!("legacy v1 keyring {fp}")))
        }
        (Master::V2(m), _) => {
            let fp = m.fingerprint();
            let b = Bundle {
                master: m,
                tenants: read_tenants(dir)?,
                ledger: read_ledger(dir)?,
            };
            let n = b.tenants.tenants.len();
            Ok((
                Zeroizing::new(b.to_text().as_bytes().to_vec()),
                format!("bundle {fp} ({n} tenants)"),
            ))
        }
    }
}

fn serve(args: &[String]) {
    let dir = PathBuf::from(need(args, "--dir"));
    let listen: SocketAddr = need(args, "--listen").parse().unwrap_or_else(|_| usage());
    let allow: Vec<IpAddr> = need(args, "--allow")
        .split(',')
        .map(|s| s.trim().parse().unwrap_or_else(|_| usage()))
        .collect();
    // Validate the files once at start; they are re-read per request.
    match read_master(&dir).unwrap_or_else(|e| {
        log(&e);
        std::process::exit(1)
    }) {
        Master::V1(k) => log(&format!("v1 keyring {} kids {:?}", k.fingerprint(), k.kids())),
        Master::V2(m) => log(&format!(
            "master v2 {} escrowed {}; tenants {}; ledger {}",
            m.fingerprint(),
            m.is_escrowed(),
            read_tenants(&dir).map(|t| t.tenants.len()).unwrap_or(0),
            read_ledger(&dir).map(|l| l.entries.len()).unwrap_or(0)
        )),
    }
    read_psk(&dir.join("psk")).unwrap_or_else(|e| {
        log(&e);
        std::process::exit(1)
    });
    // The Tailscale address may not exist yet at boot: retry the bind.
    let listener = loop {
        match TcpListener::bind(listen) {
            Ok(l) => break l,
            Err(e) => {
                log(&format!("bind {listen}: {e}; retrying in 5 s"));
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    };
    log(&format!("listening on {listen}, allowing {allow:?}"));
    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let Ok(peer) = stream.peer_addr() else {
            continue;
        };
        if !allow.contains(&peer.ip()) {
            log(&format!("refused {peer}: not on the allow list"));
            continue;
        }
        if active.load(Ordering::SeqCst) >= 8 {
            log(&format!("refused {peer}: too many concurrent sessions"));
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let dir = dir.clone();
        let active = active.clone();
        std::thread::spawn(move || {
            let mut stream = stream;
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
            let mut what = String::new();
            let result = (|| -> Result<u8, String> {
                let psk = read_psk(&dir.join("psk"))?;
                keyproto::server_serve_versioned(&mut stream, &psk, |v| {
                    let (p, w) = payload(&dir, v)?;
                    what = w;
                    Ok(p)
                })
                .map_err(|e| e.to_string())
            })();
            match result {
                Ok(v) => log(&format!("served {what} to {peer} (protocol v{v})")),
                Err(e) => log(&format!("session with {peer} failed: {e} {what}")),
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}
