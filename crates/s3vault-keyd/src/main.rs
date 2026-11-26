//! s3vault-keyd: a tiny key service.
//!
//! It holds the master keyring file (`<dir>/keyring`) and a pre-shared key (`<dir>/psk`) and hands the keyring
//! to proxies that connect from an allow-listed address and prove the PSK (see `s3vault_format::keyproto`).
//! It never prints key material. The keyring file is re-read for every request, so a rotation needs no restart.
//!
//! ```text
//! s3vault-keyd init --dir DIR                 create DIR/keyring and DIR/psk (mode 600); refuses to overwrite
//! s3vault-keyd serve --dir DIR --listen ADDR --allow IP[,IP...]
//! s3vault-keyd rotate --dir DIR               add a key as pending (used only after escrow-confirm)
//! s3vault-keyd escrow-export --dir DIR        write the keyring to stdout (refuses a terminal) for the copy
//! s3vault-keyd escrow-digest --file COPY      non-secret digest of an escrow copy (run where the copy is)
//! s3vault-keyd escrow-confirm --dir DIR --digest D --place P
//!                                             record a confirmed copy; a pending key becomes active
//! s3vault-keyd fingerprint --dir DIR          print the non-secret keyring fingerprint, key ids, escrow state
//! s3vault-keyd fetch --addr ADDR --psk FILE   test client: fetch and print the fingerprint only
//! ```

use s3vault_format::keyproto;
use s3vault_format::keyring::Keyring;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use zeroize::Zeroizing;

fn usage() -> ! {
    eprintln!(
        "usage:\n  s3vault-keyd init --dir DIR\n  s3vault-keyd serve --dir DIR --listen ADDR --allow IP[,IP]\n  \
         s3vault-keyd rotate --dir DIR\n  s3vault-keyd escrow-export --dir DIR > COPY\n  \
         s3vault-keyd escrow-digest --file COPY\n  s3vault-keyd escrow-confirm --dir DIR --digest D --place P\n  \
         s3vault-keyd fingerprint --dir DIR\n  s3vault-keyd fetch --addr ADDR --psk FILE"
    );
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    eprintln!("{now} s3vault-keyd: {msg}");
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

fn write_secret(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

fn read_keyring(dir: &Path) -> Result<Keyring, String> {
    let text = Zeroizing::new(
        fs::read_to_string(dir.join("keyring")).map_err(|e| format!("read keyring: {e}"))?,
    );
    Keyring::parse(&text).map_err(|e| e.to_string())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Replace `DIR/keyring` atomically (write `keyring.new`, fsync, rename).
fn replace_keyring(dir: &Path, kr: &Keyring) {
    let tmp = dir.join("keyring.new");
    let _ = fs::remove_file(&tmp);
    write_secret(&tmp, kr.to_text().as_bytes()).expect("write keyring.new");
    fs::rename(&tmp, dir.join("keyring")).expect("rename keyring");
}

fn die(e: impl std::fmt::Display) -> ! {
    eprintln!("{e}");
    std::process::exit(1)
}

fn read_psk(path: &Path) -> Result<s3vault_format::keyring::Key32, String> {
    let text = Zeroizing::new(fs::read_to_string(path).map_err(|e| format!("read psk: {e}"))?);
    keyproto::parse_psk(&text).map_err(|e| e.to_string())
}

fn main() {
    harden();
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or_else(|| usage());
    match cmd {
        "init" => {
            let dir = PathBuf::from(need(&args, "--dir"));
            fs::create_dir_all(&dir).expect("create dir");
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod 700");
            }
            let kr = Keyring::generate();
            if let Err(e) = write_secret(&dir.join("keyring"), kr.to_text().as_bytes()) {
                eprintln!("keyring: {e} (refusing to overwrite an existing keyring)");
                std::process::exit(1);
            }
            if let Err(e) = write_secret(&dir.join("psk"), keyproto::generate_psk_text().as_bytes())
            {
                eprintln!("psk: {e}");
                std::process::exit(1);
            }
            println!(
                "created keyring (fingerprint {}) and psk in {}",
                kr.fingerprint(),
                dir.display()
            );
        }
        "rotate" => {
            let dir = PathBuf::from(need(&args, "--dir"));
            let mut kr = read_keyring(&dir).unwrap_or_else(|e| die(e));
            let kid = kr.rotate().unwrap_or_else(|e| die(e));
            replace_keyring(&dir, &kr);
            println!(
                "added key {kid} as PENDING (writes stay on key {}). It becomes active only after an escrow \
                 copy is confirmed:\n  1. escrow-export to the owner's offline copy\n  2. escrow-digest --file \
                 <copy> where the copy is\n  3. escrow-confirm --digest <digest> --place <where>\n\
                 expected digest {} (fingerprint {}, kids {:?})",
                kr.active_kid,
                kr.escrow_digest(),
                kr.fingerprint(),
                kr.kids()
            );
        }
        "escrow-export" => {
            let dir = PathBuf::from(need(&args, "--dir"));
            if unsafe { libc::isatty(1) } == 1 {
                die("refusing to write key material to a terminal; redirect stdout to the copy");
            }
            let kr = read_keyring(&dir).unwrap_or_else(|e| die(e));
            let text = kr.to_text();
            let mut out = std::io::stdout().lock();
            out.write_all(text.as_bytes()).unwrap_or_else(|e| die(e));
            out.flush().unwrap_or_else(|e| die(e));
            log(&format!(
                "escrow-export: keyring {} (digest {}) written to stdout",
                kr.fingerprint(),
                kr.escrow_digest()
            ));
        }
        "escrow-digest" => {
            let file = PathBuf::from(need(&args, "--file"));
            let text = Zeroizing::new(fs::read_to_string(&file).unwrap_or_else(|e| die(e)));
            let kr = Keyring::parse(&text).unwrap_or_else(|e| die(e));
            println!(
                "digest {} fingerprint {} kids {:?}",
                kr.escrow_digest(),
                kr.fingerprint(),
                kr.kids()
            );
        }
        "escrow-confirm" => {
            let dir = PathBuf::from(need(&args, "--dir"));
            let digest = need(&args, "--digest");
            let place = need(&args, "--place");
            let mut kr = read_keyring(&dir).unwrap_or_else(|e| die(e));
            let before = kr.active_kid;
            kr.confirm_escrow(&digest, &place, now_secs())
                .unwrap_or_else(|e| die(e));
            replace_keyring(&dir, &kr);
            println!(
                "escrow recorded ({place}, keys up to {}); active key {} -> {}",
                kr.max_kid(),
                before,
                kr.active_kid
            );
        }
        "fingerprint" => {
            let dir = PathBuf::from(need(&args, "--dir"));
            match read_keyring(&dir) {
                Ok(kr) => println!(
                    "fingerprint {} name_kid {} active_kid {} write_kid {} pending {:?} kids {:?} \
                     escrow digest {} escrowed at {:?}",
                    kr.fingerprint(),
                    kr.name_kid,
                    kr.active_kid,
                    kr.write_kid(),
                    kr.pending_kid,
                    kr.kids(),
                    kr.escrow_digest(),
                    kr.escrow_places()
                ),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1)
                }
            }
        }
        "fetch" => {
            let addr = need(&args, "--addr");
            let psk = read_psk(Path::new(&need(&args, "--psk"))).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1)
            });
            let mut s = TcpStream::connect(&addr).expect("connect");
            s.set_read_timeout(Some(Duration::from_secs(10))).ok();
            match keyproto::client_fetch(&mut s, &psk) {
                Ok(text) => {
                    let kr =
                        Keyring::parse(std::str::from_utf8(&text).unwrap_or("")).expect("keyring");
                    println!("ok: fingerprint {} kids {:?}", kr.fingerprint(), kr.kids());
                }
                Err(e) => {
                    eprintln!("fetch failed: {e}");
                    std::process::exit(1)
                }
            }
        }
        "serve" => serve(&args),
        _ => usage(),
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
    let kr = read_keyring(&dir).unwrap_or_else(|e| {
        log(&e);
        std::process::exit(1)
    });
    read_psk(&dir.join("psk")).unwrap_or_else(|e| {
        log(&e);
        std::process::exit(1)
    });
    log(&format!(
        "keyring fingerprint {} kids {:?}",
        kr.fingerprint(),
        kr.kids()
    ));
    drop(kr);
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
            let result = (|| -> Result<String, String> {
                let psk = read_psk(&dir.join("psk"))?;
                let kr = read_keyring(&dir)?;
                let text = kr.to_text();
                keyproto::server_serve(&mut stream, &psk, text.as_bytes())
                    .map_err(|e| e.to_string())?;
                Ok(kr.fingerprint())
            })();
            match result {
                Ok(fp) => log(&format!("served keyring {fp} to {peer}")),
                Err(e) => log(&format!("session with {peer} failed: {e}")),
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}
