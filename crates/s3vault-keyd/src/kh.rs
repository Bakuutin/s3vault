//! Key hierarchy commands (keystore, slots, places, baseline, drills). No network: they run in keyd's admin
//! container on the key host or on any machine that holds a keystore copy and a slot.
//!
//! ```text
//! slot-keygen --kem x25519|p256 --kind K --label L [--holder H] [--backend B] [--tenant N] --key-out F --pub-out F
//!                                         software slot key pair (host slot file, Bitwarden recovery slot, tests)
//! slot-pub --slot DESC --kind K --label L [--holder H] [--backend B] [--tenant N] --pub-out F
//!                                         slot public file for a helper-held key (Secure Enclave, TPM, stand-in)
//! slot-helper-soft pub|dh FILE            the software stand-in for a hardware helper (test environment TPM)
//! kh-baseline --dir DIR [--out F]         7.2: non-secret baseline from the plain files
//! kh-init --dir DIR --slot-pub F... --verify-slot DESC [--policy F]
//!                                         7.3: keystore epoch 1 from the plain files (refuses a pending tenant)
//! kh-verify (--dir DIR | --keystore F) --slot DESC [--baseline F [--changes F]] [--against-files DIR]
//!                                         open through one slot; compare with the frozen baseline and/or the
//!                                         bundle the plain files give (old code path)
//! kh-drill --copy F [--copy F...] --slot DESC [--baseline F --changes F] [--approved F]
//!          [--rebuild-dir DIR [--ledger-merge F...]]
//!                                         recovery from copies and one slot key: hash chain, bundle digest,
//!                                         slot table; optionally a fresh keyd directory with a new host slot
//! ks-status --dir DIR                     epochs, public slots, places, warnings (no slot needed)
//! ks-slots --dir DIR --slot DESC [--approved F]   slot table; audit against the approved slot ids
//! ks-slot-add --dir DIR --slot DESC --pub F
//! ks-slot-revoke --dir DIR --slot DESC --id ID [--purge]
//! ks-tenant-create|ks-tenant-erase|ks-tenant-rewrap --dir DIR --slot DESC --name N [--dual-write]
//! ks-tenant-activate --dir DIR --slot DESC [--dual-write]   pending -> active once policy places confirm
//! ks-tenant-list --dir DIR --slot DESC
//! ks-ledger-import --dir DIR --slot DESC [--dual-write] < OUTBOX
//! ks-place-confirm --dir DIR --epoch N --digest D --place P
//! ks-cat --dir DIR [--epoch N]            a sealed epoch to stdout (refuses a terminal)
//! ks-prune --dir DIR [--purge]            retention from keys/policy.toml (keeps the newest)
//! ks-resync-plain --dir DIR --slot DESC   dual write repair: plain files := keystore (after a crash)
//! ks-master-escrow-replace --dir DIR --slot DESC --place P   7.8 step 4
//! ```

use super::*;
use s3vault_format::hpke::{Kem, SlotSecret, SoftSecret};
use s3vault_format::keys2::TenantStatus;
use s3vault_format::keystore::{
    self, Baseline, Keystore, KeystoreDir, Places, Policy, PublicInfo, check_chain, compare, epoch_file_name,
    file_digest, parse_changes,
};
use s3vault_format::slots::{self, PubTarget, SlotPub};

fn ks_dir(dir: &Path) -> KeystoreDir {
    KeystoreDir::new(dir.join("keystore"))
}

fn slot_secret(args: &[String]) -> Box<dyn SlotSecret> {
    slots::open_descriptor(&need(args, "--slot")).unwrap_or_else(|e| die(e))
}

fn all(args: &[String], name: &str) -> Vec<String> {
    args.windows(2).filter(|w| w[0] == name).map(|w| w[1].clone()).collect()
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// The bundle text the plain files give, through the old code path (read_master, read_tenants, read_ledger).
pub fn plain_bundle(dir: &Path) -> Result<Zeroizing<String>, String> {
    match read_master(dir)? {
        Master::V1(_) => Err("v1 master keyring".into()),
        Master::V2(m) => Ok(Bundle { master: m, tenants: read_tenants(dir)?, ledger: read_ledger(dir)? }.to_text()),
    }
}

fn sha_hex(s: &str) -> String {
    file_digest(s.as_bytes())
}

/// Open the newest epoch on the key host: (epoch number, file bytes, opened keystore).
fn open_newest(dir: &Path, s: &dyn SlotSecret) -> (u64, Vec<u8>, Keystore) {
    let (n, b) = ks_dir(dir).read_newest().unwrap_or_else(|e| die(e));
    let ks = Keystore::open(&b, s).unwrap_or_else(|e| die(format!("epoch {n}: {e}")));
    (n, b, ks)
}

fn record_change(dir: &Path, op: &str, arg: &str) {
    if dir.join("baseline").exists() {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(dir.join("baseline.changes"))
            .unwrap_or_else(|e| die(e));
        writeln!(f, "{op} {arg}").unwrap_or_else(|e| die(e));
        f.sync_all().ok();
    }
}

/// Seal and write the next epoch of `ks` (which was opened from `prev` bytes of epoch `prev_n`).
fn commit(dir: &Path, prev_n: u64, prev: &[u8], ks: &mut Keystore) -> (u64, String) {
    let kd = ks_dir(dir);
    let lock = kd.lock().unwrap_or_else(|e| die(e));
    let _ = prev;
    let bytes = ks.seal().unwrap_or_else(|e| die(e));
    let p = kd.write_epoch(&lock, Some(prev_n), ks.epoch, &bytes).unwrap_or_else(|e| die(e));
    let d = file_digest(&bytes);
    log(&format!("keystore epoch {} written ({}, sha256 {})", ks.epoch, p.display(), &d[..16]));
    Places::append(&dir.join("places"), ks.epoch, &d, "d", now_secs()).unwrap_or_else(|e| die(e));
    (ks.epoch, d)
}

/// Dual write (KH14, soak 7.7): after the keystore, check that the plain files (written by the old code path)
/// give the same bundle. A mismatch stops loudly; `ks-resync-plain` repairs a crash between the two writes.
fn dual_check(dir: &Path, ks: &Keystore) {
    let plain = plain_bundle(dir).unwrap_or_else(|e| die(e));
    let k = ks.bundle_text().unwrap_or_else(|e| die(e));
    if sha_hex(&plain) != sha_hex(&k) {
        die("DUAL WRITE MISMATCH: the plain files and the keystore give different bundles; stop and run kh-verify");
    }
    println!("dual write: plain files and keystore give the same bundle (sha256 {})", &sha_hex(&k)[..16]);
}

fn old_ledger_import(l: &mut Ledger, outbox: &Ledger) -> usize {
    // the loop of `s3vault-keyd ledger-import` (old code path)
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
    n
}

fn tenant_line(m: &Arc<MasterV2>, t: &s3vault_format::keys2::TenantEntry) -> String {
    format!(
        "{} {} tag {} {} created {} erased {:?} k_t_fp {}",
        t.name,
        t.id_hex(),
        m.tenant_tag(&t.id),
        t.status.as_str(),
        t.created,
        t.erased_at,
        keystore::tenant_fp(m, t)
    )
}

fn pub_from(args: &[String], kem: Kem, pk: Vec<u8>) -> SlotPub {
    SlotPub {
        kem,
        pk,
        kind: need(args, "--kind"),
        label: need(args, "--label"),
        holder: arg(args, "--holder").unwrap_or_else(|| "owner".into()),
        backend: arg(args, "--backend").unwrap_or_else(|| "file".into()),
        target: match arg(args, "--tenant") {
            Some(n) => PubTarget::Tenant(n),
            None => PubTarget::Master,
        },
    }
}

fn approved_ids(path: &str) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_else(|e| die(format!("approved list: {e}")))
        .lines()
        .map(|l| l.split_whitespace().next().unwrap_or("").to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Print the slot table; with an approved list, fail on any slot nobody approved (review R9).
fn slot_audit(ks: &Keystore, approved: Option<&str>) -> bool {
    let ap = approved.map(approved_ids);
    let mut ok = true;
    for s in &ks.slots {
        let mark = match &ap {
            Some(a) if !a.contains(&s.id) => {
                ok = false;
                "UNAPPROVED "
            }
            _ => "",
        };
        println!(
            "{mark}slot {} {} {} label {} holder {} backend {} kem {} pk_fp {} created {} by {}",
            s.id, s.kind, s.target, s.label, s.holder, s.backend, s.kem, s.pk_fingerprint(), s.created, s.created_by
        );
    }
    if let Some(a) = &ap {
        for id in a.iter().filter(|id| !ks.slots.iter().any(|s| &s.id == *id)) {
            println!("note: approved slot {id} is not in the keystore");
        }
    }
    let pol = ks.policy();
    if ks.master_slots() < pol.min_master_slots {
        println!("WARNING: {} master slots, policy min_master_slots {}", ks.master_slots(), pol.min_master_slots);
    }
    ok
}

pub fn run(cmd: &str, args: &[String]) -> bool {
    let dir = || PathBuf::from(need(args, "--dir"));
    match cmd {
        "slot-keygen" => {
            let kem = Kem::from_name(&need(args, "--kem")).unwrap_or_else(|e| die(e));
            let sk = SoftSecret::generate(kem);
            let p = pub_from(args, kem, sk.public_key());
            let key_out = PathBuf::from(need(args, "--key-out"));
            write_secret(&key_out, slots::soft_key_text(&sk).as_bytes())
                .unwrap_or_else(|e| die(format!("{}: {e} (refusing to overwrite)", key_out.display())));
            write_secret(Path::new(&need(args, "--pub-out")), p.to_text().as_bytes()).unwrap_or_else(|e| die(e));
            println!("slot key pair: id {} kem {} kind {} label {}", hex::encode(p.id()), kem.name(), p.kind, p.label);
        }
        "slot-pub" => {
            let s = slot_secret(args);
            let p = pub_from(args, s.kem(), s.public_key());
            write_secret(Path::new(&need(args, "--pub-out")), p.to_text().as_bytes()).unwrap_or_else(|e| die(e));
            println!("slot public file: id {} kem {} kind {}", hex::encode(p.id()), s.kem().name(), p.kind);
        }
        "slot-helper-soft" => {
            let verb = args.get(2).cloned().unwrap_or_default();
            let file = args.get(3).cloned().unwrap_or_else(|| usage());
            let mut input = String::new();
            if verb == "dh" {
                std::io::stdin().read_to_string(&mut input).unwrap_or_else(|e| die(e));
            }
            let out = slots::soft_helper(&verb, Path::new(&file), &input).unwrap_or_else(|e| die(e));
            std::io::stdout().write_all(out.as_bytes()).unwrap_or_else(|e| die(e));
        }
        "kh-baseline" => {
            let dir = dir();
            let text = plain_bundle(&dir).unwrap_or_else(|e| die(e));
            let mut b = Baseline::from_bundle(&text).unwrap_or_else(|e| die(e));
            if let Some((name, path)) = newest_escrow(&dir) {
                let bytes = fs::read(&path).unwrap_or_else(|e| die(e));
                b.extra.push(format!("sealed_copy {name} {}", escrow_file_digest(&bytes)));
            }
            b.extra.push(format!("created {}", now_secs()));
            let pending: Vec<&String> =
                b.tenants.iter().filter(|(_, v)| v.1 == "pending").map(|(n, _)| n).collect();
            let out = b.to_text();
            match arg(args, "--out") {
                Some(f) => write_secret(Path::new(&f), out.as_bytes()).unwrap_or_else(|e| die(e)),
                None => print!("{out}"),
            }
            if !pending.is_empty() {
                die(format!("FREEZE PRECONDITION FAILS: pending tenants {pending:?}"));
            }
            eprintln!("baseline: bundle sha256 {} ({} tenants)", &b.bundle_sha256[..16], b.tenants.len());
        }
        "kh-init" => {
            let dir = dir();
            if ks_dir(&dir).newest().ok().flatten().is_some() {
                die("a keystore exists already (undo of 7.3 = delete keys/keystore/)");
            }
            let master_text = Zeroizing::new(fs::read_to_string(dir.join("keyring")).unwrap_or_else(|e| die(e)));
            let tenants_text = Zeroizing::new(fs::read_to_string(dir.join("tenants")).unwrap_or_default());
            let ledger_text = fs::read_to_string(dir.join("ledger.jsonl")).unwrap_or_default();
            let policy_text = match arg(args, "--policy") {
                Some(f) => fs::read_to_string(f).unwrap_or_else(|e| die(e)),
                None => fs::read_to_string(dir.join("policy.toml")).unwrap_or_else(|_| Policy::default_text()),
            };
            Policy::parse(&policy_text).unwrap_or_else(|e| die(e));
            let pubs: Vec<SlotPub> = all(args, "--slot-pub")
                .iter()
                .map(|f| SlotPub::parse(&fs::read_to_string(f).unwrap_or_else(|e| die(e))).unwrap_or_else(|e| die(e)))
                .collect();
            let verify = slots::open_descriptor(&need(args, "--verify-slot")).unwrap_or_else(|e| die(e));
            let ks = Keystore::init(&master_text, &tenants_text, &ledger_text, &policy_text, &pubs, "kh-init", now_secs())
                .unwrap_or_else(|e| die(e));
            let bytes = ks.seal().unwrap_or_else(|e| die(e));
            // self-check before writing: the bundle through the verify slot equals the plain files' bundle
            let back = Keystore::open(&bytes, verify.as_ref()).unwrap_or_else(|e| die(format!("verify slot: {e}")));
            let want = plain_bundle(&dir).unwrap_or_else(|e| die(e));
            if sha_hex(&back.bundle_text().unwrap_or_else(|e| die(e))) != sha_hex(&want) {
                die("kh-init: the keystore bundle differs from the plain files; nothing written");
            }
            if !dir.join("policy.toml").exists() {
                write_secret(&dir.join("policy.toml"), policy_text.as_bytes()).unwrap_or_else(|e| die(e));
            }
            let kd = ks_dir(&dir);
            let lock = kd.lock().unwrap_or_else(|e| die(e));
            kd.write_epoch(&lock, None, 1, &bytes).unwrap_or_else(|e| die(e));
            let d = file_digest(&bytes);
            Places::append(&dir.join("places"), 1, &d, "d", now_secs()).unwrap_or_else(|e| die(e));
            println!(
                "keystore epoch 1 written: id {} slots {} tenants {} sha256 {d}; bundle sha256 {} (equal to the plain files)",
                hex::encode(ks.id),
                ks.slots.len(),
                ks.tenants.tenants.len(),
                sha_hex(&want)
            );
        }
        "kh-verify" => {
            let s = slot_secret(args);
            let (label, bytes) = match arg(args, "--keystore") {
                Some(f) => (f.clone(), fs::read(&f).unwrap_or_else(|e| die(e))),
                None => {
                    let (n, b) = ks_dir(&dir()).read_newest().unwrap_or_else(|e| die(e));
                    (epoch_file_name(n), b)
                }
            };
            let ks = Keystore::open(&bytes, s.as_ref()).unwrap_or_else(|e| die(format!("{label}: {e}")));
            let bundle = ks.bundle_text().unwrap_or_else(|e| die(e));
            println!(
                "opened {label}: epoch {} sha256 {} slots {} tenants {}; bundle sha256 {}",
                ks.epoch,
                file_digest(&bytes),
                ks.slots.len(),
                ks.tenants.tenants.len(),
                sha_hex(&bundle)
            );
            let mut ok = true;
            if let Some(bf) = arg(args, "--baseline") {
                let base = Baseline::parse(&fs::read_to_string(&bf).unwrap_or_else(|e| die(e))).unwrap_or_else(|e| die(e));
                let ch = arg(args, "--changes").map(|f| parse_changes(&fs::read_to_string(f).unwrap_or_default())).unwrap_or_default();
                let (rep, good) = compare(&base, &bundle, &ch).unwrap_or_else(|e| die(e));
                for l in rep {
                    println!("  {l}");
                }
                ok &= good;
            }
            if let Some(pd) = arg(args, "--against-files") {
                let plain = plain_bundle(Path::new(&pd)).unwrap_or_else(|e| die(e));
                let eq = bool::from(subtle_eq(sha_hex(&plain).as_bytes(), sha_hex(&bundle).as_bytes()));
                println!("  {} bundle vs plain files (old code path)", if eq { "equal" } else { "DIFFERS" });
                ok &= eq;
            }
            if !ok {
                die("kh-verify: DIFFERENCES (see above)");
            }
            println!("kh-verify: equal");
        }
        "kh-drill" => drill(args),
        "ks-status" => {
            let dir = dir();
            let kd = ks_dir(&dir);
            let places = Places::load(&dir.join("places")).unwrap_or_else(|e| die(e));
            let pol = Policy::parse(&fs::read_to_string(dir.join("policy.toml")).unwrap_or_default()).unwrap_or_default();
            let now = now_secs();
            for (n, p) in kd.epochs().unwrap_or_else(|e| die(e)) {
                let b = fs::read(&p).unwrap_or_else(|e| die(e));
                let d = file_digest(&b);
                match PublicInfo::parse(&b) {
                    Ok(i) => println!(
                        "epoch {n} sha256 {} issued {} ({} days ago) slots {} blocks {} places {:?}",
                        &d[..16],
                        i.issued,
                        now.saturating_sub(i.issued) / 86_400,
                        i.slots.len(),
                        i.blocks,
                        places.places_for(n, &d)
                    ),
                    Err(e) => println!("epoch {n}: UNREADABLE ({e})"),
                }
            }
            if let Ok(d) = fs::read_dir(&kd.dir) {
                for e in d.flatten().filter(|e| e.file_name().to_string_lossy().ends_with(".partial")) {
                    println!("partial write left by a crash: {} (removed by the next write)", e.file_name().to_string_lossy());
                }
            }
            let newest = kd.newest().ok().flatten().map(|x| x.0).unwrap_or(0);
            for (place, (e, at)) in places.latest() {
                let age = now.saturating_sub(at) / 86_400;
                let warn = if e < newest { " (behind the newest epoch)" } else { "" };
                let old = if age >= pol.warn_after_days { format!(" WARNING: {age} days old, retention {} days", pol.retention_days) } else { String::new() };
                println!("place {place}: newest confirmed epoch {e}{warn}{old}");
            }
        }
        "ks-slots" => {
            let (_, _, ks) = open_newest(&dir(), slot_secret(args).as_ref());
            if !slot_audit(&ks, arg(args, "--approved").as_deref()) {
                eprintln!("SLOT AUDIT FAILED: unapproved slot(s) present");
                std::process::exit(3);
            }
        }
        "ks-slot-add" => {
            let dir = dir();
            let p = SlotPub::parse(&fs::read_to_string(need(args, "--pub")).unwrap_or_else(|e| die(e))).unwrap_or_else(|e| die(e));
            let (n, b, mut ks) = open_newest(&dir, slot_secret(args).as_ref());
            ks.chain_from(&b);
            let id = ks.add_slot(&p, "ks-slot-add", now_secs()).unwrap_or_else(|e| die(e));
            let (e, d) = commit(&dir, n, &b, &mut ks);
            println!("slot {id} ({} {}) added; epoch {e} sha256 {d}", p.kind, p.label);
        }
        "ks-slot-revoke" => {
            let dir = dir();
            let id = need(args, "--id");
            let (n, b, mut ks) = open_newest(&dir, slot_secret(args).as_ref());
            ks.chain_from(&b);
            let e = ks.revoke_slot(&id, now_secs()).unwrap_or_else(|e| die(e));
            let (ep, d) = commit(&dir, n, &b, &mut ks);
            println!("slot {id} ({} {}) revoked, unlock key rotated; epoch {ep} sha256 {d}", e.kind, e.label);
            if flag(args, "--purge") {
                let kd = ks_dir(&dir);
                let lock = kd.lock().unwrap_or_else(|e| die(e));
                let del = kd.prune(&lock, now_secs(), 0, true).unwrap_or_else(|e| die(e));
                println!("purged {} older epochs on this host: {del:?}", del.len());
            }
            println!("next: mirror push, then replace the copies on a and in Bitwarden (4.2)");
        }
        "ks-tenant-create" | "ks-tenant-erase" | "ks-tenant-rewrap" => {
            let dir = dir();
            let name = need(args, "--name");
            let dual = flag(args, "--dual-write");
            let (n, b, mut ks) = open_newest(&dir, slot_secret(args).as_ref());
            ks.chain_from(&b);
            let now = now_secs();
            match cmd {
                "ks-tenant-create" => {
                    let e = ks.tenant_create(&name, now).unwrap_or_else(|e| die(e));
                    let (ep, d) = commit(&dir, n, &b, &mut ks);
                    record_change(&dir, "tenant-create", &name);
                    let m = ks.master().unwrap_or_else(|e| die(e));
                    println!(
                        "tenant {name} id {} tag {} created PENDING in epoch {ep} (sha256 {d}). It activates after \
                         the epoch is confirmed at {:?} (ks-tenant-activate).",
                        e.id_hex(),
                        m.tenant_tag(&e.id),
                        ks.policy().activate_requires
                    );
                    if dual {
                        keystore::crash_point("dual-before-plain");
                        let mut tk = read_tenants(&dir).unwrap_or_else(|e| die(e));
                        tk.tenants.insert(name.clone(), ks.tenants.tenants[&name].clone());
                        replace_file(&dir.join("tenants"), tk.to_text().as_bytes());
                        let (file, dg) = issue_escrow(&dir, &m, &tk);
                        println!("dual write: plain tenants updated; legacy sealed copy {file} digest {dg}");
                        dual_check(&dir, &ks);
                    }
                }
                "ks-tenant-erase" => {
                    let entry = ks.tenant_erase(&name, now).unwrap_or_else(|e| die(e));
                    let (ep, d) = commit(&dir, n, &b, &mut ks);
                    record_change(&dir, "tenant-erase", &name);
                    // the working ledger copy follows the keystore
                    println!(
                        "tenant {name} ERASED in epoch {ep} (sha256 {d}); ledger entry {} (seq {}). Older epochs and \
                         copies age out within {} days. next on the proxy: POST /tenant/erase?tenant={name}&confirm={name}",
                        entry.hash,
                        entry.seq,
                        ks.policy().retention_days
                    );
                    if dual {
                        keystore::crash_point("dual-before-plain");
                        // the old code path, independently: ledger first, then the key
                        let m = Arc::new(read_v2(&dir));
                        let mut tk = read_tenants(&dir).unwrap_or_else(|e| die(e));
                        let mut l = read_ledger(&dir).unwrap_or_else(|e| die(e));
                        let before = tk.tenants.get(&name).cloned().unwrap_or_else(|| die(format!("plain: no tenant {name}")));
                        let fp = m.tenant_keys(&before).map(|k| k.fingerprint.clone()).ok();
                        let e = tk.erase(&name, now).unwrap_or_else(|e| die(e)).clone();
                        let tag = m.tenant_tag(&e.id);
                        l.append(
                            ledger::TENANT_ERASED,
                            &e.id_hex(),
                            &tag,
                            serde_json::json!({"k_t_fingerprint": fp, "erased_at": now, "created": e.created}),
                            now,
                        );
                        replace_file(&dir.join("ledger.jsonl"), l.to_text().as_bytes());
                        replace_file(&dir.join("tenants"), tk.to_text().as_bytes());
                        let (file, dg) = issue_escrow(&dir, &m, &tk);
                        println!("dual write: plain ledger and tenants updated; legacy sealed copy {file} digest {dg}");
                        dual_check(&dir, &ks);
                    } else {
                        replace_file(&dir.join("ledger.jsonl"), ks.ledger.to_text().as_bytes());
                    }
                }
                _ => {
                    ks.tenant_rewrap(&name, now).unwrap_or_else(|e| die(e));
                    let (ep, d) = commit(&dir, n, &b, &mut ks);
                    println!("tenant {name}: new TUK, block re-wrapped; K_t unchanged; epoch {ep} sha256 {d}");
                }
            }
        }
        "ks-tenant-activate" => {
            let dir = dir();
            let dual = flag(args, "--dual-write");
            let (n, b, mut ks) = open_newest(&dir, slot_secret(args).as_ref());
            let pending: Vec<String> = ks
                .tenants
                .tenants
                .values()
                .filter(|t| t.status == TenantStatus::Pending)
                .map(|t| t.name.clone())
                .collect();
            if pending.is_empty() {
                println!("no pending tenant");
                return true;
            }
            let req = ks.policy().activate_requires;
            let places = Places::load(&dir.join("places")).unwrap_or_else(|e| die(e));
            // the newest epoch on d confirmed at every required place that holds the pending tenants
            let s = slot_secret(args);
            let mut found = None;
            for (e, p) in ks_dir(&dir).epochs().unwrap_or_else(|e| die(e)).into_iter().rev() {
                let fb = fs::read(&p).unwrap_or_else(|e| die(e));
                let d = file_digest(&fb);
                let at = places.places_for(e, &d);
                if !req.iter().all(|r| at.contains(r)) {
                    continue;
                }
                let copy = Keystore::open(&fb, s.as_ref()).unwrap_or_else(|e| die(e));
                found = Some((e, d, copy.tenants.clone(), at));
                break;
            }
            let Some((ce, cd, copy, at)) = found else {
                die(format!(
                    "pending {pending:?}: no epoch on d is confirmed at all of {req:?} yet (mirror push, Bitwarden tool, then rerun)"
                ));
            };
            ks.chain_from(&b);
            let now = now_secs();
            let place = at.join("+");
            let act = ks.tenant_activate(&copy, &cd[..32], &place, now).unwrap_or_else(|e| die(e));
            if act.is_empty() {
                die(format!("pending {pending:?} are not in the confirmed epoch {ce}; push and confirm the newest epoch"));
            }
            let (ep, d) = commit(&dir, n, &b, &mut ks);
            for a in &act {
                record_change(&dir, "tenant-activate", a);
            }
            println!("activated {act:?} (held by epoch {ce}, confirmed at {place}); epoch {ep} sha256 {d}; next: POST /unlock on the proxy");
            if dual {
                keystore::crash_point("dual-before-plain");
                let mut tk = read_tenants(&dir).unwrap_or_else(|e| die(e));
                tk.confirm_escrow(&copy, &cd[..32], &place, now).unwrap_or_else(|e| die(e));
                replace_file(&dir.join("tenants"), tk.to_text().as_bytes());
                dual_check(&dir, &ks);
            }
        }
        "ks-tenant-list" => {
            let (n, _, ks) = open_newest(&dir(), slot_secret(args).as_ref());
            let m = Arc::new(ks.master().unwrap_or_else(|e| die(e)));
            println!("epoch {n}");
            for t in ks.tenants.tenants.values() {
                println!("{}", tenant_line(&m, t));
            }
        }
        "ks-ledger-import" => {
            let dir = dir();
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text).unwrap_or_else(|e| die(e));
            let outbox = Ledger::parse(&text).unwrap_or_else(|e| die(format!("outbox: {e}")));
            let (n, b, mut ks) = open_newest(&dir, slot_secret(args).as_ref());
            ks.chain_from(&b);
            let k = ks.ledger_import(&outbox, now_secs()).unwrap_or_else(|e| die(e));
            if k > 0 {
                let (ep, d) = commit(&dir, n, &b, &mut ks);
                println!("imported {k} entries; ledger has {}; epoch {ep} sha256 {d}", ks.ledger.entries.len());
            } else {
                println!("nothing new to import");
            }
            if flag(args, "--dual-write") {
                keystore::crash_point("dual-before-plain");
                let mut l = read_ledger(&dir).unwrap_or_else(|e| die(e));
                old_ledger_import(&mut l, &outbox);
                replace_file(&dir.join("ledger.jsonl"), l.to_text().as_bytes());
                dual_check(&dir, &ks);
            } else {
                replace_file(&dir.join("ledger.jsonl"), ks.ledger.to_text().as_bytes());
            }
        }
        "ks-place-confirm" => {
            let dir = dir();
            let e: u64 = need(args, "--epoch").parse().unwrap_or_else(|_| usage());
            let d = need(args, "--digest");
            let place = need(args, "--place");
            match fs::read(ks_dir(&dir).dir.join(epoch_file_name(e))) {
                Ok(b) if file_digest(&b) == d.trim() => {}
                Ok(_) => die(format!("the digest does not match epoch {e} on this host: copy it again")),
                Err(_) => die(format!("epoch {e} is not on this host (pruned?): confirm a newer epoch")),
            }
            Places::append(&dir.join("places"), e, d.trim(), &place, now_secs()).unwrap_or_else(|e| die(e));
            println!("epoch {e} recorded at {place}");
        }
        "ks-cat" => {
            refuse_tty();
            let dir = dir();
            let b = match arg(args, "--epoch") {
                Some(e) => fs::read(ks_dir(&dir).dir.join(epoch_file_name(e.parse().unwrap_or_else(|_| usage()))))
                    .unwrap_or_else(|e| die(e)),
                None => ks_dir(&dir).read_newest().unwrap_or_else(|e| die(e)).1,
            };
            std::io::stdout().lock().write_all(&b).unwrap_or_else(|e| die(e));
            let i = PublicInfo::parse(&b).unwrap_or_else(|e| die(e));
            log(&format!("ks-cat: epoch {} sha256 {} written to stdout", i.epoch, file_digest(&b)));
        }
        "ks-prune" => {
            let dir = dir();
            let pol = Policy::parse(&fs::read_to_string(dir.join("policy.toml")).unwrap_or_default()).unwrap_or_else(|e| die(e));
            let kd = ks_dir(&dir);
            let lock = kd.lock().unwrap_or_else(|e| die(e));
            let del = kd
                .prune(&lock, now_secs(), pol.retention_days * 86_400, flag(args, "--purge"))
                .unwrap_or_else(|e| die(e));
            println!("deleted {} keystore epochs (retention {} days, newest kept): {del:?}", del.len(), pol.retention_days);
        }
        "ks-resync-plain" => {
            let dir = dir();
            let (_, _, ks) = open_newest(&dir, slot_secret(args).as_ref());
            let before = plain_bundle(&dir).unwrap_or_else(|e| die(e));
            let kb = ks.bundle_text().unwrap_or_else(|e| die(e));
            if sha_hex(&before) == sha_hex(&kb) {
                println!("plain files already equal the keystore");
                return true;
            }
            let m = read_v2(&dir);
            let km = ks.master().unwrap_or_else(|e| die(e));
            if m.fingerprint() != km.fingerprint() || m.escrow_digest() != km.escrow_digest() {
                die("the plain master keyring is a different root: refusing to resync");
            }
            replace_file(&dir.join("ledger.jsonl"), ks.ledger.to_text().as_bytes());
            replace_file(&dir.join("tenants"), ks.tenants_text().as_bytes());
            let tk = read_tenants(&dir).unwrap_or_else(|e| die(e));
            let (file, dg) = issue_escrow(&dir, &m, &tk);
            println!("plain tenants and ledger rewritten from epoch {}; legacy sealed copy {file} digest {dg}", ks.epoch);
            dual_check(&dir, &ks);
        }
        "ks-master-escrow-replace" => {
            let dir = dir();
            let place = need(args, "--place");
            let (n, b, mut ks) = open_newest(&dir, slot_secret(args).as_ref());
            let mut m = ks.master().unwrap_or_else(|e| die(e));
            m.escrows.clear();
            let dg = m.escrow_digest();
            m.confirm_escrow(&dg, &place, now_secs()).unwrap_or_else(|e| die(e));
            ks.chain_from(&b);
            ks.replace_master_text(&m.to_text(), now_secs()).unwrap_or_else(|e| die(e));
            let (ep, d) = commit(&dir, n, &b, &mut ks);
            record_change(&dir, "master-escrow-replace", &place);
            println!("master escrow places replaced by one '{place}' record (same root digest); epoch {ep} sha256 {d}");
        }
        _ => return false,
    }
    true
}

fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Recovery drill (4.7, `kh-drill`): copies + one slot key -> hash chain, newest epoch opened, bundle digest,
/// slot table, ledger head; optionally a fresh keyd directory (new host slot, new psk).
fn drill(args: &[String]) {
    let copies: Vec<Vec<u8>> = all(args, "--copy").iter().map(|f| fs::read(f).unwrap_or_else(|e| die(format!("{f}: {e}")))).collect();
    if copies.is_empty() {
        die("kh-drill needs at least one --copy");
    }
    let (newest, digest) = check_chain(&copies).unwrap_or_else(|e| die(e));
    let bytes = copies
        .iter()
        .find(|c| PublicInfo::parse(c).map(|i| i.epoch == newest).unwrap_or(false))
        .unwrap()
        .clone();
    let s = slot_secret(args);
    let mut ks = Keystore::open(&bytes, s.as_ref()).unwrap_or_else(|e| die(format!("epoch {newest}: {e}")));
    let bundle = ks.bundle_text().unwrap_or_else(|e| die(e));
    let m = Arc::new(ks.master().unwrap_or_else(|e| die(e)));
    println!(
        "drill: {} copies, hash chain ok, newest epoch {newest} sha256 {digest}\n  bundle sha256 {}\n  master {} root escrowed {}\n  ledger {} entries head {}",
        copies.len(),
        sha_hex(&bundle),
        m.fingerprint(),
        m.is_escrowed(),
        ks.ledger.entries.len(),
        ks.ledger.head().1
    );
    for t in ks.tenants.tenants.values() {
        println!("  tenant {}", tenant_line(&m, t));
    }
    let audit_ok = slot_audit(&ks, arg(args, "--approved").as_deref());
    let mut ok = audit_ok;
    if let Some(bf) = arg(args, "--baseline") {
        let base = Baseline::parse(&fs::read_to_string(&bf).unwrap_or_else(|e| die(e))).unwrap_or_else(|e| die(e));
        let ch = arg(args, "--changes").map(|f| parse_changes(&fs::read_to_string(f).unwrap_or_default())).unwrap_or_default();
        let (rep, good) = compare(&base, &bundle, &ch).unwrap_or_else(|e| die(e));
        for l in rep {
            println!("  {l}");
        }
        ok &= good;
    }
    if let Some(out) = arg(args, "--rebuild-dir") {
        let out = PathBuf::from(out);
        let keys = out.join("keys");
        if keys.exists() {
            die(format!("{} exists; the rebuild needs a fresh directory", keys.display()));
        }
        fs::create_dir_all(keys.join("keystore")).unwrap_or_else(|e| die(e));
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap_or_else(|e| die(e));
        }
        // merge the surviving proxy's ledger first: its chain may be longer (4.7 step 2)
        for f in all(args, "--ledger-merge") {
            let other = Ledger::parse(&fs::read_to_string(&f).unwrap_or_else(|e| die(e))).unwrap_or_else(|e| die(e));
            let mut l = ks.ledger.clone();
            match l.merge(&other) {
                Ok(changed) => {
                    if changed {
                        println!("  ledger merged from {f}: now {} entries", l.entries.len());
                    }
                    ks.ledger = l;
                }
                Err(e) => {
                    // an outbox is not a chain extension: import it instead
                    let n = keystore::import_outbox(&mut ks.ledger, &other).unwrap_or_else(|_| die(format!("ledger {f}: {e}")));
                    println!("  outbox {f}: imported {n} entries");
                }
            }
        }
        // the recovered epoch is epoch N in the new directory; a new host slot makes N+1
        let kd = KeystoreDir::new(keys.join("keystore"));
        let host = SoftSecret::generate(Kem::X25519);
        write_secret(&keys.join("host-slot.key"), slots::soft_key_text(&host).as_bytes()).unwrap_or_else(|e| die(e));
        let hp = SlotPub {
            kem: Kem::X25519,
            pk: host.public_key(),
            kind: "host".into(),
            label: "recovered-host".into(),
            holder: "owner".into(),
            backend: "file".into(),
            target: PubTarget::Master,
        };
        write_secret(&kd.dir.join(epoch_file_name(newest)), &bytes).unwrap_or_else(|e| die(e));
        ks.chain_from(&bytes);
        let id = ks.add_slot(&hp, "kh-drill", now_secs()).unwrap_or_else(|e| die(e));
        let nb = ks.seal().unwrap_or_else(|e| die(e));
        let lock = kd.lock().unwrap_or_else(|e| die(e));
        kd.write_epoch(&lock, Some(newest), ks.epoch, &nb).unwrap_or_else(|e| die(e));
        write_secret(&keys.join("psk"), keyproto::generate_psk_text().as_bytes()).unwrap_or_else(|e| die(e));
        replace_file(&keys.join("ledger.jsonl"), ks.ledger.to_text().as_bytes());
        write_secret(&keys.join("policy.toml"), ks.policy_text.as_bytes()).unwrap_or_else(|e| die(e));
        let rb = ks.bundle_text().unwrap_or_else(|e| die(e));
        println!(
            "  rebuilt keyd directory {}: epoch {} with new host slot {id} (file host-slot.key), new psk; bundle sha256 {}\n  \
             next: start keyd --source keystore --slot file:{}/host-slot.key, point the proxy at it (new psk), unlock; \
             then revoke the lost host and device slots",
            keys.display(),
            ks.epoch,
            sha_hex(&rb),
            keys.display()
        );
    }
    if !ok {
        die("kh-drill: FAILED (see above)");
    }
    println!("kh-drill: ok");
}
