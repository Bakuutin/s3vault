//! s3vault command line.
//!
//! ```text
//! s3vault serve   --config FILE
//! s3vault check   --config FILE            validate the config and fetch the keys (prints fingerprints only:
//!                                          master, each tenant's K_t, the bundle SHA-256)
//! s3vault rebuild --config FILE --out NEW_DATA_DIR [--tenant NAME] [--snapshot] [--concurrency N]
//!                 [--no-replay] [--keyring-file F --tenants-file F --ledger-file F]
//!                 rebuild the index partitions from the store (and the tenant snapshots); replays the
//!                 erasure ledger on the stores first
//! s3vault migrate-v2 --config FILE --old-index PATH [--delete-v1]
//!                 offline: re-encrypt every object of a v1 index as format v2 under its bucket's tenant
//! s3vault ledger-replay --config FILE (--store NAME | --dir PATH [--prefix o/]) [--ledger FILE] [--dry-run]
//!                 apply the erasure ledger to a restored store or a follower copy (needs no key)
//! s3vault escrow-digest --file KEYRING     digest of a master keyring copy (v1 or v2), for escrow-confirm
//! s3vault tenant-escrow-check --file COPY --keyring MASTER
//!                 open a tenant escrow copy with the master keyring; prints its digest and tenant names
//! s3vault escrow-prune --dir DIR [--max-age-days 30]   delete escrow copies older than the limit (keeps the newest)
//! s3vault gen-client --secret-out FILE     new client access key id (printed) and secret (written, mode 600)
//! s3vault gen-keyring --out FILE           new keyring file (mode 600) for tests; production uses s3vault-keyd init
//! s3vault gen-admin-token --out FILE       new admin API bearer token (written, mode 600; never printed)
//! ```

use anyhow::{Context, Result, bail};
use rand::RngCore;
use s3vault::background::{fetch_bundle, harden_process, legacy_keyring, rebuild};
use s3vault::config::{Config, KeySource};
use s3vault::index::Index;
use s3vault::vault::Vault;
use s3vault_format::keys2::{MasterV2, open_tenant_escrow, escrow_file_digest, prune_escrow_dir};
use s3vault_format::keyring::Keyring;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use tracing::info;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn need(args: &[String], name: &str) -> Result<String> {
    arg(args, name).with_context(|| format!("missing {name}"))
}

fn write_secret_file(path: &str, data: &[u8]) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {path} (refusing to overwrite)"))?;
    f.write_all(data)?;
    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    match cmd {
        "serve" => {
            harden_process();
            let cfg = Config::load(&PathBuf::from(need(&args, "--config")?))?;
            rt.block_on(async move {
                let running = s3vault::start(cfg).await?;
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = term.recv() => {},
                }
                info!("shutting down");
                running.shutdown().await;
                Ok::<_, anyhow::Error>(())
            })
        }
        "check" => {
            let cfg = Config::load(&PathBuf::from(need(&args, "--config")?))?;
            let b = fetch_bundle(&cfg.keys)?;
            println!(
                "config ok; master fingerprint {} active generation {} root escrowed {} ({:?}); legacy v1 keys {}",
                b.master.fingerprint(),
                b.master.active,
                b.master.is_escrowed(),
                b.master.escrow_places(),
                b.master.legacy.as_ref().map(|l| l.fingerprint()).unwrap_or_else(|| "none".into())
            );
            // key hierarchy gates G4/G5: each tenant's K_t fingerprint and the bundle digest (non-secret)
            let base = s3vault_format::keystore::Baseline::from_bundle(&b.to_text())?;
            for t in b.tenants.tenants.values() {
                let fp = base.tenants.get(&t.name).map(|x| x.2.as_str()).unwrap_or("-");
                println!("tenant {} {} {} k_t_fp {fp}", t.name, t.id_hex(), t.status.as_str());
            }
            println!("ledger entries {} head {}", b.ledger.entries.len(), base.ledger_head);
            println!("bundle_sha256 {} root_escrow_digest {}", base.bundle_sha256, base.root_escrow_digest);
            Ok(())
        }
        "rebuild" => {
            harden_process();
            let mut cfg = Config::load(&PathBuf::from(need(&args, "--config")?))?;
            if let Some(f) = arg(&args, "--keyring-file") {
                cfg.keys.source = KeySource::File;
                cfg.keys.file = Some(f.into());
                cfg.keys.tenants_file = arg(&args, "--tenants-file").map(Into::into);
                cfg.keys.ledger_file = arg(&args, "--ledger-file").map(Into::into);
            }
            let out = PathBuf::from(need(&args, "--out")?);
            if out.join("tenants").exists() {
                bail!(
                    "{} already holds index partitions; rebuild writes a fresh data directory",
                    out.display()
                );
            }
            let conc: usize = arg(&args, "--concurrency")
                .and_then(|c| c.parse().ok())
                .unwrap_or(16);
            let use_snapshot = args.iter().any(|a| a == "--snapshot");
            let only = arg(&args, "--tenant");
            let replay = !args.iter().any(|a| a == "--no-replay");
            cfg.server.data_dir = out.clone();
            cfg.server.listen.clear();
            cfg.server.admin_listen = None;
            let bundle = fetch_bundle(&cfg.keys)?;
            let vault = Vault::new(cfg)?;
            vault.unlock(bundle)?;
            let u = vault.unlocked()?;
            let mut reports = serde_json::Map::new();
            if replay {
                let entries = s3vault::erasure::all_entries(&vault)?;
                let r = rt.block_on(s3vault::erasure::replay_all(&vault, &entries, false))?;
                reports.insert("ledger_replay".into(), serde_json::to_value(&r)?);
            }
            for t in u.loaded_tenants() {
                if only.as_ref().is_some_and(|o| o != &t.keys.name) {
                    continue;
                }
                info!(tenant = %t.keys.name, "rebuilding");
                let rep = rt.block_on(rebuild(vault.clone(), &t.keys, &t.index, use_snapshot, conc))?;
                reports.insert(
                    t.keys.name.clone(),
                    serde_json::json!({"id": t.keys.id_hex(), "report": rep}),
                );
            }
            println!("{}", serde_json::to_string_pretty(&reports)?);
            Ok(())
        }
        "migrate-v2" => {
            harden_process();
            let cfg = Config::load(&PathBuf::from(need(&args, "--config")?))?;
            let old_path = PathBuf::from(need(&args, "--old-index")?);
            let delete_v1 = args.iter().any(|a| a == "--delete-v1");
            let bundle = fetch_bundle(&cfg.keys)?;
            let legacy = legacy_keyring(&bundle)?;
            let old = Index::open(&old_path, Some(&legacy.index_db_key()))?;
            match old.meta_get("keyring_fingerprint")? {
                Some(fp) if fp == legacy.fingerprint() => {}
                other => bail!("the old index belongs to keyring {other:?}, not the legacy keys"),
            }
            let vault = Vault::new(cfg)?;
            vault.unlock(bundle)?;
            let rep = rt.block_on(s3vault::migrate::migrate_v2(&vault, &legacy, &old, delete_v1))?;
            println!("{}", serde_json::to_string_pretty(&rep)?);
            Ok(())
        }
        "ledger-replay" => {
            let cfg = Config::load(&PathBuf::from(need(&args, "--config")?))?;
            let dry = args.iter().any(|a| a == "--dry-run");
            let mut entries = match arg(&args, "--ledger") {
                Some(f) => s3vault_format::ledger::Ledger::parse(&std::fs::read_to_string(&f)?)?.entries,
                None => fetch_bundle(&cfg.keys)?.ledger.entries,
            };
            if let Ok(t) = std::fs::read_to_string(cfg.server.data_dir.join("outbox.jsonl")) {
                let out = s3vault_format::ledger::Ledger::parse(&t)?;
                let known: std::collections::HashSet<String> = entries
                    .iter()
                    .filter_map(|e| e.detail.get("src_hash").and_then(|v| v.as_str()).map(String::from))
                    .collect();
                entries.extend(out.entries.into_iter().filter(|e| !known.contains(&e.hash)));
            }
            let target = if let Some(d) = arg(&args, "--dir") {
                s3vault::erasure::ReplayTarget::Dir {
                    dir: d.into(),
                    prefix: arg(&args, "--prefix").unwrap_or_else(|| "o/".into()),
                }
            } else {
                let name = need(&args, "--store")?;
                let sc = cfg.stores.get(&name).with_context(|| format!("no store {name}"))?;
                s3vault::erasure::ReplayTarget::Store(std::sync::Arc::new(
                    s3vault::remote::Remote::from_cfg(&format!("store:{name}"), sc, None)?,
                ))
            };
            let r = rt.block_on(s3vault::erasure::replay(&entries, &target, dry))?;
            println!("{}", serde_json::to_string_pretty(&r)?);
            Ok(())
        }
        "escrow-digest" => {
            let text = zeroize::Zeroizing::new(std::fs::read_to_string(need(&args, "--file")?)?);
            if text.starts_with("s3vault-keyring v2") {
                let m = MasterV2::parse(&text)?;
                println!("digest {} fingerprint {} (master v2)", m.escrow_digest(), m.fingerprint());
            } else {
                let k = Keyring::parse(&text)?;
                println!("digest {} fingerprint {} kids {:?} (v1)", k.escrow_digest(), k.fingerprint(), k.kids());
            }
            Ok(())
        }
        "tenant-escrow-check" => {
            let copy = std::fs::read(need(&args, "--file")?)?;
            let text = zeroize::Zeroizing::new(std::fs::read_to_string(need(&args, "--keyring")?)?);
            let m = MasterV2::parse(&text)?;
            let (issued, tk) = open_tenant_escrow(&m, &copy)
                .map_err(|e| anyhow::anyhow!("the copy does not open with this master keyring: {e}"))?;
            println!("digest {} issued {issued} opens with master {}", escrow_file_digest(&copy), m.fingerprint());
            for t in tk.tenants.values() {
                println!("tenant {} {} {}", t.name, t.id_hex(), t.status.as_str());
            }
            Ok(())
        }
        "escrow-prune" => {
            let dir = PathBuf::from(need(&args, "--dir")?);
            let days: u64 = arg(&args, "--max-age-days").and_then(|d| d.parse().ok()).unwrap_or(30);
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
            for n in prune_escrow_dir(&dir, now, days * 86_400)? {
                println!("deleted {n}");
            }
            Ok(())
        }
        "gen-client" => {
            let out = need(&args, "--secret-out")?;
            let mut id = [0u8; 10];
            rand::rngs::OsRng.fill_bytes(&mut id);
            let mut sec = [0u8; 30];
            rand::rngs::OsRng.fill_bytes(&mut sec);
            let access = format!("SV{}", data_encoding::BASE32_NOPAD.encode(&id));
            let secret = zeroize::Zeroizing::new(data_encoding::BASE64URL_NOPAD.encode(&sec));
            write_secret_file(&out, format!("{}\n", secret.as_str()).as_bytes())?;
            println!("access_key_id = \"{access}\"\nsecret_file = \"{out}\"");
            Ok(())
        }
        "gen-admin-token" => {
            let out = need(&args, "--out")?;
            let mut t = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut t);
            let tok = zeroize::Zeroizing::new(data_encoding::BASE64URL_NOPAD.encode(&t));
            write_secret_file(&out, format!("{}\n", tok.as_str()).as_bytes())?;
            println!("admin token written to {out}");
            Ok(())
        }
        "gen-keyring" => {
            let out = need(&args, "--out")?;
            let kr = MasterV2::generate(None);
            write_secret_file(&out, kr.to_text().as_bytes())?;
            println!(
                "master keyring v2 written (fingerprint {}); not escrowed yet: escrow digest {}",
                kr.fingerprint(),
                kr.escrow_digest()
            );
            Ok(())
        }
        _ => {
            eprintln!(
                "usage: s3vault serve|check|rebuild|migrate-v2|ledger-replay|escrow-digest|tenant-escrow-check|escrow-prune|gen-client|gen-admin-token|gen-keyring ... (see README.md)"
            );
            std::process::exit(2)
        }
    }
}
