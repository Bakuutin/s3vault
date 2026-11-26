//! s3vault command line.
//!
//! ```text
//! s3vault serve   --config FILE
//! s3vault rebuild --config FILE --index NEW_INDEX_PATH [--snapshot] [--concurrency N] [--keyring-file FILE]
//! s3vault check   --config FILE            validate the config and fetch the keyring (prints the fingerprint)
//! s3vault gen-client --secret-out FILE     new client access key id (printed) and secret (written, mode 600)
//! s3vault gen-keyring --out FILE           new keyring file (mode 600) for tests; production uses s3vault-keyd init
//! s3vault gen-admin-token --out FILE       new admin API bearer token (written, mode 600; never printed)
//! ```

use anyhow::{Context, Result, bail};
use rand::RngCore;
use s3vault::background::{fetch_keyring, harden_process, rebuild};
use s3vault::config::{Config, KeySource};
use s3vault::index::Index;
use s3vault::vault::Vault;
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
            let kr = fetch_keyring(&cfg.keys)?;
            println!(
                "config ok; keyring fingerprint {} kids {:?} active {}",
                kr.fingerprint(),
                kr.kids(),
                kr.active_kid
            );
            Ok(())
        }
        "rebuild" => {
            harden_process();
            let mut cfg = Config::load(&PathBuf::from(need(&args, "--config")?))?;
            if let Some(f) = arg(&args, "--keyring-file") {
                cfg.keys.source = KeySource::File;
                cfg.keys.file = Some(f.into());
            }
            let index_path = PathBuf::from(need(&args, "--index")?);
            if index_path.exists() {
                bail!(
                    "{} exists; rebuild writes a fresh index (move it into place after checking)",
                    index_path.display()
                );
            }
            let conc: usize = arg(&args, "--concurrency")
                .and_then(|c| c.parse().ok())
                .unwrap_or(16);
            let use_snapshot = args.iter().any(|a| a == "--snapshot");
            let kr = fetch_keyring(&cfg.keys)?;
            let index = Index::open(&index_path, Some(&kr.index_db_key()))?;
            index.meta_set("keyring_fingerprint", &kr.fingerprint())?;
            let vault = Vault::new(cfg)?;
            let rep = rt.block_on(rebuild(vault, &kr, &index, use_snapshot, conc))?;
            println!("{}", serde_json::to_string_pretty(&rep)?);
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
            let kr = s3vault_format::keyring::Keyring::generate();
            write_secret_file(&out, kr.to_text().as_bytes())?;
            println!("keyring written (fingerprint {})", kr.fingerprint());
            Ok(())
        }
        _ => {
            eprintln!(
                "usage: s3vault serve|check|rebuild|gen-client|gen-admin-token|gen-keyring ... (see README.md)"
            );
            std::process::exit(2)
        }
    }
}
