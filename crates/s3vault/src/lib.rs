//! s3vault: an encrypting S3 gateway.
//!
//! Clients speak S3 to it with per-bucket access keys. It stores only ciphertext in the store of record
//! (content and object names; see `s3vault_format::object`), reads through from an optional legacy store
//! with write-back, keeps tombstones so a fallback never resurrects a delete, and holds its keyring only in
//! RAM (fetched from `s3vault-keyd`). The sqlite index is a cache: the store plus the keyring rebuild it.

pub mod admin;
pub mod background;
pub mod config;
pub mod index;
pub mod remote;
pub mod s3;
pub mod server;
pub mod spool;
pub mod streams;
pub mod vault;

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Notify, watch};

pub struct Running {
    pub vault: Arc<vault::Vault>,
    pub fills: Arc<background::Fills>,
    pub s3_addrs: Vec<SocketAddr>,
    pub admin_addr: Option<SocketAddr>,
    pub wake: Arc<Notify>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Running {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for t in self.tasks {
            let _ = t.await;
        }
    }
}

/// Start listeners and background tasks. The vault starts locked and unlocks when the keyring arrives.
pub async fn start(cfg: config::Config) -> Result<Running> {
    let vault = vault::Vault::new(cfg.clone())?;
    let fills = Arc::new(background::Fills::default());
    let wake = Arc::new(Notify::new());
    let (tx, rx) = watch::channel(false);
    let service = server::build_s3_service(vault.clone(), &cfg)?;
    let mut tasks = Vec::new();
    let mut s3_addrs = Vec::new();
    for addr in &cfg.server.listen {
        let l = server::bind(addr)?;
        s3_addrs.push(l.local_addr()?);
        tasks.push(tokio::spawn(server::serve(l, service.clone(), rx.clone())));
    }
    let mut admin_addr = None;
    if let Some(a) = &cfg.server.admin_listen {
        let l = server::bind(a)?;
        admin_addr = Some(l.local_addr()?);
        let token_file = cfg
            .server
            .admin_token_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("admin_listen needs admin_token_file"))?;
        let token = config::read_secret_line(token_file)?;
        if token.len() < 32 {
            anyhow::bail!("admin token in {} is too short (32+ characters)", token_file.display());
        }
        let ctx = admin::AdminCtx {
            vault: vault.clone(),
            fills: fills.clone(),
            wake: wake.clone(),
            token: Arc::new(zeroize::Zeroizing::new(token)),
        };
        tasks.push(tokio::spawn(admin::serve_admin(l, ctx, rx.clone())));
    }
    tokio::spawn(background::unlock_loop(vault.clone(), wake.clone()));
    tokio::spawn(background::maintenance_loop(vault.clone()));
    Ok(Running {
        vault,
        fills,
        s3_addrs,
        admin_addr,
        wake,
        shutdown: tx,
        tasks,
    })
}
