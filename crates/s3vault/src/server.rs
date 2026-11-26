//! Listeners: the S3 service (s3s over hyper) and the admin API.

use crate::config::Config;
use crate::s3::{VaultAccess, VaultS3, load_clients};
use crate::vault::Vault;
use anyhow::{Context, Result};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use s3s::service::{S3Service, S3ServiceBuilder};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info};

pub fn build_s3_service(vault: Arc<Vault>, cfg: &Config) -> Result<S3Service> {
    let (auth, clients) = load_clients(cfg)?;
    let mut b = S3ServiceBuilder::new(VaultS3 {
        vault,
        clients: clients.clone(),
    });
    b.set_auth(auth);
    b.set_access(VaultAccess { clients });
    Ok(b.build())
}

/// Bind a TCP listener. On Linux, `IP_FREEBIND` lets the proxy bind its Tailscale address before
/// tailscaled has brought the interface up (boot ordering).
pub fn bind(addr: &str) -> Result<TcpListener> {
    let sa: SocketAddr = addr
        .parse()
        .with_context(|| format!("listen address {addr}"))?;
    let domain = if sa.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let s = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    s.set_reuse_address(true)?;
    #[cfg(target_os = "linux")]
    {
        if sa.is_ipv4() {
            s.set_freebind_v4(true)?;
        } else {
            s.set_freebind_v6(true)?;
        }
    }
    s.set_nonblocking(true)?;
    s.bind(&sa.into()).with_context(|| format!("bind {addr}"))?;
    s.listen(1024)?;
    let std_listener: std::net::TcpListener = s.into();
    Ok(TcpListener::from_std(std_listener)?)
}

pub async fn serve(listener: TcpListener, service: S3Service, mut shutdown: watch::Receiver<bool>) {
    let local = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let http = ConnBuilder::new(TokioExecutor::new());
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    info!("listening on {local}");
    loop {
        let (socket, _) = tokio::select! {
            r = listener.accept() => match r {
                Ok(c) => c,
                Err(e) => { error!("accept on {local}: {e}"); continue; }
            },
            _ = shutdown.changed() => break,
        };
        let conn = http.serve_connection(TokioIo::new(socket), service.clone());
        let conn = graceful.watch(conn.into_owned());
        tokio::spawn(async move {
            let _ = conn.await;
        });
    }
    tokio::select! {
        () = graceful.shutdown() => {},
        () = tokio::time::sleep(std::time::Duration::from_secs(30)) => {},
    }
    info!("listener {local} stopped");
}
