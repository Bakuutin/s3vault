//! Admin API (loopback only, bearer token): status, fill control, verification, snapshots, unlock retry.
//!
//! Every call needs `Authorization: Bearer <token>` (the content of `server.admin_token_file`); anything
//! else gets 401.
//!
//! ```text
//! GET  /status
//! GET  /fill
//! POST /fill/start?bucket=B[&max_objects=N][&rate=BYTES_PER_SEC][&concurrency=N][&restart=1]
//! POST /fill/stop?bucket=B
//! POST /verify?bucket=B[&max=N][&origin=fill|write|any][&fallback=1]
//! POST /reconcile?bucket=B&dry_run=1      count filled copies the fallback deleted or changed since
//! POST /reconcile?bucket=B&expect=N[&force=1]
//!                       remove them; N must equal the dry run's `stale`; refused above the configured
//!                       fraction unless force=1; refused when the fallback lists empty or is retired
//! GET  /manifest?bucket=B[&after=K][&limit=N]   index rows only (key, size, sha256, etag, mtime, state);
//!                       never asks the fallback (export manifests and deploy pass checks)
//! POST /snapshot
//! POST /unlock          (retry the key service now)
//! ```

use crate::background::{self, Fills};
use crate::vault::Vault;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::net::TcpListener;
use tokio::sync::{Notify, watch};
use tracing::info;

#[derive(Clone)]
pub struct AdminCtx {
    pub vault: Arc<Vault>,
    pub fills: Arc<Fills>,
    pub wake: Arc<Notify>,
    /// The bearer token every call must present.
    pub token: Arc<zeroize::Zeroizing<String>>,
}

fn authorized(req: &Request<Incoming>, token: &str) -> bool {
    let Some(h) = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(got) = h.strip_prefix("Bearer ") else {
        return false;
    };
    !token.is_empty() && bool::from(subtle::ConstantTimeEq::ct_eq(got.trim().as_bytes(), token.as_bytes()))
}

pub async fn serve_admin(
    listener: TcpListener,
    ctx: AdminCtx,
    mut shutdown: watch::Receiver<bool>,
) {
    info!(
        "admin API on {}",
        listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    );
    loop {
        let (sock, _) = tokio::select! {
            r = listener.accept() => match r { Ok(c) => c, Err(_) => continue },
            _ = shutdown.changed() => return,
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| handle(ctx.clone(), req));
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(sock), svc)
                .await;
        });
    }
}

fn reply(code: StatusCode, v: Value) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = serde_json::to_vec_pretty(&v).unwrap_or_default();
    Ok(Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

pub fn status_json(vault: &Vault, fills: &Fills) -> Value {
    let mut buckets = Vec::new();
    let mut names: Vec<&String> = vault.buckets.keys().collect();
    names.sort();
    let u = vault.unlocked().ok();
    for n in names {
        let b = &vault.buckets[n];
        let counts = u.as_ref().and_then(|u| u.index.counts(n).ok());
        buckets.push(json!({
            "name": n,
            "store": b.store.label,
            "store_bucket": b.store.bucket_name(),
            "fallback": b.fallback.as_ref().map(|f| f.label.clone()),
            "fallback_bucket": b.fallback.as_ref().map(|f| f.bucket_name().to_string()),
            "index_live": counts.map(|c| c.0),
            "index_tombstones": counts.map(|c| c.1),
            "index_live_bytes": counts.map(|c| c.2),
        }));
    }
    json!({
        "locked": vault.is_locked(),
        "unlock_error": *vault.last_unlock_error.read().unwrap(),
        "keyring_fingerprint": u.as_ref().map(|u| u.keyring.fingerprint()),
        "active_kid": u.as_ref().map(|u| u.keyring.active_kid),
        "write_kid": u.as_ref().map(|u| u.keyring.write_kid()),
        "pending_kid": u.as_ref().map(|u| u.keyring.pending_kid),
        "active_kid_escrowed": u.as_ref().map(|u| u.keyring.is_escrowed(u.keyring.active_kid)),
        "escrow_places": u.as_ref().map(|u| u.keyring.escrow_places()),
        "kids": u.as_ref().map(|u| u.keyring.kids()),
        "started_ms": vault.started_ms,
        "live_fetches": vault.live_fetches.load(Ordering::SeqCst),
        "buckets": buckets,
        "fills": fills.statuses(vault),
    })
}

async fn handle(
    ctx: AdminCtx,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let q: HashMap<String, String> =
        url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    let num = |k: &str| q.get(k).and_then(|v| v.parse::<u64>().ok());
    let vault = ctx.vault.clone();
    if !authorized(&req, &ctx.token) {
        return reply(
            StatusCode::UNAUTHORIZED,
            json!({"error": "admin token required (Authorization: Bearer ...)"}),
        );
    }
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/status") | (&Method::GET, "/") => {
            reply(StatusCode::OK, status_json(&vault, &ctx.fills))
        }
        (&Method::GET, "/fill") => reply(StatusCode::OK, json!(ctx.fills.statuses(&vault))),
        (&Method::POST, "/fill/start") => {
            let Some(bucket) = q.get("bucket") else {
                return reply(StatusCode::BAD_REQUEST, json!({"error": "bucket"}));
            };
            let rate = num("rate")
                .unwrap_or(vault.cfg.fill.rate_bytes_per_sec)
                .max(1);
            let conc = num("concurrency")
                .map(|c| c as usize)
                .unwrap_or(vault.cfg.fill.concurrency)
                .clamp(1, crate::config::MAX_FILL_CONCURRENCY);
            let restart = q.get("restart").is_some_and(|v| v == "1");
            match ctx.fills.start(
                vault.clone(),
                bucket,
                num("max_objects"),
                rate,
                conc,
                restart,
            ) {
                Ok(()) => reply(
                    StatusCode::OK,
                    json!({"started": bucket, "max_objects": num("max_objects"), "rate": rate, "concurrency": conc}),
                ),
                Err(e) => reply(StatusCode::CONFLICT, json!({"error": e})),
            }
        }
        (&Method::POST, "/fill/stop") => {
            let Some(bucket) = q.get("bucket") else {
                return reply(StatusCode::BAD_REQUEST, json!({"error": "bucket"}));
            };
            reply(StatusCode::OK, json!({"stopping": ctx.fills.stop(bucket)}))
        }
        (&Method::POST, "/verify") => {
            let Some(bucket) = q.get("bucket") else {
                return reply(StatusCode::BAD_REQUEST, json!({"error": "bucket"}));
            };
            let origin = match q.get("origin").map(String::as_str) {
                Some("fill") | None => Some(1),
                Some("write") => Some(0),
                _ => None,
            };
            let fb = q.get("fallback").is_some_and(|v| v == "1");
            match background::verify(
                vault.clone(),
                bucket,
                num("max").unwrap_or(100) as usize,
                origin,
                fb,
            )
            .await
            {
                Ok(r) => reply(StatusCode::OK, json!(r)),
                Err(e) => reply(
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({"error": format!("{e:#}")}),
                ),
            }
        }
        (&Method::POST, "/reconcile") => {
            let Some(bucket) = q.get("bucket") else {
                return reply(StatusCode::BAD_REQUEST, json!({"error": "bucket"}));
            };
            let dry = q.get("dry_run").is_some_and(|v| v == "1");
            let force = q.get("force").is_some_and(|v| v == "1");
            let expect = num("expect");
            if !dry && expect.is_none() {
                return reply(
                    StatusCode::BAD_REQUEST,
                    json!({"error": "run with dry_run=1 first, then pass expect=<stale count from the dry run>"}),
                );
            }
            let opts = background::ReconcileOpts {
                dry_run: dry,
                expect,
                force,
            };
            match background::reconcile(vault.clone(), bucket, opts).await {
                Ok(r) => reply(StatusCode::OK, json!(r)),
                Err(e) => reply(
                    StatusCode::CONFLICT,
                    json!({"error": format!("{e:#}")}),
                ),
            }
        }
        (&Method::GET, "/manifest") => {
            let Some(bucket) = q.get("bucket") else {
                return reply(StatusCode::BAD_REQUEST, json!({"error": "bucket"}));
            };
            let after = q.get("after").cloned().unwrap_or_default();
            let limit = num("limit").unwrap_or(1000).clamp(1, 10_000) as usize;
            let rows = match vault
                .unlocked()
                .map_err(|e| e.to_string())
                .and_then(|u| u.index.list(bucket, "", &after, limit).map_err(|e| e.to_string()))
            {
                Ok(r) => r,
                Err(e) => return reply(StatusCode::SERVICE_UNAVAILABLE, json!({"error": e})),
            };
            let next = (rows.len() == limit).then(|| rows.last().map(|r| r.key.clone()));
            let items: Vec<Value> = rows
                .iter()
                .map(|r| {
                    json!({"key": r.key, "size": r.size, "sha256": r.sha256, "etag": r.etag,
                           "mtime_ms": r.mtime_ms, "tombstone": r.state == crate::index::TOMBSTONE})
                })
                .collect();
            reply(StatusCode::OK, json!({"bucket": bucket, "items": items, "next_after": next.flatten()}))
        }
        (&Method::POST, "/snapshot") => match background::snapshot(&vault).await {
            Ok(r) => reply(StatusCode::OK, json!(r)),
            Err(e) => reply(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": format!("{e:#}")}),
            ),
        },
        (&Method::POST, "/unlock") => {
            ctx.wake.notify_one();
            reply(
                StatusCode::OK,
                json!({"locked": vault.is_locked(), "retrying": vault.is_locked()}),
            )
        }
        _ => reply(StatusCode::NOT_FOUND, json!({"error": "not found"})),
    }
}
