//! s3vault-provision command line. Runs on the key host, never on the proxy.
//!
//! ```text
//! s3vault-provision [--admin-env FILE] [--state FILE] [--api URL] [--max-buckets N] COMMAND
//!   provision-tenant --tenant T (--out FILE | --out -) [--recipient PUB.pem]
//!         new random-name private bucket (lifecycle D2, object lock off) and a key scoped to it;
//!         the key goes to --out (mode 600, or stdout when it is not a terminal), sealed to the proxy's
//!         RSA key with --recipient; the [stores.*] block for the proxy goes to stderr
//!   rotate-key --tenant T (--out FILE | --out -) [--recipient PUB.pem]   a new scoped key (old ones stay)
//!   revoke-old-keys --tenant T            delete every key of the bucket but the newest
//!   retire-tenant --tenant T --confirm T  after the erasure on the proxy: revoke all bucket keys, drain lifecycle
//!   deprovision-tenant --tenant T --confirm T [--purge]   delete the (drained) bucket
//!   list                                  state against the account (JSON; key ids shortened to their last 4 characters)
//!   check-key --key-env FILE              authorize a key (B2_APPLICATION_KEY_ID/_KEY or a credentials TOML);
//!                                         print its bucket scope and capabilities
//! ```
//!
//! Defaults: `--admin-env /srv/s3vault-provision/b2-admin.env`, `--state` next to it (`state.json`),
//! `--api https://api.backblazeb2.com` (or `$B2_API_URL`), `--max-buckets 100`.

use anyhow::{Context, Result, bail};
use s3vault_provision::*;
use std::io::{IsTerminal, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn need(args: &[String], name: &str) -> Result<String> {
    arg(args, name).with_context(|| format!("missing {name}"))
}

fn emit_secret(args: &[String], creds: &Creds) -> Result<()> {
    let plain = credentials_toml(creds);
    let data = match arg(args, "--recipient") {
        Some(p) => zeroize::Zeroizing::new(seal_for(Path::new(&p), plain.as_bytes())?),
        None => plain,
    };
    let out = need(args, "--out")?;
    if out == "-" {
        if std::io::stdout().is_terminal() {
            bail!("refusing to print a key on a terminal: redirect stdout or use --out FILE");
        }
        let mut o = std::io::stdout().lock();
        o.write_all(data.as_bytes())?;
        o.flush()?;
    } else {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&out)
            .with_context(|| format!("create {out} (refusing to overwrite)"))?;
        f.write_all(data.as_bytes())?;
    }
    Ok(())
}

fn confirm(args: &[String], tenant: &str) -> Result<()> {
    if arg(args, "--confirm").as_deref() != Some(tenant) {
        bail!("pass --confirm {tenant}");
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let admin_env = PathBuf::from(arg(&args, "--admin-env").unwrap_or_else(|| "/srv/s3vault-provision/b2-admin.env".into()));
    let state = arg(&args, "--state")
        .map(PathBuf::from)
        .unwrap_or_else(|| admin_env.with_file_name("state.json"));
    let api = arg(&args, "--api")
        .or_else(|| std::env::var("B2_API_URL").ok())
        .unwrap_or_else(|| DEFAULT_API.into());
    let max_buckets: usize = arg(&args, "--max-buckets").and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_MAX_BUCKETS);
    let cmd = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with("--") && !is_value(&args, a))
        .cloned()
        .unwrap_or_default();
    let admin = || -> Result<B2> { B2::authorize(&api, &admin_creds(&admin_env)?) };
    match cmd.as_str() {
        "provision-tenant" => {
            let tenant = need(&args, "--tenant")?;
            need(&args, "--out")?;
            let b2 = admin()?;
            let (e, creds) = provision_tenant(&b2, &state, &tenant, max_buckets)?;
            emit_secret(&args, &creds)?;
            eprintln!("tenant {tenant}: bucket {} (private, lifecycle D2, object lock off), key {} {:?}", e.bucket_name, short(&creds.key_id), SCOPED_CAPS);
            eprintln!("proxy config:\n{}", store_snippet(&b2, &format!("t-{tenant}"), &e.bucket_name, &format!("/etc/s3vault/secrets/store-{tenant}.toml")));
            Ok(())
        }
        "rotate-key" => {
            let tenant = need(&args, "--tenant")?;
            need(&args, "--out")?;
            let creds = rotate_key(&admin()?, &state, &tenant)?;
            emit_secret(&args, &creds)?;
            eprintln!("tenant {tenant}: new key {}; install it on the proxy, restart, then revoke-old-keys", short(&creds.key_id));
            Ok(())
        }
        "revoke-old-keys" => {
            let tenant = need(&args, "--tenant")?;
            let n = revoke_old_keys(&admin()?, &state, &tenant)?;
            eprintln!("tenant {tenant}: {n} old key(s) deleted");
            Ok(())
        }
        "retire-tenant" => {
            let tenant = need(&args, "--tenant")?;
            confirm(&args, &tenant)?;
            let n = retire_tenant(&admin()?, &state, &tenant)?;
            eprintln!("tenant {tenant}: {n} key(s) deleted, bucket draining (empty after about 2 days); then deprovision-tenant");
            Ok(())
        }
        "deprovision-tenant" => {
            let tenant = need(&args, "--tenant")?;
            confirm(&args, &tenant)?;
            let purge = args.iter().any(|a| a == "--purge");
            let n = deprovision_tenant(&admin()?, &state, &tenant, purge)?;
            eprintln!("tenant {tenant}: bucket deleted ({n} file versions purged)");
            Ok(())
        }
        "list" => {
            let v = list(&admin()?, &state, max_buckets)?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            Ok(())
        }
        "check-key" => {
            let path = PathBuf::from(need(&args, "--key-env")?);
            let env = read_env_file(&path)?;
            let pick = |a: &str, b: &str| env.get(a).or_else(|| env.get(b)).map(|v| v.to_string());
            let creds = Creds {
                key_id: pick("B2_APPLICATION_KEY_ID", "access_key_id").context("no key id")?,
                key: zeroize::Zeroizing::new(pick("B2_APPLICATION_KEY", "secret_access_key").context("no key")?),
            };
            let b2 = B2::authorize(&api, &creds)?;
            println!("{}", serde_json::to_string_pretty(&describe_scope(&b2))?);
            Ok(())
        }
        _ => {
            eprintln!("usage: s3vault-provision provision-tenant|rotate-key|revoke-old-keys|retire-tenant|deprovision-tenant|list|check-key ... (see docs/PROVISIONING.md)");
            std::process::exit(2)
        }
    }
}

/// Whether `a` is the value of a `--flag value` pair (so it is not the command).
fn is_value(args: &[String], a: &String) -> bool {
    args.iter()
        .position(|x| std::ptr::eq(x, a))
        .is_some_and(|i| i > 0 && args[i - 1].starts_with("--") && !matches!(args[i - 1].as_str(), "--purge"))
}
