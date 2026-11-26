# s3vault: an encrypting S3 gateway

`s3vault` is a small S3 server. Clients (applications, backup tools) talk plain S3 to it with their own
access keys. It encrypts every object, **content and name**, before it leaves the host, and stores only
ciphertext in a *store of record* (any S3: Backblaze B2, Garage, MinIO). For a migration it can read through
from a *fallback* (an old plain store), serve the object and write it back encrypted, and copy everything in
the background. The keyring lives in RAM only; it comes from `s3vault-keyd` on another host.

Threat model in short: the store of record (a cloud provider) is not trusted with content or names; the
proxy host is trusted while running (its RAM holds the keyring); the key service host is trusted to keep the
keyring. Losing every copy of the keyring loses the data.

```
client --S3 (private net/loopback)--> s3vault (proxy host) --TLS--> store of record (e.g. B2, Garage, MinIO)
                                        |  \--read-only--> fallback (old plain store), per bucket
                                        \--keyring at start-- s3vault-keyd (key host; allow-list + PSK)
```

The commands below use placeholders: `<proxy>` is the proxy host (reached as `root@<proxy>`), `<keyhost>` the
key service host, `/srv/s3vault-keyd` the key service directory there, and `~/.s3vault/master.key` the
owner's offline keyring backup. A real deployment is described in [Example deployment](#example-deployment-media).

## What the store of record sees

One object per client object, under a flat keyed-hash name `o/<52 base32 chars>`. Each object is a 64-byte
preamble, an encrypted header (bucket, key, size, ETag, SHA-256, content type, metadata, generation,
tombstone flag; padded to 1 KiB steps so key lengths do not show) and the body in 64 KiB XChaCha20-Poly1305
chunks. It learns object count, exact sizes (no padding, by owner decision), write and read timing, and
overwrites. It does not learn names, prefixes, bucket names, content types or content. Tampering, truncation,
swapping and rollback of an object fail authentication (500, never wrong data).

The store plus the keyring alone rebuild everything (`s3vault rebuild`); the local index is a cache.

## Pieces and where they run

| What | Where | Files |
|---|---|---|
| `s3vault` (systemd `s3vault.service`) | proxy | `/usr/local/bin/s3vault`, `/etc/s3vault/config.toml`, `/etc/s3vault/secrets/*` (root:s3vault 640), `/var/lib/s3vault/` (index.db SQLCipher, spool, staging) |
| S3 listeners | proxy | `127.0.0.1:9100` and a private (e.g. Tailscale) address, port 9100. Never a public IP; firewall the rest |
| Admin API | proxy | `127.0.0.1:9101` (status, fill, verify, reconcile, snapshot, unlock); loopback only, bearer token from `/etc/s3vault/secrets/admin.token` |
| Source and build tree | proxy | `/opt/s3vault/src` (clone of this repository) |
| `s3vault-keyd` (container `s3vault-keyd`) | key host | `/srv/s3vault-keyd/` (compose, Dockerfile, `bin/`, `keys/` root 700 with `keyring` and `psk`, 600); listens on its private address, port 7373, allows only the proxy's address |
| Keyring backup | owner | `~/.s3vault/master.key` (600). Keep a second offline copy. **Lose every copy and the data is gone.** |

Hardening on the proxy: swap off, core dumps off (`kernel.core_pattern=|/bin/false`), the unit has
`LimitMEMLOCK=infinity`, `LimitCORE=0`, `MemorySwapMax=0`; the process calls `mlockall` and
`PR_SET_DUMPABLE=0`. The keyring is never written to the proxy's disk. Whoever can read the proxy's RAM (its
hosting provider) can read the keyring: an accepted risk of this design.

## Build

```sh
cargo test --workspace                       # integration tests use in-process S3 servers
cargo build --release -p s3vault             # needs perl + make (vendored OpenSSL for SQLCipher)
cargo build --release -p s3vault-keyd --target x86_64-unknown-linux-musl   # static, for the scratch image
```

Needs Rust 1.85 or newer (edition 2024). A release build takes a few minutes; dev builds keep no debug info
(`[profile.dev] debug = 0`).

## Start

Key service on the key host (once):

```sh
cd /srv/s3vault-keyd                  # contains deploy/keyd/* and bin/s3vault-keyd
docker compose build
docker compose run --rm init          # creates keys/keyring and keys/psk (root, 600); prints the fingerprint only
docker compose up -d keyd
docker compose run --rm fingerprint   # non-secret fingerprint and key ids
```

Copy the PSK to the proxy and the keyring to the owner's Mac without printing them:

```sh
ssh <keyhost> 'docker run --rm --network none -v /srv/s3vault-keyd/keys:/k:ro alpine cat /k/psk' \
  | ssh root@<proxy> 'umask 027; cat > /etc/s3vault/secrets/keyd.psk; chgrp s3vault /etc/s3vault/secrets/keyd.psk'
(umask 077; mkdir -p ~/.s3vault; ssh <keyhost> 'docker run --rm --network none -v /srv/s3vault-keyd/keys:/k:ro alpine cat /k/keyring' \
  > ~/.s3vault/master.key)
```

Proxy: create a system user `s3vault`, `/etc/s3vault/secrets` (root:s3vault 750) and `/var/lib/s3vault`
(owned by `s3vault`), build and install the binary (see [Update](#update-a-deployment) for the clone and
build steps), `deploy/proxy/config.example.toml` as `/etc/s3vault/config.toml`,
`deploy/proxy/s3vault.service` as `/etc/systemd/system/s3vault.service`, then:

```sh
s3vault gen-admin-token --out /etc/s3vault/secrets/admin.token          # never printed
chgrp s3vault /etc/s3vault/secrets/admin.token; chmod 640 /etc/s3vault/secrets/admin.token
runuser -u s3vault -- s3vault check --config /etc/s3vault/config.toml   # validates; fetches the keyring
systemctl enable --now s3vault
alias sva='curl -s -H "Authorization: Bearer $(cat /etc/s3vault/secrets/admin.token)"'
sva 127.0.0.1:9101/status
```

The admin API answers 401 without `Authorization: Bearer <token>`; `admin_listen` must be a loopback
address and `admin_token_file` is required with it. The examples below use the `sva` alias.

## Unlock

Automatic. At start the proxy is **locked** and answers every S3 request with 503; it asks the key service
every `keys.retry_secs` (10 s) until it gets the keyring, then opens the encrypted index and serves. Once
unlocked it stays unlocked while running, even if the key service goes away. A restart of the proxy while the key service is down stays
locked (503) until the key service is back. `sva -X POST 127.0.0.1:9101/unlock` retries at once. `GET /status` shows
`locked` and `unlock_error`.

The index is encrypted with a key derived from the keyring, and it records the keyring fingerprint: a
different keyring refuses to open it.

## Clients and buckets

Buckets are configuration, not API (`CreateBucket` is refused). Each `[[buckets]]` names a store and an
optional fallback `{ source, bucket }`. Several client buckets can share one store bucket; the bucket name is
inside the keyed hash, so the store cannot tell them apart.

```sh
s3vault gen-client --secret-out /etc/s3vault/secrets/client-NAME.secret   # prints access_key_id
chgrp s3vault /etc/s3vault/secrets/client-NAME.secret; chmod 640 /etc/s3vault/secrets/client-NAME.secret
```

Add a `[[clients]]` block with `buckets` (read-write) and/or `read_buckets` (read-only), then
`systemctl restart s3vault`. Clients use path-style addressing, region `us-east-1`, endpoint
`http://<proxy>:9100` (its private name or address). Presigned URLs are not offered.

## Fill from the fallback

```sh
sva -X POST '127.0.0.1:9101/fill/start?bucket=app&max_objects=1000&rate=500000&concurrency=4'
sva 127.0.0.1:9101/fill                     # progress, cursor, errors, failed keys
sva -X POST '127.0.0.1:9101/fill/stop?bucket=app'
sva -X POST '127.0.0.1:9101/verify?bucket=app&max=1000&fallback=1'   # re-read and compare with the fallback
```

`concurrency` is clamped to 1..32.

The fill walks the fallback listing in key order with a resumable cursor (in the index), skips keys already
in the store or tombstoned, copies create-only under a per-key lock, checks the body against the fallback's
MD5 ETag, and keeps the fallback's ETag and Last-Modified. `rate` is a byte budget; the fill pauses while a
live read-through fetch is running. `restart=1` resets the cursor for a second pass (cheap: present keys are
skipped from the index). Size a full fill against the fallback host's uplink: it can saturate it.

Consistency: while the old writer (the application before cutover) still writes to the fallback directly, a filled copy
goes stale when the fallback later overwrites or deletes that key. Reconcile drops such copies (only rows that
came from the fallback; client writes and tombstones are never touched):

```sh
sva -X POST '127.0.0.1:9101/reconcile?bucket=app&dry_run=1'          # "stale": N, examples
sva -X POST '127.0.0.1:9101/reconcile?bucket=app&expect=N'           # removes; N from the dry run
```

Guards (a reconcile against an empty or unreachable fallback would otherwise drop every filled copy):

- refused when the fallback's listing is empty (retired, re-created, wrong bucket), or when the bucket's
  fallback is marked `retired = true` in the config (the fill refuses it too);
- a key counts as deleted only when a direct HEAD answers 404; any other error aborts the run;
- a real run needs `expect` equal to the dry run's `stale` (so a dry run always comes first), and is refused
  when it would remove more than `fill.reconcile_max_fraction` (default 0.01) of the checked filled rows,
  unless `force=1` is added after checking the fallback.

Cutover of a client: stop its writes to the fallback, reconcile, run a last fill pass with `restart=1`, then
point the client at s3vault.

## Rotate

- **Content key** (escrow first; review H2). A rotated key is **pending**: it is served but never used for
  writes until an offline copy holding it is confirmed, so a key can never exist only on the key host.

  ```sh
  ssh <keyhost> 'cd /srv/s3vault-keyd && docker compose run --rm rotate'          # prints the expected digest
  (umask 077; ssh <keyhost> 'cd /srv/s3vault-keyd && docker compose run --rm -T escrow-export' \
     > ~/.s3vault/master.key.new)                                                 # never on a terminal
  s3vault-keyd escrow-digest --file ~/.s3vault/master.key.new                     # where the copy is
  mv ~/.s3vault/master.key.new ~/.s3vault/master.key                              # and the second offline copy
  ssh <keyhost> 'cd /srv/s3vault-keyd && docker compose run --rm escrow-confirm --digest <digest> --place <where>'
  ssh root@<proxy> systemctl restart s3vault
  ```

  `escrow-confirm` compares the digest computed from the copy with the keyring and only then makes the key
  active. The proxy enforces the same rule: it writes under the highest **escrowed** key (`/status`:
  `write_kid`, `active_kid_escrowed`, `escrow_places`), so a hand-edited or old-binary rotation cannot
  create data under an unescrowed key. Nothing is re-encrypted. Keep two offline copies in different places.
- **Name key**: never rotates in place (every object would be renamed). Not supported.
- **PSK**: stop keyd, replace `keys/psk` with a fresh `s3vault-psk v1 <base64 32 bytes>` (e.g. move the old
  files aside and run `init` in a scratch dir, keep only `psk`), start keyd, copy it to the proxy as above. Running
  proxies are unaffected; the next start needs the new PSK.
- **Client secret**: generate a new one with `gen-client` (new id) or overwrite the secret file, restart.
- **Store credentials**: replace the credentials file, restart.

## Rebuild the index

The index can always be rebuilt from the store and the keyring (every object's header names its bucket, key,
generation and tombstone state). Stop the service first, rebuild into a new file, then move it into place:

```sh
systemctl stop s3vault
runuser -u s3vault -- s3vault rebuild --config /etc/s3vault/config.toml \
    --index /var/lib/s3vault/index.rebuilt.db [--snapshot] [--concurrency 32]
mv /var/lib/s3vault/index.db /var/lib/s3vault/index.db.old; rm -f /var/lib/s3vault/index.db-wal /var/lib/s3vault/index.db-shm
mv /var/lib/s3vault/index.rebuilt.db /var/lib/s3vault/index.db
systemctl start s3vault
```

`--snapshot` starts from the latest encrypted index snapshot (written every `index_snapshot_secs` when the
index changed, or by `POST /snapshot`) and reads only headers of objects written since (store Last-Modified)
or unknown to it. The snapshot is streamed and applied in transactions, and the name sets of the rebuild
live in a scratch sqlite file next to the index (removed at the end), so RAM stays bounded at any index
size (see `tests/scale.rs`; the production-size drill is described there). Without it, every header is read (one ranged GET of about 2 KiB per object; budget hours for
millions of objects). Fill cursors and unfinished multipart uploads are not in the store and start over.

Disaster recovery on a new host: same command with `--keyring-file ~/.s3vault/master.key`
and a config pointing at the store.

## Switch the store of record to Backblaze B2

The owner, in the B2 web console or with the `b2` CLI:

1. Create a **private** bucket, e.g. `<name>-vault` (no B2 server-side encryption needed: the data is already
   encrypted; object lock optional). Lifecycle: "keep only the last version" with a few days before deletion
   is a good compromise (old ciphertext versions of overwritten and tombstoned keys cost storage; a short
   window helps against accidental deletes).
2. Create an **application key restricted to that bucket** with `listBuckets, listFiles, readFiles,
   writeFiles, deleteFiles` (`b2 key create --bucket <name>-vault s3vault listBuckets,listFiles,readFiles,writeFiles,deleteFiles`).
   Keep the account master key offline. Note the key id, the key, and the bucket's S3 endpoint
   (`https://s3.<region>.backblazeb2.com`, region e.g. `eu-central-003`).

Then on the proxy:

```sh
umask 027; printf 'access_key_id = "%s"\nsecret_access_key = "%s"\n' "$KEY_ID" "$KEY" \
  > /etc/s3vault/secrets/store-b2.toml; chgrp s3vault /etc/s3vault/secrets/store-b2.toml
```

Copy the existing ciphertext as-is from the old store (here a local Garage on `127.0.0.1:3910`) (no keyring needed: names and bytes do not depend on the store), e.g. with
rclone configured through environment variables (fill the keys from the two credentials files; do not echo
them):

```sh
export RCLONE_CONFIG_SRC_TYPE=s3 RCLONE_CONFIG_SRC_PROVIDER=Other RCLONE_CONFIG_SRC_ENDPOINT=http://127.0.0.1:3910 \
       RCLONE_CONFIG_SRC_REGION=garage RCLONE_CONFIG_SRC_ACCESS_KEY_ID=... RCLONE_CONFIG_SRC_SECRET_ACCESS_KEY=...
export RCLONE_CONFIG_B2_TYPE=s3 RCLONE_CONFIG_B2_PROVIDER=Other RCLONE_CONFIG_B2_ENDPOINT=https://s3.<region>.backblazeb2.com \
       RCLONE_CONFIG_B2_REGION=<region> RCLONE_CONFIG_B2_ACCESS_KEY_ID=... RCLONE_CONFIG_B2_SECRET_ACCESS_KEY=...
rclone copy src:s3vault-store/o b2:<name>-vault/o --checksum --transfers 32
```

Edit `[stores.primary]`: `endpoint = "https://s3.<region>.backblazeb2.com"`, `region = "<region>"`,
`bucket = "<name>-vault"`, `credentials_file = "/etc/s3vault/secrets/store-b2.toml"`. Stop writes (or accept
a short window), copy again, `systemctl restart s3vault`, check `/status` and `POST /verify` (with the admin token). The index stays
valid (it does not depend on the store endpoint). Then the old store can be stopped. Store-side multipart is used above 512 MiB of ciphertext; B2's
minimum part size (5 MB) is respected.

## Update a deployment

The proxy builds from a clone of this repository in `/opt/s3vault/src`, using a read-only deploy key
(`/root/.ssh/s3vault_deploy`, registered on the repository as a read-only deploy key) through an SSH alias in
`/root/.ssh/config`:

```
Host gitea-s3vault
    HostName git.example.com
    User git
    IdentityFile /root/.ssh/s3vault_deploy
    IdentitiesOnly yes
```

First time: `git clone gitea-s3vault:<owner>/s3vault.git /opt/s3vault/src`. Each update, as root on the proxy:

```sh
cd /opt/s3vault/src
git pull --ff-only
cargo test --workspace                                   # optional; a few minutes
cargo build --release -p s3vault
cp -p /usr/local/bin/s3vault /usr/local/bin/s3vault.prev  # keep the running binary for rollback
install -m 755 target/release/s3vault /usr/local/bin/s3vault.new && mv /usr/local/bin/s3vault.new /usr/local/bin/s3vault
systemctl restart s3vault
```

Verify (the service is locked, 503, for a moment until the keyring arrives):

```sh
systemctl is-active s3vault
journalctl -u s3vault -n 20 --no-pager
sva 127.0.0.1:9101/status            # "locked": false, "unlock_error": null, the same "keyring_fingerprint" as before
ss -ltnp | grep ':910[01]'           # 9100 only on loopback and the private address; 9101 only on loopback
```

Then read back one known object through S3 with a client key and compare its SHA-256 with a value taken before
the update. Config, secrets and `/var/lib/s3vault` are not touched by an update.

Rollback: `mv /usr/local/bin/s3vault.prev /usr/local/bin/s3vault && systemctl restart s3vault`, then verify as
above. A unit file change (`deploy/proxy/s3vault.service`) is installed separately:
`install -m 644 deploy/proxy/s3vault.service /etc/systemd/system/ && systemctl daemon-reload`.

## Troubleshooting

- 503 everywhere: locked. `GET /status` -> `unlock_error`. Is keyd up on the key host (`docker logs s3vault-keyd`)?
  Is the proxy's address the one allowed?
- 503 for some keys: the fallback (or the store) is unreachable. Unfilled keys are never answered 404 while the
  fallback is down.
- 500 `integrity check failed`: a stored object failed authentication (tampered, swapped, rolled back, or the
  store returned another object). Logged as `integrity:`; never served.
- Logs: `journalctl -u s3vault`. Key material is never logged.

## Example deployment (the application)

The first deployment protects the audio store of the application (a personal audio and transcription platform).

| What | Host | Details |
|---|---|---|
| `s3vault.service` | `w` | `/usr/local/bin/s3vault` (previous binary `/usr/local/bin/s3vault.prev`), `/etc/s3vault/config.toml`, `/etc/s3vault/secrets/`, `/var/lib/s3vault/`, source `/opt/s3vault/src` |
| S3 listeners | `w` | `127.0.0.1:9100`, `100.64.0.2:9100` (Tailscale); firewalld zone `tailnet` (tailscale0) allows only ssh and 9100/tcp |
| Store of record (stand-in until B2) | `w` | Garage, Podman quadlet `s3vault-garage.service` (`/etc/containers/systemd/s3vault-garage.container`, `/etc/s3vault-garage/garage.toml`, `/var/lib/s3vault-garage/`), S3 on `127.0.0.1:3910`, bucket `s3vault-store` |
| Fallback `d-garage` | `d` | the application's plain Garage, `100.64.0.1:3900`, bucket `media` (about 8.7M objects, 851 GB; a full fill needs the owner's go-ahead) |
| `s3vault-keyd` | `d` | `/srv/s3vault-keys/`, listens `100.64.0.1:7373`, allows `100.64.0.2` only |
| Keyring backup | owner's Mac | `~/.s3vault-admin/vault-master.key` |

Buckets: `media` (fallback `d-garage`/`media`) and `scratch`. Clients: only the test client `admin-test`
(read-write `scratch`, read-only `media`); the the application is not pointed at the proxy yet. Hardening on
`w`: swap off (fstab entry commented, `swap.target` masked), `kernel.core_pattern=|/bin/false`.
