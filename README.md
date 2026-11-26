# s3vault: an encrypting S3 gateway

`s3vault` is a small S3 server. Clients (the application, backups, other apps) talk plain S3 to it with their own
access keys. It encrypts every object, **content and name**, before it leaves the host, and stores only
ciphertext in a *store of record* (any S3: Backblaze B2, Garage, MinIO). For a migration it can read through
from a *fallback* (an old plain store), serve the object and write it back encrypted, and copy everything in
the background. The keyring lives in RAM only; it comes from `s3vault-keyd` on another host.

Design and threat model: `docs/design/S3_ENCRYPTED_PROXY.md` (section 7 records what was built).

```
client --S3 (Tailscale/loopback)--> s3vault on w --TLS--> store of record (B2; today a local Garage)
                                       |  \--read-only--> fallback (d's Garage, plain), per bucket
                                       \--keyring at start-- s3vault-keyd on d (Tailscale, allow-list + PSK)
```

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
| `s3vault` (systemd `s3vault.service`) | `w` | `/usr/local/bin/s3vault`, `/etc/s3vault/config.toml`, `/etc/s3vault/secrets/*` (root:s3vault 640), `/var/lib/s3vault/` (index.db SQLCipher, spool, staging) |
| S3 listeners | `w` | `127.0.0.1:9100`, `100.64.0.2:9100` (Tailscale). Never the public IP. firewalld zone `tailnet` (tailscale0) allows only ssh and 9100/tcp |
| Admin API | `w` | `127.0.0.1:9101` (status, fill, verify, reconcile, snapshot, unlock) |
| Store-of-record stand-in: Garage (quadlet `s3vault-garage.service`) | `w` | `/etc/containers/systemd/s3vault-garage.container`, `/etc/s3vault-garage/garage.toml`, `/var/lib/s3vault-garage/`; S3 on `127.0.0.1:3910`, bucket `s3vault-store` |
| `s3vault-keyd` (container `s3vault-keyd`) | `d` | `/srv/s3vault-keys/` (compose, Dockerfile, `bin/`, `keys/` root 700 with `keyring` and `psk`, 600); listens `100.64.0.1:7373`, allows `100.64.0.2` only |
| Keyring backup | owner's Mac | `~/.s3vault-admin/vault-master.key` (600). Keep a second offline copy. **Lose every copy and the data is gone.** |

Hardening on `w`: swap off (fstab entry commented, `swap.target` masked), `kernel.core_pattern=|/bin/false`,
the unit has `LimitMEMLOCK=infinity`, `LimitCORE=0`, `MemorySwapMax=0`; the process calls `mlockall` and
`PR_SET_DUMPABLE=0`. The keyring is never written to `w`'s disk. `w`'s provider can still read RAM: accepted
by the owner (design section 1.3).

## Build

```sh
cd vault
cargo test --workspace                       # 19 tests; integration tests use in-process S3 servers
cargo build --release -p s3vault             # needs perl + make (vendored OpenSSL for SQLCipher)
cargo build --release -p s3vault-keyd --target x86_64-unknown-linux-musl   # static, for the scratch image
```

On the Mac use `CARGO_PROFILE_DEV_DEBUG=0` and check `df -h ~` first. Building on `w` takes about 4 minutes.

## Start

Key service on `d` (once):

```sh
cd /srv/s3vault-keys            # contains deploy/keyd/* and bin/s3vault-keyd
docker compose build
docker compose run --rm init          # creates keys/keyring and keys/psk (root, 600); prints the fingerprint only
docker compose up -d keyd
docker compose run --rm fingerprint   # non-secret fingerprint and key ids
```

Copy the PSK to the proxy and the keyring to the owner's Mac without printing them:

```sh
ssh d 'docker run --rm --network none -v /srv/s3vault-keys/keys:/k:ro alpine cat /k/psk' \
  | ssh root@w 'umask 027; cat > /etc/s3vault/secrets/keyd.psk; chgrp s3vault /etc/s3vault/secrets/keyd.psk'
(umask 077; ssh d 'docker run --rm --network none -v /srv/s3vault-keys/keys:/k:ro alpine cat /k/keyring' \
  > ~/.s3vault-admin/vault-master.key)
```

Proxy on `w`: install the binary, `deploy/proxy/config.example.toml` as `/etc/s3vault/config.toml`,
`deploy/proxy/s3vault.service` as `/etc/systemd/system/s3vault.service`, then:

```sh
runuser -u s3vault -- s3vault check --config /etc/s3vault/config.toml   # validates; fetches the keyring
systemctl enable --now s3vault
curl -s 127.0.0.1:9101/status
```

## Unlock

Automatic. At start the proxy is **locked** and answers every S3 request with 503; it asks the key service
every `keys.retry_secs` (10 s) until it gets the keyring, then opens the encrypted index and serves. Once
unlocked it stays unlocked while running, even if `d` goes away. A restart of `w` while `d` is down stays
locked (503) until `d` is back. `curl -X POST 127.0.0.1:9101/unlock` retries at once. `GET /status` shows
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
`http://w.<tailnet>.ts.net:9100` (or the Tailscale IP). Presigned URLs are not offered.

Example: the the application would be a client of bucket `media`. **It is not pointed at the proxy yet**; today
only the test client `admin-test` exists (read-write `scratch`, read-only `media`).

## Fill from the fallback

```sh
curl -X POST '127.0.0.1:9101/fill/start?bucket=media&max_objects=1000&rate=500000&concurrency=4'
curl -s 127.0.0.1:9101/fill                     # progress, cursor, errors, failed keys
curl -X POST '127.0.0.1:9101/fill/stop?bucket=media'
curl -X POST '127.0.0.1:9101/verify?bucket=media&max=1000&fallback=1'   # re-read and compare with the fallback
```

The fill walks the fallback listing in key order with a resumable cursor (in the index), skips keys already
in the store or tombstoned, copies create-only under a per-key lock, checks the body against the fallback's
MD5 ETag, and keeps the fallback's ETag and Last-Modified. `rate` is a byte budget; the fill pauses while a
live read-through fetch is running. `restart=1` resets the cursor for a second pass (cheap: present keys are
skipped from the index). **A full fill of `media` (8.7M objects, about 851 GB) needs the owner's go-ahead**:
it would saturate `d`'s uplink.

Consistency: while the old writer (e.g. the the application) still writes to the fallback directly, a filled copy
goes stale when the fallback later overwrites or deletes that key. Reconcile drops such copies (only rows that
came from the fallback; client writes and tombstones are never touched):

```sh
curl -X POST '127.0.0.1:9101/reconcile?bucket=media&dry_run=1'   # counts and examples only
curl -X POST '127.0.0.1:9101/reconcile?bucket=media'
```

Cutover of a client: stop its writes to the fallback, reconcile, run a last fill pass with `restart=1`, then
point the client at s3vault.

## Rotate

- **Content key**: `cd /srv/s3vault-keys && docker compose run --rm rotate` (adds a key and makes it
  active; old keys stay for reads), then copy the keyring to the Mac again and `systemctl restart s3vault` on
  `w`. New writes use the new key; nothing is re-encrypted. Re-encrypting old objects is only needed after a
  compromise (not built).
- **Name key**: never rotates in place (every object would be renamed). Not supported.
- **PSK**: stop keyd, replace `keys/psk` with a fresh `s3vault-psk v1 <base64 32 bytes>` (e.g. move the old
  files aside and run `init` in a scratch dir, keep only `psk`), start keyd, copy it to `w` as above. Running
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
or unknown to it. Without it, every header is read (one ranged GET of about 2 KiB per object; budget hours for
millions of objects). Fill cursors and unfinished multipart uploads are not in the store and start over.

Disaster recovery on a new host or the Mac: same command with `--keyring-file ~/.s3vault-admin/vault-master.key`
and a config pointing at the store.

## Switch the store of record to Backblaze B2

The owner, in the B2 web console or with the `b2` CLI:

1. Create a **private** bucket, e.g. `<name>-vault` (no B2 server-side encryption needed: the data is already
   encrypted; object lock optional). Lifecycle: "keep only the last version" with a few days before deletion
   is a good compromise (old ciphertext versions of overwritten and tombstoned keys cost storage; a short
   window helps against accidental deletes).
2. Create an **application key restricted to that bucket** with `listBuckets, listFiles, readFiles,
   writeFiles, deleteFiles` (`b2 key create --bucket <name>-vault s3vault-w listBuckets,listFiles,readFiles,writeFiles,deleteFiles`).
   Keep the account master key offline. Note the key id, the key, and the bucket's S3 endpoint
   (`https://s3.<region>.backblazeb2.com`, region e.g. `eu-central-003`).

Then on `w`:

```sh
umask 027; printf 'access_key_id = "%s"\nsecret_access_key = "%s"\n' "$KEY_ID" "$KEY" \
  > /etc/s3vault/secrets/store-b2.toml; chgrp s3vault /etc/s3vault/secrets/store-b2.toml
```

Copy the existing ciphertext as-is (no keyring needed: names and bytes do not depend on the store), e.g. with
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
a short window), copy again, `systemctl restart s3vault`, check `/status` and `POST /verify`. The index stays
valid (it does not depend on the store endpoint). Then the local Garage can be stopped
(`systemctl disable --now s3vault-garage`). Store-side multipart is used above 512 MiB of ciphertext; B2's
minimum part size (5 MB) is respected.

## Troubleshooting

- 503 everywhere: locked. `GET /status` -> `unlock_error`. Is keyd up on `d` (`docker logs s3vault-keyd`)? Is
  `w`'s address the one allowed?
- 503 for some keys: the fallback (or the store) is unreachable. Unfilled keys are never answered 404 while the
  fallback is down.
- 500 `integrity check failed`: a stored object failed authentication (tampered, swapped, rolled back, or the
  store returned another object). Logged as `integrity:`; never served.
- Logs: `journalctl -u s3vault`. Key material is never logged.
