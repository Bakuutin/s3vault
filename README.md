# s3vault: an encrypting S3 gateway

`s3vault` is a small S3 server. Clients (applications, backup tools) talk plain S3 to it with their own
access keys. It encrypts every object, **content and name**, before it leaves the host, and stores only
ciphertext in a *store of record* (any S3: Backblaze B2, Garage, MinIO). For a migration it can read through
from a *fallback* (an old plain store), serve the object and write it back encrypted, and copy everything in
the background. The keyring lives in RAM only; it comes from `s3vault-keyd` on another host.

Threat model in short: the store of record (a cloud provider) is not trusted with content or names; the
proxy host is trusted while running (its RAM holds the keys); the key service host is trusted to keep the
keys. Losing every copy of the master keyring loses the data.

Every bucket belongs to a **tenant** (a user or a space). Each tenant has its own random secret, mixed
into every key and name of its objects (object format v2): destroying that secret makes the tenant's data
unreadable everywhere a copy lives (store versions, follower copies, index snapshots, staging files)
without touching ciphertext. Erasures are recorded in a hash-chained **erasure ledger** that every restore
replays. See [Keys and tenants](#keys-and-tenants) and [docs/erasure-runbook.md](docs/erasure-runbook.md).

```
client --S3 (private net/loopback)--> s3vault (proxy host) --TLS--> store of record (e.g. B2, Garage, MinIO)
                                        |  \--read-only--> fallback (old plain store), per bucket
                                        \--keyring at start-- s3vault-keyd (key host; allow-list + PSK)
```

The commands below use placeholders: `<proxy>` is the proxy host (reached as `root@<proxy>`), `<keyhost>` the
key service host, `/srv/s3vault-keyd` the key service directory there, and `~/.s3vault/master.key` the
owner's offline keyring backup. A real deployment is described in [Example deployment](#example-deployment-media).

## What the store of record sees

One object per client object, named `o/<tenant tag>/<52 base32 chars>`: the tag (16 characters, an opaque
keyed hash of the tenant id) groups a tenant's objects, so one tenant's objects can be copied, restored,
exported or purged alone; the rest is a keyed hash of the bucket and key under the tenant's name key. Each
object (format v2) is a 64-byte preamble (magic `S3VAULT2`), a 32-byte tenant box (the tenant id, sealed
under a master subkey, so a rebuild with the root knows which tenant key opens the header), an encrypted
header (bucket, key, size, ETag, SHA-256, content type, metadata, generation, tombstone flag; padded to
1 KiB steps so key lengths do not show) and the body in 64 KiB XChaCha20-Poly1305 chunks.

The store learns object count, exact sizes (no padding, by owner decision), write and read timing,
overwrites, and which objects belong to the same tenant (the tag; the price of per-tenant backups). It
does not learn names, prefixes, bucket names, tenant names, content types or content. Tampering,
truncation, swapping (also between tenants) and rollback of an object fail authentication (500, never
wrong data).

The store plus the keyring alone rebuild everything (`s3vault rebuild`); the local index is a cache.

## Pieces and where they run

| What | Where | Files |
|---|---|---|
| `s3vault` (systemd `s3vault.service`) | proxy | `/usr/local/bin/s3vault`, `/etc/s3vault/config.toml`, `/etc/s3vault/secrets/*` (root:s3vault 640), `/var/lib/s3vault/`: `system.db` (SQLCipher, fingerprint and freeze flags), `tenants/<tenant id>.db` (one SQLCipher index per tenant, under its tenant key), `ledger.jsonl` (copy of the erasure ledger), `outbox.jsonl` (erasures recorded here, to import into the key service), `erasures/<id>/` (manifests, proofs), `spool/`, `staging/<tenant id>/` |
| S3 listeners | proxy | `127.0.0.1:9100` and a private (e.g. Tailscale) address, port 9100. Never a public IP; firewall the rest |
| Admin API | proxy | `127.0.0.1:9101` (status, fill, verify, reconcile, snapshot, unlock); loopback only, bearer token from `/etc/s3vault/secrets/admin.token` |
| Source and build tree | proxy | `/opt/s3vault/src` (clone of this repository) |
| `s3vault-keyd` (container `s3vault-keyd`) | key host | `/srv/s3vault-keyd/` (compose, Dockerfile, `bin/`, `keys/` root 700: `keyring` (master, v2), `tenants` (tenant keyring), `ledger.jsonl` (erasure ledger), `escrow/` (sealed tenant-keyring copies), `psk`; files 600); listens on its private address, port 7373, allows only the proxy's address |
| `s3vault-provision` | key host | `/srv/s3vault-provision/`: `bin/s3vault-provision`, `b2-admin.env` (the B2 provisioning key, account-admin equivalent; 600), `state.json` (tenant to B2 bucket; 600). Never on the proxy. See [docs/PROVISIONING.md](docs/PROVISIONING.md) |
| Master keyring backup | owner | `~/.s3vault/master.key` (600) plus a second offline copy in another place. Rarely changes (only on a root change). **Lose every copy and the data is gone.** |
| Tenant keyring escrow | owner | `~/.s3vault/tenant-escrow/tenants-<time>.sealed` (sealed under the master; a new copy after every tenant change; copies older than 30 days are pruned, the newest is kept) |

Hardening on the proxy: swap off, core dumps off (`kernel.core_pattern=|/bin/false`), the unit has
`LimitMEMLOCK=infinity`, `LimitCORE=0`, `MemorySwapMax=0`; the process calls `mlockall` and
`PR_SET_DUMPABLE=0`. The keyring is never written to the proxy's disk. Whoever can read the proxy's RAM (its
hosting provider) can read the keyring: an accepted risk of this design.

## Build

```sh
cargo test --workspace                       # integration tests use in-process S3 servers
cargo build --release -p s3vault             # needs perl + make (vendored OpenSSL for SQLCipher)
cargo build --release -p s3vault-keyd --target x86_64-unknown-linux-musl   # static, for the scratch image
cargo build --release -p s3vault-provision   # B2 provisioner for the key host (docs/PROVISIONING.md)
```

Needs Rust 1.85 or newer (edition 2024). A release build takes a few minutes; dev builds keep no debug info
(`[profile.dev] debug = 0`).

## Start

Key service on the key host (once):

```sh
cd /srv/s3vault-keyd                  # contains deploy/keyd/* and bin/s3vault-keyd
docker compose build
docker compose run --rm init          # creates keys/keyring (master v2) and keys/psk (root, 600); prints the fingerprint only
docker compose up -d keyd
docker compose run --rm fingerprint   # non-secret fingerprint, escrow state, tenants, ledger head
```

Then escrow the master keyring (the proxy refuses an unescrowed root) and create the tenants, as in
[Keys and tenants](#keys-and-tenants).

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

## Keys and tenants

**Master keyring (format v2).** One random root; everything else derives from it deterministically: the
key-encryption keys of every generation (`KEK[n] = HKDF(root, "s3vault/v2/kek" || n)`), the name root, the
tenant-box key, the tenant-tag key, the system-database key and the tenant-escrow key. Rotation
(`docker compose run --rm admin rotate --dir /keys`) only moves `active` to the next generation: no new
secret, so the offline copy of the root keeps covering every rotation (review H2). The root itself must
have a confirmed escrow copy before any proxy uses it:

```sh
(umask 077; ssh <keyhost> 'cd /srv/s3vault-keyd && docker compose run --rm -T escrow-export' > ~/.s3vault/master.key)
s3vault escrow-digest --file ~/.s3vault/master.key                     # computed where the copy is
ssh <keyhost> 'cd /srv/s3vault-keyd && docker compose run --rm admin escrow-confirm --dir /keys --digest <digest> --place owner-mac'
# second offline copy: copy the file to the second place, run escrow-digest there, confirm with --place <it>
```

**Tenants.** A tenant has a random id and a random 256-bit secret `K_t`, kept only in the key service's
tenant keyring (never in a database, never in a backup of the application, never in the store). Its object
keys, names, index key and staging key all mix in `K_t`. A tenant is created **pending** and is not
served until an escrow copy of the tenant keyring that holds it is confirmed, so a tenant key never exists
only on the key host:

```sh
ssh <keyhost> 'cd /srv/s3vault-keyd && docker compose run --rm admin tenant-create --dir /keys --name <tenant>'
mkdir -p ~/.s3vault/tenant-escrow
ssh <keyhost> 'cd /srv/s3vault-keyd && docker compose run --rm -T admin escrow-cat --dir /keys 2>/dev/null' \
  > ~/.s3vault/tenant-escrow/new.sealed
s3vault tenant-escrow-check --file ~/.s3vault/tenant-escrow/new.sealed --keyring ~/.s3vault/master.key
# prints "digest D issued T ..."; name the copy by its issue time (escrow-prune reads it from the name):
mv ~/.s3vault/tenant-escrow/new.sealed ~/.s3vault/tenant-escrow/tenants-T.sealed
ssh <keyhost> 'cd /srv/s3vault-keyd && docker compose run --rm admin tenant-escrow-confirm --dir /keys --digest <digest> --place owner-mac'
ssh root@<proxy> 'sva -X POST 127.0.0.1:9101/unlock'     # the running proxy picks up the active tenant
```

The escrow copy is sealed under a key derived from the master root, so the master copy plus the newest
tenant escrow copy restore every tenant.

**Escrow retention (R_tk = 30 days).** Every tenant change (create, erase) issues a new escrow copy. Copies
older than 30 days are deleted, except the newest, which never holds an erased tenant's key (an erasure
always issues a new copy). Run daily, on the key host and on the owner's device:

```sh
docker compose run --rm admin escrow-prune --dir /keys --max-age-days 30       # key host (cron or a systemd timer)
s3vault escrow-prune --dir ~/.s3vault/tenant-escrow --max-age-days 30          # owner's device (cron or launchd)
```

After an erasure, the owner copies and confirms the new escrow copy (as above); 30 days later the last
copy holding the erased tenant's key is gone, which is the crypto-erasure deadline for escrow.

**What the proxy receives.** Protocol v2 (`S3VKEY02`): the master keyring, the tenant keyring and the
erasure ledger. Protocol v1 clients (an older proxy binary, for a rollback) receive the legacy v1 keyring
kept inside the v2 master after `upgrade-v2`.

## Clients and buckets

Buckets are configuration, not API (`CreateBucket` is refused). Each `[[buckets]]` names a store, its
`tenant` and an optional fallback `{ source, bucket }`. Several client buckets can share one store bucket; the bucket name is
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

- **Key-encryption key, format v2**: `docker compose run --rm admin rotate --dir /keys` moves to the next
  generation (derived from the root; nothing to escrow), then `systemctl restart s3vault`. Old generations
  stay derivable, so old objects stay readable.
- **Tenant secret**: not rotated in place. After a suspected leak of one tenant's key: create a new tenant,
  copy its objects over (S3 copy between the two buckets), erase the old tenant (not automated).
- **Content key, legacy v1 keyring** (escrow first; review H2). A rotated key is **pending**: it is served but never used for
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
- **Name root and master root**: never rotate in place (every object would be renamed and re-keyed). Not
  supported.
- **PSK**: stop keyd, replace `keys/psk` with a fresh `s3vault-psk v1 <base64 32 bytes>` (e.g. move the old
  files aside and run `init` in a scratch dir, keep only `psk`), start keyd, copy it to the proxy as above. Running
  proxies are unaffected; the next start needs the new PSK.
- **Client secret**: generate a new one with `gen-client` (new id) or overwrite the secret file, restart.
- **Store credentials**: replace the credentials file, restart.

## Rebuild the index

Each tenant's index partition can always be rebuilt from the store and the keys (every object's header
names its bucket, key, generation and tombstone state, and only the tenant's prefix `o/<tag>/` is listed).
The rebuild first **replays the erasure ledger** on the stores (so a restored store never brings erased
data back), then rebuilds into a fresh data directory:

```sh
systemctl stop s3vault
runuser -u s3vault -- s3vault rebuild --config /etc/s3vault/config.toml \
    --out /var/lib/s3vault.rebuilt [--tenant NAME] [--snapshot] [--concurrency 32]
# whole directory: keep the outbox, swap the directories
cp -p /var/lib/s3vault/outbox.jsonl /var/lib/s3vault.rebuilt/ 2>/dev/null
mv /var/lib/s3vault /var/lib/s3vault.old && mv /var/lib/s3vault.rebuilt /var/lib/s3vault
# one tenant only (--tenant): move just its partition, tenants/<id>.db, into /var/lib/s3vault/tenants/
systemctl start s3vault
```

`--snapshot` starts from the tenant's latest encrypted index snapshot (one per tenant, sealed under the
tenant key and stored under its tag; written every `index_snapshot_secs` when the tenant's index changed,
or by `POST /snapshot`) and reads only headers of objects written since (store Last-Modified) or unknown to
it. The snapshot is streamed and applied in transactions, and the name sets of the rebuild live in a
scratch sqlite file next to the index (removed at the end), so RAM stays bounded at any index size
(`tests/scale.rs`; drill at production size, 8.7M rows, release build: a 3.96 GB snapshot written in 155 s,
the rebuild from it in 23 min at 31 MiB peak RSS, 108 MiB for the whole drill process). Without it, every header of the tenant is read (one ranged GET of about 2 KiB per
object; budget hours for millions of objects). Fill cursors and unfinished multipart uploads are not in the
store and start over. `--no-replay` skips the ledger replay.

Disaster recovery on a new host: same command with `--keyring-file ~/.s3vault/master.key`,
`--tenants-file <tenant keyring opened from the newest escrow copy>`, `--ledger-file <a ledger copy>`
and a config pointing at the store.

## Erasure and the erasure ledger

Erasing a tenant (a user or a space): the key service destroys `K_t` and records it in the ledger
(`tenant-erase`), then the proxy drops it, deletes the tenant's index partition and staging files, purges
the store by manifest and by prefix, and returns a proof record (`POST /tenant/erase`). Erasing one object
(a third party's recording): `POST /object/erase?bucket=B&key=K&confirm=1`. The step-by-step procedure,
the deadlines and how to show the proof are in [docs/erasure-runbook.md](docs/erasure-runbook.md).

The **erasure ledger** (`keys/ledger.jsonl` on the key host, authoritative; a copy in the proxy's data
directory and with the owner) is a hash-chained JSON-lines file of opaque ids only: erased tenants (id and
tag), erased object versions (store name and the hash of the object's head) and proof records. Proxy
entries go to its outbox and are imported on the key host:

```sh
ssh root@<proxy> 'sva 127.0.0.1:9101/ledger/outbox' \
  | ssh <keyhost> 'cd /srv/s3vault-keyd && docker compose run --rm -T admin ledger-import --dir /keys'
```

**Replay after every restore** (before the restored data is served):

| Restored | Command |
|---|---|
| the store of record (a backup, or B2 versions re-promoted) | `sva -X POST '127.0.0.1:9101/ledger/replay?dry_run=1'`, then without `dry_run` (or `s3vault ledger-replay --config ... --store NAME`) |
| a follower copy (a directory copied from the store) | `s3vault ledger-replay --config ... --dir /path/to/copy --prefix o/ --ledger ledger.jsonl` (needs no key) |
| the proxy's index (rebuild, snapshot) | `s3vault rebuild` replays first (above) |
| the key service from an old backup | nothing to do on the proxy: it keeps its ledger copy and refuses a tenant the ledger lists as erased; restore the ledger file from the proxy's copy (`GET /ledger`) |
| application databases (for example per-space Mongo backups) | the application's restore runbook reads the same ledger (see `docs/per-tenant-backups.md`) |

## Migrate from format v1

A v1 deployment (one keyring, flat names) moves to v2 in place, with no read from the fallback:

1. Key host: back up `keys/`, install the new binary, `docker compose run --rm admin upgrade-v2 --dir /keys`
   (new random root; the v1 keys stay inside as legacy keys, so a v1 proxy binary still unlocks), escrow
   the new master keyring (above), create the tenants and confirm their escrow copy.
2. Proxy: add `tenant = "..."` to every `[[buckets]]`, stop the service, then

   ```sh
   runuser -u s3vault -- s3vault migrate-v2 --config /etc/s3vault/config.toml --old-index /var/lib/s3vault/index.db
   ```

   Every v1 object is read with the legacy keys, checked against its recorded SHA-256 and written again as
   a v2 object of its bucket's tenant (ETag, metadata, Last-Modified, generation and fill origin kept).
   Fill cursors move along; unfinished multipart uploads do not. Start the service and run the pass
   checks. Then `mv index.db index.v1.db` and, once satisfied, run the same command with `--delete-v1`
   (idempotent: it re-encrypts nothing and deletes the v1 objects and the v1 snapshot).

Rollback before `--delete-v1`: the previous binary with the previous config and `index.db` still works
(the key service serves it the legacy keyring).

## Switch the store of record to Backblaze B2

Buckets and keys come from `s3vault-provision` on the key host: **one random-name private bucket per
tenant** (lifecycle D2, object lock off) and **one key restricted to it** (`listBuckets, listFiles,
readFiles, writeFiles, deleteFiles`, no `writeKeys`). The account-admin provisioning key stays on the key
host; the proxy only receives the scoped keys, sealed to its RSA key in transit. Design, flow, rotation,
erasure and the 100-bucket limit: [docs/PROVISIONING.md](docs/PROVISIONING.md). Before the first bucket:
choose an **EU region** at account sign-up (fixed per account) and sign Backblaze's DPA (see
`docs/gdpr/processor-agreements.md`). Never name a bucket after a tenant, a user or the product.

Then on the proxy, per tenant: the credentials file `/etc/s3vault/secrets/store-<tenant>.toml` (from
`provision-tenant` or `rotate-key`, see docs/PROVISIONING.md section 5), a store `[stores.t-<tenant>]`, and
the tenant's `[[buckets]]` pointed at it.

Copy each tenant's existing ciphertext as-is from the old store (here a local Garage on `127.0.0.1:3910`)
into its own bucket (no keyring needed: names and bytes do not depend on the store). A tenant's objects are
everything under `o/<tag>/`; the tag is in `sva 127.0.0.1:9101/status` (`tenants[].tag`). For example with
rclone configured through environment variables (fill the keys from the credentials files; do not echo
them):

```sh
export RCLONE_CONFIG_SRC_TYPE=s3 RCLONE_CONFIG_SRC_PROVIDER=Other RCLONE_CONFIG_SRC_ENDPOINT=http://127.0.0.1:3910 \
       RCLONE_CONFIG_SRC_REGION=garage RCLONE_CONFIG_SRC_ACCESS_KEY_ID=... RCLONE_CONFIG_SRC_SECRET_ACCESS_KEY=...
export RCLONE_CONFIG_B2_TYPE=s3 RCLONE_CONFIG_B2_PROVIDER=Other RCLONE_CONFIG_B2_ENDPOINT=https://s3.<region>.backblazeb2.com \
       RCLONE_CONFIG_B2_REGION=<region> RCLONE_CONFIG_B2_ACCESS_KEY_ID=... RCLONE_CONFIG_B2_SECRET_ACCESS_KEY=...
rclone copy src:s3vault-store/o/<tag> b2:<tenant bucket>/o/<tag> --checksum --transfers 32
```

Point the tenant's `[[buckets]]` at `t-<tenant>`. Stop writes (or accept a short window), copy again,
`systemctl restart s3vault`, check `/status` and `POST /verify` (with the admin token). The index stays
valid (it does not depend on the store endpoint). Tenants can move one at a time; the old store can be
stopped when none is left on it. Store-side multipart is used above one part (`store_multipart_part`, 64 MiB)
of ciphertext; B2's minimum part size (5 MB) is respected.

**Retries (review M4).** B2 answers 503 (and 500) under load and expects clients to retry. Every store and
fallback request is retried with exponential backoff and jitter (a random delay between half and all of
`retry_base_ms * 2^(n-1)`, capped at `retry_max_ms`, raised to `Retry-After`), at most `retry_attempts`
attempts per request (defaults 6, 250 ms, 10 s; settable per store). Idempotent requests (GET, HEAD, LIST,
DELETE, a whole-object PUT, upload part N, complete and abort) repeat on 408, 429, 500, 502, 503, 504,
timeouts and resets; create-multipart only on 408, 429, 503 and connect errors (when B2 certainly did not
process it). Every request body is buffered (objects up to one part in one PUT, larger ones in parts), so a
repeat sends the same bytes; a part is repeated under its part number. A complete that is repeated after a
lost answer and finds the upload gone checks the object (size and multipart ETag) instead of failing. An
error in the middle of a GET body is not retried (the client sees it). Retries are logged as
`store request failed, retrying` with the store label and operation, never the URL.

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
| `s3vault-keyd` | `d` | `/srv/s3vault-keys/` (`keys/`: master keyring v2, tenants, ledger, `escrow/`; `backups/keys-<date>.tar` taken before each key-service change; `bin/s3vault-keyd.prev`), listens `100.64.0.1:7373`, allows `100.64.0.2` only; daily `escrow-prune` from admin's crontab (03:23, log `escrow-prune.log`) |
| Master keyring backup | owner's Mac | `~/.s3vault-admin/vault-master.v2.key` (master v2, fingerprint `<fingerprint>`, escrowed as `owner-mac`; carries the legacy v1 keys). The v1 file `~/.s3vault-admin/vault-master.key` is now only needed for the v1 legacy keys, which the v2 file also holds. A second offline copy is an owner step |
| B2 provisioning | `d`, owner's Mac | `d`: `/srv/s3vault-provision/` (provisioning key, state, binary). B2 region `eu-central-003`: tenant `owner` bucket `<bucket-id>`, tenant `system` bucket `<bucket-id>`, one scoped key each; a copy of the scoped keys in `~/.s3vault-admin/b2-s3vault.env` on the Mac. Not used by the proxy yet (ST1) |
| Tenant keyring escrow | owner's Mac | `~/.s3vault-admin/tenant-escrow/tenants-<issued>.sealed` (prune with `s3vault escrow-prune --dir ~/.s3vault-admin/tenant-escrow --max-age-days 30`; scheduling it on the Mac is an owner step) |

Tenants: `owner` (bucket `media`, fallback `d-garage`/`media`), `scratch` (bucket `scratch`); `drill` was
created and erased on 2026-11-26 as the live erasure drill (ledger entries 1-2). Clients: only the test
client `admin-test` (read-write `scratch` and `drill`, read-only `media`); the the application is not pointed
at the proxy yet. The ~1,000 trial objects were migrated to format v2 (`migrate-v2`, then `--delete-v1`);
the v1 index is kept as `/var/lib/s3vault/index.v1.db`. Hardening on `w`: swap off (fstab entry
commented, `swap.target` masked), `kernel.core_pattern=|/bin/false`.
