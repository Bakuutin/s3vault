# Provisioning: one Backblaze B2 bucket and one scoped key per tenant

Design and tool (`s3vault-provision`, crate `crates/s3vault-provision`). Placeholders as in the README:
`<proxy>` the proxy host, `<keyhost>` the key service host, `<admin>` the administrator's workstation.

## 1. Constraint

Backblaze (its admins, or anyone with access to the account's storage) must learn nothing about data or
metadata beyond what the owner accepted:

- Every object is encrypted on the proxy before it reaches B2 (object format v2, per-tenant secret, D1).
- Object names are `o/<tenant tag>/<52 base32>`: keyed hashes, no names, prefixes or bucket names.
- **Bucket names and application key names are random** (`[a-z][a-z0-9]{31}` and `[a-z][a-z0-9]{23}`):
  no tenant name, no user, no product name. No `bucketInfo`, no CORS, no tags. The mapping from
  tenant to bucket lives only in the provisioner's state file on the key host and in the proxy's config.
- Sizes stay exact: **no padding** (owner answer 6 of the design, `S3_ENCRYPTED_PROXY.md`), accepted.
- Deletion (D2): lifecycle "keep only the last version", 7 days from hide to delete, on every bucket.
- Object lock **off** (it would block erasure, D6); B2's default SSE-B2 stays on (harmless, irrelevant:
  the content is already ciphertext).

What B2 still learns: the number of tenant buckets and when each was created, per-bucket object count,
exact object sizes, total bytes, write and read timing, overwrites and deletes, and the source addresses
(the proxy for data, the key host for provisioning). See section 3 for the count and creation time.

## 2. Mapping: one B2 bucket per tenant

Each s3vault **tenant** gets its own B2 bucket, configured on the proxy as a store `t-<tenant>`; every
logical (client) bucket of the tenant points at that store. Several logical buckets of one tenant share it
(the logical bucket name is inside the keyed hash). The tenant's index snapshots go to the store of its
first bucket by name (`Config::tenant_store`), so to the same B2 bucket.

```toml
[stores.t-owner]                         # printed by s3vault-provision provision-tenant (no secrets)
endpoint = "https://s3.eu-central-003.backblazeb2.com"
region = "eu-central-003"
bucket = "<bucket-id>"
credentials_file = "/etc/s3vault/secrets/store-owner.toml"
prefix = "o/"

[[buckets]]
name = "app"
store = "t-owner"
tenant = "owner"
```

| | Per-tenant bucket (chosen) | One shared bucket, tenant prefixes `o/<tag>/` |
|---|---|---|
| Erasure (D6) | crypto-shred, then revoke the bucket key and delete the bucket: nothing of the tenant is left in B2 after the drain (about 2 days), no per-object deletes | crypto-shred, then a prefix purge (one delete per object, millions for a large tenant), then 7 days of hidden versions |
| Blast radius of a leaked store key | one tenant's ciphertext (still encrypted) | every tenant's ciphertext; deletes of everyone's data |
| Per-tenant backups (D1), export, cost attribution | B2 bucket = tenant: size, versions, egress per tenant from the B2 console; follower copy per bucket | needs the tag and listing work |
| Tenant count leak | bucket count | tag count (`o/<tag>/` is visible in every object name): **the same leak** |
| Creation time leak | bucket creation time | the first write under a new tag: **the same leak** |
| Account limit | 100 buckets per account by default (Backblaze docs: "limited to 100 buckets"; more on request to Backblaze sales) | none |
| Proxy restarts to add a tenant | one store and one credentials file per tenant (a restart, as for any tenant today; M1) | none for the store |

So per-tenant buckets add no metadata leak beyond the tag, which the per-tenant backups already
required, and they make erasure and key compromise strictly smaller.

**The 100-bucket limit.** Backblaze limits an account to 100 buckets. The tool
refuses to create a bucket when the account has `--max-buckets` (default 100) or more. Plan: per-tenant
buckets up to about 90; before that, ask Backblaze sales for a higher limit (cheap, no design change).
If refused: small tenants share one **overflow** bucket (a store `shared`, the tag separates them, erasure
is the existing crypto-shred plus prefix purge, without key revocation), large tenants keep their own; or a
second B2 account for the next 100.

## 3. Count and creation time

Both leak equally with a shared bucket (section 2). Mitigations, if the owner wants them (not built):

- A **spare pool**: create buckets in batches at fixed times (for example 5 spares, refilled weekly), and
  assign a spare when a tenant is created, so creation time says nothing about sign-ups and the count is
  rounded up. The scoped key would be created at assignment (key creation is visible to Backblaze too), or
  also pre-created and its secret kept on the key host until assigned.
- Deleting a bucket at erasure shows when a tenant left. A retired bucket could instead be kept empty and
  returned to the pool.

The billing identity of the account and the restic buckets in the same account (named after what they
back up) are outside s3vault's control; they identify the owner, not tenants.

## 4. Custody of the provisioning credential

Two kinds of B2 keys:

| Key | Capabilities | Where | Who uses it |
|---|---|---|---|
| **Provisioning key** (one, account-wide) | `listBuckets readBuckets writeBuckets deleteBuckets readBucketLifecycleRules writeBucketLifecycleRules listKeys writeKeys deleteKeys listFiles deleteFiles` (`ADMIN_CAPS`) | **key host only**: `/srv/s3vault-provision/b2-admin.env` (dir 700, file 600) | `s3vault-provision` on the key host |
| **Tenant key** (one per bucket, more during a rotation) | `listBuckets listFiles readFiles writeFiles deleteFiles` (`SCOPED_CAPS`), restricted to one bucket | proxy: `/etc/s3vault/secrets/store-<tenant>.toml` (root:s3vault 640) | the proxy's data path |

`writeKeys` cannot be scoped: a key that holds it can mint a key with every capability on every bucket, so
**the provisioning key is account-admin equivalent** even though it has no `readFiles`/`writeFiles`. It
never goes to the proxy. Choice of host:

- **Key host (chosen).** It already holds the keyrings (s3vault-keyd), so its compromise already exposes
  every tenant; the provisioning key adds account administration (deleting buckets), not readability. It
  is where tenants are created (`tenant-create`), so one host runs both steps. If that host already holds
  another account-wide B2 key (for example a backup tool's), the new key adds no new exposure there.
- The administrator's workstation (an admin CLI there) was the alternative: the laptop travels and sleeps, and it would
  need the B2 admin key on it as well. It keeps only the tenant keys' copy and the record of where the
  provisioning key is.
- The proxy: never (its RAM and disk are visible to the VPS provider).

Mint the provisioning key once from an existing account key, so that the existing key (for example a backup
tool's) is not used by s3vault again. Recommended follow-up: restrict that tool to its own buckets with a
fresh key that has no `writeKeys`, then delete the old all-capability key; and keep the account's master
application key offline.

## 5. Flow

One-time, the proxy's recipient key (RSA 3072, for sealing tenant keys in transit, the same way the
Cloudflare token was handed over):

```sh
ssh root@<proxy> 'umask 077; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out /etc/s3vault/secrets/provision-recipient.key
                  openssl pkey -in /etc/s3vault/secrets/provision-recipient.key -pubout' \
  | ssh <keyhost> 'cat > /srv/s3vault-provision/w-recipient.pub'
```

New tenant `T` (after `tenant-create` and its escrow confirmation in the key service, see the README):

```sh
P=/srv/s3vault-provision/bin/s3vault-provision
ssh <keyhost> "$P provision-tenant --tenant T --recipient /srv/s3vault-provision/w-recipient.pub --out -" \
  | ssh root@<proxy> 'umask 027; sed 1d | base64 -d | openssl pkeyutl -decrypt -inkey /etc/s3vault/secrets/provision-recipient.key \
        -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 \
        > /etc/s3vault/secrets/store-T.toml && chgrp s3vault /etc/s3vault/secrets/store-T.toml'
# stderr shows the bucket, the key id (last 4 characters) and the [stores.t-T] block
```

`provision-tenant` creates the random-name bucket (`allPrivate`, `fileLockEnabled: false`, lifecycle D2, no
bucket info; retries on a name collision; bucket names are global), then a key restricted to it with
`SCOPED_CAPS` and a random name; if the key cannot be created, the empty bucket is deleted again. It saves
the state (tenant, bucket name and id, key ids, dates) before it writes the key, which goes only to
`--out FILE` (mode 600, never overwritten) or to stdout when stdout is not a terminal; with `--recipient`
it is sealed (RSA-OAEP-SHA256 via `openssl pkeyutl`), so the operator's machine only relays ciphertext.
Then add `[stores.t-T]` and the tenant's `[[buckets]]` to the proxy's config and restart it (M1: a restart
per tenant change, until tenants are hot-reloaded).

**Listing:** `s3vault-provision list` checks the state against the account: per tenant the bucket, status,
key ids in the state and in B2 (last 4 characters), whether the bucket exists, is private, has the expected
lifecycle and no object lock; plus the account's bucket count, the limit and the number of buckets the tool
does not manage. `check-key --key-env FILE` authorizes any key (env or credentials TOML) and prints only
its bucket scope and capabilities.

**Rotation of a tenant key:** `rotate-key --tenant T --recipient ... --out -` (as above, into the same
credentials file), restart the proxy, check `/status`, then `revoke-old-keys --tenant T` (deletes every key
of the bucket except the newest). **Rotation of the provisioning key:** mint a new one with the same
capabilities using the current one (`b2_create_key`, as in the initial setup), replace `b2-admin.env`,
`list` to check, delete the old key.

## 6. Deprovisioning and erasure (D6)

The tenant erasure of `docs/erasure-runbook.md` stays the guarantee (crypto-shred minutes after step 3,
prefix purge in step 4). Per-tenant buckets add three steps after step 4:

| Step | Where | Command | Effect |
|---|---|---|---|
| 4a | proxy | remove `[stores.t-T]`, T's `[[buckets]]` and `store-T.toml`; restart | the proxy no longer holds a key for the bucket |
| 4b | key host | `s3vault-provision retire-tenant --tenant T --confirm T` | deletes **every** key restricted to the bucket (also any made outside the tool), sets the drain lifecycle (hide 1 day after upload, delete 1 day after hide): B2 empties the bucket itself, with no per-object calls |
| 9a | key host, after 2 days | `s3vault-provision deprovision-tenant --tenant T --confirm T [--purge]` | deletes the bucket; refuses while file versions remain (`--purge` deletes them one by one: fine for small buckets); the state keeps the entry as `deleted` with dates |

Record the retire and delete times from the state (`list`) in the proof record's pending steps. With this,
nothing of T is left in B2 about 3 days after the erasure (instead of D + 1 = 8 days), beyond whatever
Backblaze keeps internally after a delete (covered by the DPA, D5). A deleted tenant name may be
provisioned again later: it gets a new random bucket.

## 7. Tests

`cargo test -p s3vault-provision` runs the tool against an in-process fake of the B2 native API v4
(`tests/provision.rs`: authorize, buckets, keys, file versions, with capability checks, bucket scoping and
the bucket limit). MinIO and the in-process S3 servers of the other tests do not speak the B2 native API,
which is what manages buckets and keys; the S3 data path is already covered by `crates/s3vault/tests`.
Covered: random private bucket with D2 lifecycle and no object lock, scoped key with exactly
`SCOPED_CAPS` on one bucket and a random name, the scoped key cannot reach the other tenant or manage
anything, state file mode 600, duplicate and invalid tenants refused, bucket limit, missing `writeKeys`,
rotate and revoke, retire (including a stray key), deprovision with and without purge, re-provisioning a
deleted name, sealing and opening with `openssl`, uniform random names.

## 8. Example deployment

| What | Where |
|---|---|
| `s3vault-provision` binary | `<keyhost>`: `/srv/s3vault-provision/bin/s3vault-provision` (built in a `rust:slim-bookworm` container, glibc 2.34+) |
| Provisioning key (`ADMIN_CAPS`, not bucket-restricted, random name) | `<keyhost>`: `/srv/s3vault-provision/b2-admin.env` (service user, mode 600; directory 700) |
| State (tenant to bucket) | `<keyhost>`: `/srv/s3vault-provision/state.json` (600) |
| Tenant `owner` | one private bucket, one scoped key |
| Tenant `system` | one private bucket, one scoped key |
| Copy of the tenant keys, endpoint, region | `<admin>`: `~/.s3vault-admin/b2-s3vault.env` (600); records the provisioning key's location, not its value |

Verified: each scoped key authorizes with exactly its own bucket and `SCOPED_CAPS` (no `writeKeys`); S3 PUT,
GET (SHA-256 equal), LIST and DELETE (by version id, nothing left) in its own bucket; PUT, GET and LIST on the
other tenant's bucket answer 403. `list` shows the buckets private, lifecycle D2, object lock off.

Bringing a tenant onto its own bucket, in order:

1. Sign the storage provider's data processing agreement (`docs/gdpr/processor-agreements.md`).
2. Make the proxy's recipient key (section 5) and mint a second tenant key with `rotate-key --recipient`; open
   it straight into `store-<tenant>.toml` on `<proxy>`.
3. Point `[stores.t-<tenant>]` and the tenant's buckets at it.
4. Copy the tenant's objects from the old store as-is (`deploy/tools/s3sum.py --pull-to`, then `--push-from
   --skip-existing`; both retry transient 500/503 answers) and compare SHA-256 sums.
5. Restart the proxy, check `/status` and `POST /verify`.
6. Retire the old key with `revoke-old-keys`, which also removes the copy on the workstation.
7. Run the full fill from the fallback, if there is one.
