# Per-tenant backups: design

Status: design. Decision (D1): every backup tier is kept **per tenant** and encrypted
under that tenant's key, so one tenant's backups can be restored, exported or erased alone, and destroying
the tenant secret shreds all of them at once. The s3vault part is built (format v2); the application part
(an application with one MongoDB database per space) is a design only.

## 1. Tiers produced by s3vault (built)

| Tier | Per tenant how | Encrypted under | Restore one tenant | Erase one tenant |
|---|---|---|---|---|
| Objects in the store of record | names `o/<tag>/...`; the tag is an opaque keyed hash of the tenant id | `K_obj = HKDF(KEK[kid] \|\| K_t, salt, ...)` | `s3vault rebuild --tenant X` lists only `o/<tag>/` | `K_t` destroyed; purge `o/<tag>/` |
| Store versions (B2) | same names | same | promote versions under `o/<tag>/` (B2 tooling), then rebuild X | `K_t` destroyed; lifecycle 7 days |
| Index | one SQLCipher file per tenant, `tenants/<id>.db` | `K_idx_t = HKDF(K_t, ...)` | rebuild X alone; move only its file | file deleted; unreadable without `K_t` |
| Index snapshots | one per tenant, an object of that tenant (`.s3vault` bucket under its name key and tag) | `K_obj` of the tenant | `rebuild --tenant X --snapshot` reads only X's snapshot | `K_t` destroyed; purged with the prefix |
| Journals | not built (planned per tenant, like snapshots) | | | |
| Follower copy (copy-only) | a copy of the store, so a folder per tenant | as the objects | copy `o/<tag>/` back, then rebuild X | `K_t` destroyed; delete the folder (`ledger-replay --dir`) |
| Multipart staging | `staging/<tenant id>/` | `K_stg_t = HKDF(K_t, ...)` | (transient) | deleted at erasure |
| Tenant keys | tenant keyring on the key service; escrow copies sealed under the master | master escrow key | the newest escrow copy | removed from the keyring; old escrow copies pruned after 30 days |

Export of one tenant: the manifest (`GET /manifest?bucket=B` for each of its buckets) plus the objects
through S3 with a read-only client of those buckets.

What the store learns from the per-tenant layout: which objects belong to the same tenant and, over time,
each tenant's object count, sizes and write cadence. That is the price of per-tenant restore and purge by
prefix; names, keys, contents and the tenant's identity stay hidden.

## 2. Application example: per-space MongoDB databases (design only)

Assumed setup: every space has its own Mongo database; Percona Backup for MongoDB (PBM) makes full PITR
bases plus oplog for the whole replica set, and per-space snapshots; a system database `app_sys` (users,
memberships, access log, storage secrets) has a yearly tier kept forever.

### 2.1 Tenant = space

- One s3vault tenant per space, created by the application's space provisioner together with the space's bucket
  (`tenant-create`, escrow confirmation, then the bucket). A user's personal space is a tenant like any
  other; `app_sys` is the system, not a tenant.
- The space document stores the tenant **name** and **id** (opaque), never `K_t`.

### 2.2 Per-space database backups, encrypted under the space's key

- A per-space logical backup (`mongodump --db <space db> --archive --gzip`, or a PBM selective backup of
  that database) is written **through s3vault** into a per-space backup bucket
  (`app-b-<space>`, tenant = the space's tenant). s3vault encrypts it under `K_t` like any object, so
  the archive is shredded with the space, its B2 versions included, with no extra key handling in the application.
- Alternative when PBM must write directly: encrypt each archive with a key derived from `K_t`
  (`HKDF(K_t, "app/backup" || space id)`) obtained from the proxy through an authenticated admin call
  that returns only that derived key; the archive goes to the store under the tenant's prefix. More moving
  parts; prefer the first option.
- Schedule per space (for example daily, 30 dailies plus 12 monthlies), so a space's retention can differ
  from the system's.
- **Restore of one space**: read its archives through s3vault (`mongorestore --nsInclude '<space db>.*'`),
  replay the ledger (section 2.4), then run the application's dangling-reference check against the space's bucket
  (`s3vault rebuild --tenant` first if the space's objects were restored too).

### 2.3 Shared tiers that cannot be per tenant

- **PBM full PITR bases and the oplog** cover every database of the replica set and cannot be shredded per
  space. Keep them local and short (about 2 days, as today) and never copy them off-box unless encrypted
  under a key with the same short life. A space erasure then ends in those tiers within 2 days, which the
  proof record states.
- **`app_sys`** holds identities. Its forever tier is replaced by a **12-month cap** (D4); a yearly
  snapshot that must be kept longer is re-written with the ledger's erased users removed, or an exemption
  (for example the household exemption) is decided explicitly and recorded.

### 2.4 The ledger in the application

- The application reads the s3vault erasure ledger (key service copy, or the proxy's `GET /ledger`) and keeps a
  copy in `app_sys` **and** next to the key service, so restoring `app_sys` cannot roll its own
  ledger back.
- The application adds its own entries through the same outbox mechanism: user ids (opaque) and per-chunk
  deletions inside the backup windows (`object-erased` entries come from s3vault already when the application
  deletes chunks through `/object/erase`; plain deletes are covered by the 7-day lifecycle).
- Every restore tool replays it before reopening: the PBM restore runbook (drop databases of erased spaces,
  delete rows of erased users from `app_sys`), `s3vault rebuild`, follower restores.

### 2.5 Erasure of a space, end to end

1. Application: space to `deleting`, export offered.
2. s3vault: freeze, `tenant-erase`, `POST /tenant/erase` (proof), outbox import, escrow copy confirmed.
3. Application: drop the space database; delete its per-space backups (already unreadable: they live under the
   tenant's key); record the ledger entry for the space id.
4. Within 2 days the shared PITR tier ages out; within 8 days B2 versions; within 30 days the last escrow
   copy of `K_t`. The verify step (runbook step 9) closes the record.

## 3. Open points

- Journals per tenant and an epoch counter off the proxy are not built.
- Tenants and buckets are configuration (restart to add a bucket); dynamic tenants through an admin API
  are not built.
- Per-tenant quotas and cost attribution are not built.
