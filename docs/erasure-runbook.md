# Erasure runbook

Status: Covers decisions D1-D4 of the adversarial review: per-tenant crypto-shredding, the
erasure ledger, the replay after restores, escrow retention (30 days), store lifecycle (7 days) and the
retention cap for forever tiers. Placeholders as in the README: `<proxy>`, `<keyhost>`, the `sva` alias for
authenticated admin calls on the proxy, and `kd` for `cd /srv/s3vault-keyd && docker compose run --rm`
on the key host.

## 1. Erase a tenant X (a user or a space) and show the proof

Before: the application has put the space or user into its "deleting" state and offered an export
(`sva '127.0.0.1:9101/manifest?bucket=B'` for every bucket of X, plus the objects, plus the application's
own export).

| Step | Where | Command | What it does |
|---|---|---|---|
| 1. Freeze | proxy | `sva -X POST '127.0.0.1:9101/tenant/freeze?tenant=X&on=1'` | X's buckets answer 403 from now on (also the way to *restrict* processing, GDPR Art. 18) |
| 2. Counts | proxy | `sva 127.0.0.1:9101/status` | note X's buckets, live objects and bytes for the record |
| 3. Shred | key host | `kd admin tenant-erase --dir /keys --name X` | destroys `K_t`, appends the `tenant-erased` ledger entry (id, tag, K_t fingerprint), issues a new tenant escrow copy |
| 4. Proxy erasure | proxy | `sva -X POST '127.0.0.1:9101/tenant/erase?tenant=X&confirm=X' > proof-X.json` | refuses unless step 3 happened; writes the name manifest, drops the keys from RAM, deletes the index partition and staging files, deletes every object by manifest and everything left under the tenant's prefix, returns the **proof record** and appends it to the outbox |
| 5. Ledger | proxy -> key host | `ssh root@<proxy> 'sva 127.0.0.1:9101/ledger/outbox' \| ssh <keyhost> '... kd -T admin ledger-import --dir /keys'` | the proof joins the authoritative ledger |
| 6. Escrow | owner | copy the new escrow copy (`kd -T admin escrow-cat --dir /keys`), `s3vault tenant-escrow-check`, then `kd admin tenant-escrow-confirm --digest D --place P` | the owner holds a copy without `K_t`; older copies (with it) are deleted by `escrow-prune` within 30 days |
| 7. Follower | follower host | `s3vault ledger-replay --config C --dir <copy> --prefix o/ --ledger ledger.jsonl` | deletes the tenant's folder `o/<tag>/` in the follower copy (no key needed) |
| 8. Application data | application | the application's own erasure (see `per-tenant-backups.md` for an example) | per-space databases and their backups |
| 9. Verify after D + 1 days | proxy | `sva '127.0.0.1:9101/tenant/verify-erasure?id=<tenant id>'` | 0 objects under the tag in every store, no index partition, the proof records; on B2 also `b2 ls --versions b2://<bucket>/o/<tag>/` shows nothing |
| 10. Verify after 30 days | key host, owner | `kd admin escrow-prune --dir /keys`; `s3vault escrow-prune --dir ~/.s3vault/tenant-escrow` | the last escrow copies issued before the erasure are deleted |

**What is erased when.**

| Copy | How | Deadline |
|---|---|---|
| Everything encrypted under `K_t` (store objects, all B2 versions, the follower copy, index snapshots, staging files, any old backup of them) | cryptographically: `K_t` destroyed at the key service, dropped from the proxy's RAM | minutes (step 3 and 4) |
| Store objects (current) | deleted by manifest and prefix (step 4) | minutes |
| Store object versions (B2) | lifecycle "keep only the last version", 7 days from hide to delete | D + 1 day = 8 days |
| Follower copy | prefix purge by the ledger replay (step 7) | when step 7 runs |
| Tenant-keyring escrow copies holding `K_t` | `escrow-prune` (30 days) | 30 days |
| Proxy index partition, staging, RAM | step 4 | minutes |
| Application data | the application's procedure | per the application |

**The proof record** (step 4, kept in `erasures/<id>/proof.json` on the proxy and in the ledger):
tenant id and tag (opaque), `K_t` fingerprint, key-service erasure time and its ledger entry hash, proxy
erasure time, SHA-256 of the name manifest and its size, index row counts (live, tombstones, bytes),
whether the index partition and the staging files were removed, purge counts (deleted by manifest,
errors, deleted by prefix, remaining after), and the steps still pending (versions, follower, escrow,
ledger import). Together with the `verify-erasure` output of step 9 and the prune output of step 10, it is
the evidence for the data subject or a supervisory authority. It holds no personal data.

To show it:

```sh
ssh root@<proxy> cat /var/lib/s3vault/erasures/<tenant id>/proof.json
ssh root@<proxy> "sva '127.0.0.1:9101/tenant/verify-erasure?id=<tenant id>'"
ssh <keyhost> 'cd /srv/s3vault-keyd && docker compose run --rm admin ledger-show --dir /keys' | grep <tenant id>
```

`ledger-show` verifies the hash chain first: any edit of an earlier entry makes it fail.

## 2. Erase one object (a third party's recording)

```sh
sva -X POST '127.0.0.1:9101/object/erase?bucket=B&key=K&confirm=1'
```

The object is deleted (a tombstone in buckets with a fallback, so the fallback can never serve it again);
an `object-erased` outbox entry records the store, the store name, the SHA-256 of the object's head and its
generation. Import the outbox into the key service's ledger (step 5 above). B2 versions go with the
lifecycle (7 days); a restored copy of that exact version is deleted by any later replay, while a later
legitimate write of the same key is not (its head differs). The application deletes its own references
(transcripts, speaker embeddings) separately.

## 3. Replay after any restore

No restore may serve data before the ledger is replayed:

| Restore | Replay |
|---|---|
| store of record from a backup, or B2 versions re-promoted | `sva -X POST '127.0.0.1:9101/ledger/replay?dry_run=1'`, check, then without `dry_run` |
| the proxy's data directory or index (rebuild, snapshot) | `s3vault rebuild` replays before it rebuilds; a restored data directory: `POST /ledger/replay` before the first client request (the proxy also refuses every tenant the ledger lists as erased) |
| a follower copy | `s3vault ledger-replay --dir` (no key needed) |
| the key service from a backup | the proxy keeps its newer ledger copy and refuses erased tenants even if the restored tenant keyring still holds their keys; put the ledger back from the proxy (`sva 127.0.0.1:9101/ledger > ledger.jsonl` into `keys/`), then erase those tenants again with `tenant-erase` |
| application databases | the application's restore runbook replays the same ledger (`per-tenant-backups.md`) |

## 4. Retention cap for personal data in forever tiers (decision D4)

No tier keeps personal data without an end date:

- s3vault tiers: every tier it produces is encrypted under the tenant key (objects, versions, snapshots,
  staging; the follower copy is a copy of them), so a tenant erasure ends all of them at once. The ledger
  and the proof records are kept forever: they hold opaque ids only.
- Content backups of any kind (application databases, mirrors) end within a stated period: **at most 12
  months** for any tier holding identity data (accounts, memberships, access logs), and content backups
  are either per tenant under a key derived from `K_t` (shredded with the tenant) or short-lived (days).
- A yearly snapshot meant to be kept forever is re-written with the erased tenants removed (replay of the
  ledger) or deleted when it turns 12 months old.
- Plaintext copies outside s3vault (for example a plain fallback store or a plain mirror) are
  retired once the fill is verified; until then erasure is incomplete for them and the erasure record says
  so.

## 5. Drills

Run a tenant erasure drill on a throwaway tenant after every change to this procedure and at least
yearly: create tenant `drill-<date>` with a bucket, write a few objects, snapshot, copy the store to a
directory, erase (steps 1-7), restore the copy into the store, replay, and verify that nothing of the
tenant is readable or left.
