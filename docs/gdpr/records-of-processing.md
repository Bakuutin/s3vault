# Records of processing activities (GDPR Art. 30): template

Status: draft template, 2026-11-26. Not legal advice; the controller fills it in and has it reviewed.
Generic for any deployment of s3vault; the example column uses the application (a personal audio and
transcription platform that hosts several users and records third parties), for which the owner decided
that the GDPR applies.

Keep one record per processing activity. Update it when a purpose, a category of data, a recipient, a
storage location or a retention period changes, and keep the old versions.

## 1. Controller

| Field | To fill | Example (the application) |
|---|---|---|
| Controller (name, address, contact) | | The owner of the deployment, as a natural person or a business |
| Representative in the EU (Art. 27, if established outside the EU) | | not needed if the owner is in the EU |
| Data protection officer (Art. 37, if required) | | usually not required for a small deployment; record the reasoning |
| Joint controllers (Art. 26) | | a space owner who invites others may be a joint controller for that space: decide and record |

## 2. One record per activity

Copy this table per activity.

| Field | To fill | Example: "audio recording, storage and transcription" |
|---|---|---|
| Activity name and id | | ROP-1 audio pipeline |
| Purposes (Art. 5(1)(b)) | | personal memory aid; search over one's own conversations; transcripts and summaries |
| Legal basis per purpose (Art. 6) | | consent of each tenant (contract for hosted users); for recorded third parties: legitimate interests, with the balancing test documented in the DPIA, or consent where obtainable |
| Special categories (Art. 9) and their condition | | voice used for speaker identification may be biometric data used to identify a person (Art. 9(1)); condition: explicit consent (Art. 9(2)(a)), otherwise do not run speaker identification for that person |
| Categories of data subjects | | tenants (account holders); members of shared spaces; **third parties recorded without an account** (visitors, callers, bystanders) |
| Categories of personal data | | raw audio; transcripts; speaker labels and voice embeddings; timestamps and locations (geo); device ids; account data (email, name); access logs |
| Recipients (Art. 30(1)(d)) | | processors listed in `processor-agreements.md` (hosting provider of the proxy host, object store provider); no other recipients |
| Transfers to third countries (Art. 44 ff.) and safeguards | | object store provider: EU region chosen, ciphertext only, keys held outside the provider (EDPB supplementary measure); provider group in the US: SCCs or DPF certification, check |
| Retention per category (Art. 5(1)(e)) | | see section 3 |
| Technical and organisational measures (Art. 32), summary | | see section 4 |
| Data sources (if not collected from the data subject) | | recording devices of the tenant |
| Automated decision-making (Art. 22) | | none with legal or similar effect; speaker identification and summaries are assistive |

## 3. Retention (fill per category and per storage tier)

| Category | Live system | Backups (local) | Backups (off-site) | Forever tiers |
|---|---|---|---|---|
| Raw audio | until the tenant deletes it, or N months (decide) | object versions: D = 7 days after delete (store lifecycle) | follower copy: crypto-shredded at tenant erasure; physical purge by manifest | none allowed for content (see the cap below) |
| Transcripts, summaries | with the audio | per-space database backups: deleted with the space | encrypted under the tenant key | none |
| Voice embeddings, speaker labels | with the speaker profile; deleted when the person objects or withdraws consent | as transcripts | as transcripts | none |
| Account and membership rows | while the account exists | system database backups | | **cap: 12 months** for any tier that holds identity rows, plus redaction by the erasure ledger at restore |
| Erasure ledger and proof records | forever (opaque ids only, no personal data) | with the key service | with the owner | allowed: holds no personal data |
| Tenant-key escrow copies | n/a | at most 30 days (R_tk) | at most 30 days | none |

**Retention cap for personal data in forever tiers (decision D4).** No backup tier may keep personal data
without an end date. A tier meant to be kept forever (yearly snapshots of a system database, a copy-only
follower) either (a) holds content only under per-tenant keys, so a tenant erasure shreds it, or (b) is
capped at 12 months for identity data, after which the snapshot is deleted or re-written with the erased
users removed. Every restore replays the erasure ledger before the restored data is served (see the s3vault
erasure runbook).

## 4. Technical and organisational measures (Art. 32), summary

- Encryption: content and object names encrypted before they leave the proxy host (XChaCha20-Poly1305,
  per-tenant keys); store provider holds ciphertext only.
- Key management: master root offline in two places; tenant keys in a separate key service; escrow copies
  of tenant keys at most 30 days; keys only in RAM on the proxy host (`mlockall`, no swap, no core dumps).
- Erasure: per-tenant crypto-shredding, physical purge by manifest, a hash-chained erasure ledger with a
  proof record per erasure, ledger replay after every restore.
- Access: private network only (Tailscale), per-client S3 keys with per-bucket permissions, admin API on
  loopback with a bearer token.
- Integrity and availability: authenticated encryption detects tampering and rollback of single objects;
  index snapshots per tenant; documented rebuild; backups as in section 3.
- Logging: no key material; plain object keys are still logged in some warnings (review M6, open).

## 5. Data subject requests: where the procedure lives

| Right | Procedure |
|---|---|
| Access, portability (Art. 15, 20) | per-tenant export: s3vault `GET /manifest` plus the objects; per-space database dump |
| Rectification (Art. 16) | in the application |
| Erasure (Art. 17) | tenant: s3vault erasure runbook (freeze, shred, purge, proof); third party: delete the chunks and transcripts concerned, record `object-erased` ledger entries, backups age out within the stated retention |
| Restriction (Art. 18) | tenant freeze in s3vault (the tenant's buckets answer 403); space suspension in the application |
| Objection (Art. 21) | stop speaker identification for that person; delete embeddings |

Record every request: date received, identity check, actions, date answered (one month, Art. 12(3)).
