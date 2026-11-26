# Processor agreements needed (GDPR Art. 28) and what to check

Status: draft checklist, 2026-11-26. Not legal advice. Generic for an s3vault deployment; the example is
the application's (proxy on a rented VPS `w`, object store Backblaze B2, key service on owner hardware).

A provider is a processor when it processes personal data on the controller's behalf. Ciphertext with the
keys held elsewhere is still personal data for the controller, so the object store provider is a processor
too; strong encryption is a supplementary measure, not an exemption.

## 1. Agreements

| Provider | Role | Sees | Agreement | Example |
|---|---|---|---|---|
| Hosting provider of the proxy host | processor | **plaintext and keys in RAM** (it controls the hypervisor) | DPA (Art. 28(3)), usually part of the terms; accept it explicitly and file it | the VPS provider of `w` |
| Object store provider | processor | ciphertext, object sizes, access timing | DPA; transfer safeguards if the company or its sub-processors are outside the EU/EEA | Backblaze B2 |
| Network overlay | processor for connection metadata (or not, if it only sees metadata of the controller) | node names, IPs, timing; no content | its DPA if offered | Tailscale |
| Transcription or AI services, if any run outside owner hardware | processor | plaintext audio or text | DPA plus transfer safeguards; check training-use clauses | none today: Whisper runs on owner hardware |
| Email or notification services | processor | addresses, message content | DPA | as used by the application |

The key service and the owner's devices are the controller's own hardware: no agreement, but they belong
in the records of processing.

## 2. What to check for each processor

- **Region and data location**: where data is stored and processed. B2: the region is chosen at account
  sign-up and is fixed per account; choose an EU region (for example `eu-central-003`) **before** creating
  the bucket. VPS: the data-centre country of the host.
- **Company and group location**: a US parent can be compelled under US law; check the transfer mechanism
  (EU-US Data Privacy Framework certification, or SCCs with a transfer impact assessment).
- **Sub-processors**: the published list, the notice period for changes, and the right to object.
- **Security measures (Art. 32)**: certifications (ISO 27001, SOC 2), encryption at rest, access controls,
  staff access to customer RAM or disks (critical for the proxy host).
- **Breach notification**: the time limit to notify the controller (needed for the 72-hour clock).
- **Deletion at the end of service**: how and when data, including backups, is deleted; whether deleted
  object versions are kept (B2: lifecycle rules; see below).
- **Assistance with data subject requests and DPIAs** (Art. 28(3)(e), (f)).
- **Audit rights**: reports offered instead of on-site audits is normal; note what is provided.
- **Law-enforcement requests**: the provider's policy and transparency report.

## 3. Object store settings that are part of the compliance story (owner steps)

- **Lifecycle "keep only the last version", 7 days from hide to delete (decision D2).** In the B2 console:
  bucket -> Lifecycle Settings -> "Keep only the last version of the file", or a custom rule with
  `daysFromHidingToDeleting = 7` and `daysFromUploadingToHiding = null` for the whole bucket (empty
  prefix). With the `b2` CLI:
  `b2 bucket update --lifecycle-rule '{"daysFromHidingToDeleting": 7, "daysFromUploadingToHiding": null, "fileNamePrefix": ""}' <bucket> allPrivate`.
  D = 7 days is both the undelete window and the physical-erasure tail of an erasure.
- No B2 server-side encryption is needed (the data is already encrypted), and object lock must stay **off**
  (it would block erasure).
- An application key restricted to the bucket; the account master key stays offline.

## 4. Filing

Keep each signed or accepted DPA, the date, the version, and the sub-processor list as of signing, with the
records of processing. Review yearly and when a provider announces new sub-processors.
