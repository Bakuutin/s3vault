# s3vault keystore format (S3VKS001)

The keystore holds the data keys of s3vault (the master keyring text with the root and the legacy v1 keys, every
tenant key `K_t`, the erasure ledger) sealed under a random master unlock key (MUK), with one random tenant unlock
key (TUK) per tenant. Slots are HPKE public keys that wrap the MUK (master slot) or one TUK (tenant slot). Design:
media `docs/design/S3VAULT_KEY_HIERARCHY.md`. Code: `crates/s3vault-format/src/keystore.rs`, `hpke.rs`,
`slots.rs`. All integers are big-endian.

## File (one per epoch, `ks-<epoch, 10 digits>.s3vks`)

| Part | Bytes |
|---|---|
| magic | `S3VKS001` (8) |
| keystore id | 16 random bytes, the same in every epoch |
| epoch | u64, grows by one on every change |
| issued | u64 unix seconds |
| prev hash | 32: SHA-256 of the previous epoch's whole file (zeros for epoch 1); the hash chain |
| nonce | 24 random bytes (XChaCha20 nonce of the sealed part) |
| slots | u16 count; per slot: id (8) \| KEM id u16 \| target u8 (0 master, 1 tenant) \| tenant ref (16, zeros for master) \| u16 len + HPKE enc \| u16 len + HPKE ciphertext of the 32-byte unlock key |
| tenant blocks | u16 count; per block: ref (16) \| nonce (24) \| u32 len + ciphertext |
| sealed part | u32 len + ciphertext |

"Public part" = the bytes from the magic to the end of the slots.

- **Slot id** = first 8 bytes of SHA-256(`"s3vault/keystore/v1/slot-id"` \|\| KEM id u16 \|\| public key).
- **Slot wrap**: HPKE RFC 9180 base mode, single shot. KEM DHKEM(X25519, HKDF-SHA256) `0x0020` or
  DHKEM(P-256, HKDF-SHA256) `0x0010` (public keys: 32 bytes, or 65 bytes uncompressed X9.63), KDF HKDF-SHA256
  `0x0001`, AEAD ChaCha20-Poly1305 `0x0003`. `info` = `"s3vault/keystore/v1/slot"` \|\| keystore id \|\| epoch
  u64 \|\| slot id \|\| target u8 \|\| tenant ref; `aad` empty; plaintext the MUK or TUK.
- **Tenant block**: XChaCha20-Poly1305 under the tenant's TUK, nonce from the block, AD = SHA-256(
  `"s3vault/keystore/v1/block"` \|\| public part) \|\| ref. Plaintext: tenant id (16) \|\| write generation u32 \|\|
  u16 n \|\| n x 32-byte keys (`K_t[0]` first; today n = 1).
- **Sealed part**: XChaCha20-Poly1305 under the MUK with the header nonce, AD = SHA-256(
  `"s3vault/keystore/v1/sealed"` \|\| every byte before the sealed part's length). Plaintext: TLV sections
  (tag u8, u32 len, bytes):
  1. master keyring text (`s3vault-keyring v2`, verbatim)
  2. tenant keyring text (`s3vault-tenants v1`), each tenant's key field replaced by `@<ref as hex>`
  3. TUK table: (ref 16 \|\| TUK 32)*
  4. erasure ledger (JSON lines, verbatim)
  5. slot table, JSON: id, kem, target (`master` or `tenant:<ref>`), pk (base64), kind, label, holder, backend,
     created, created_by
  6. policy (TOML: retention_days, activate_requires, min_master_slots, warn_after_days)
  7. change log, JSON: epoch, at, op, detail

## Opening by hand (recovery without the binaries)

1. Find the slot whose id matches your public key; HPKE-open its ciphertext with your private key: the MUK.
2. Open the sealed part with the MUK; read the TUK table.
3. Open each tenant block with its TUK; put `base64(K_t[0])` in place of `@<ref>` in section 2.
4. Sections 1, 2 (filled in) and 4 are the three files s3vault-keyd used before the keystore (`keyring`,
   `tenants`, `ledger.jsonl`): any s3vault-keyd since 2026-11 serves them with `--source files`.

## Slot key files

- Software key: `s3vault-slot-key v1` / `kem x25519|p256` / `sk <base64 of the 32-byte scalar>`.
- Public file: `s3vault-slot-pub v1` / `kem` / `pk <base64>` / `kind host|device|recovery|tenant-device` /
  `label` / `holder` / `backend` / `target master|tenant <name>`.
- Hardware helper protocol (Secure Enclave `s3vault-se`, TPM, testenv stand-in): `PROGRAM pub REF` prints
  `kem <name>` and `pk <base64>`; `PROGRAM dh REF` reads one base64 line (the sender's ephemeral public key) and
  prints one base64 line (the 32-byte DH output). Descriptor: `helper:REF:PROGRAM [ARGS]`.
