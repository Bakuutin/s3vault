#!/usr/bin/env bash
# Build the s3vault recovery kit (key hierarchy 4.7, review R3): everything needed to open a keystore copy on a
# new machine when `a` and `d` (and with them Gitea) are gone.
#
#   kh-build-kit.sh OUT.tar --bin PLATFORM=DIR [--bin PLATFORM=DIR ...] [--repo DIR]
#     PLATFORM e.g. macos-arm64, linux-x86_64, linux-arm64; DIR holds s3vault-keyd, s3vault-kh and s3vault
#     (s3vault-se too on macOS). Release builds without the fault-injection feature.
#
# Contents: bin/<platform>/*, s3vault-src-<commit>.tar.gz (git archive of the commit), COMMIT,
# docs/keystore-format.md, deploy/tools/*.sh, RECOVERY.txt (the steps), SHA256SUMS. Prints the kit's sha256.
set -euo pipefail
OUT=${1:?OUT.tar}; shift
REPO=$(cd "$(dirname "$0")/../.." && pwd)
BINS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BINS+=("$2"); shift 2 ;;
    --repo) REPO=$2; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
[ ${#BINS[@]} -gt 0 ] || { echo "at least one --bin PLATFORM=DIR" >&2; exit 2; }
[ -e "$OUT" ] && { echo "$OUT exists" >&2; exit 1; }
COMMIT=$(git -C "$REPO" rev-parse HEAD)
if [ -n "$(git -C "$REPO" status --porcelain --untracked-files=no)" ]; then
  echo "warning: the working tree has uncommitted changes; the kit's source is the commit $COMMIT" >&2
fi
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
K=$T/s3vault-recovery-kit; mkdir -p "$K/bin" "$K/docs" "$K/tools"
for b in "${BINS[@]}"; do
  p=${b%%=*}; d=${b#*=}; mkdir -p "$K/bin/$p"
  for f in s3vault-keyd s3vault-kh s3vault s3vault-se; do
    [ -x "$d/$f" ] && cp "$d/$f" "$K/bin/$p/"
  done
  [ -x "$K/bin/$p/s3vault-keyd" ] || { echo "$d has no s3vault-keyd" >&2; exit 1; }
done
git -C "$REPO" archive --format=tar.gz --prefix="s3vault-$COMMIT/" -o "$K/s3vault-src-$COMMIT.tar.gz" "$COMMIT"
echo "$COMMIT" > "$K/COMMIT"
cp "$REPO/docs/keystore-format.md" "$K/docs/"
cp "$REPO"/deploy/tools/kh-bitwarden-place.sh "$REPO"/deploy/tools/bw-note-blocks.sh "$K/tools/"
cat > "$K/RECOVERY.txt" <<'TXT'
s3vault recovery (key hierarchy 4.7). Needs: this kit, one keystore copy (Bitwarden item "s3vault
keystore ..." or the B2 mirror object keystore.s3vks), and one slot key (the Bitwarden recovery slot key, block
recovery-slot.key in the item "s3vault recovery"). No network is needed for steps 1-2.
1. bin/<platform>/s3vault-keyd kh-drill --copy keystore.s3vks [--copy more copies...] \
     --slot file:recovery-slot.key --rebuild-dir NEW [--ledger-merge w-ledger.jsonl --ledger-merge w-outbox.jsonl]
   It checks the hash chain of all copies, opens the newest, prints the bundle digest, tenants, ledger head and
   slot table, and writes NEW/keys/ (keystore with a new host slot, new psk, ledger, policy).
2. Compare the printed master fingerprint and tenant K_t fingerprints with the last known ones (keys/baseline,
   the proxy's /status). Delete recovery-slot.key from the disk.
3. bin/<platform>/s3vault-keyd serve --dir NEW/keys --listen ADDR --allow PROXY_IP --source keystore \
     --slot file:NEW/keys/host-slot.key ; point the proxy at it (keys.keyd_addr, the new psk), POST /unlock.
4. ks-slots: revoke the lost host and device slots and any slot nobody recognises (ks-slot-revoke), add new ones.
If no binary runs: build from s3vault-src-<commit>.tar.gz (cargo build --release -p s3vault-keyd); the format is
in docs/keystore-format.md.
TXT
( cd "$K" && find . -type f ! -name SHA256SUMS -exec shasum -a 256 {} + | sort -k2 > SHA256SUMS )
tar -cf "$OUT" -C "$T" s3vault-recovery-kit
echo "kit $OUT commit $COMMIT sha256 $(shasum -a 256 "$OUT" | cut -d' ' -f1) size $(wc -c < "$OUT" | tr -d ' ')"
