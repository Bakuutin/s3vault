#!/usr/bin/env bash
# The Bitwarden escrow place of the s3vault key hierarchy (KH6, KH12, KH15), run on the administrator's workstation.
# Files go INSIDE secure-note text as delimited blocks (bw-note-blocks.sh: no attachments, those need Premium).
#
# Items (Bitwarden caps a note at 10,000 characters after encryption, so the keystore has its own item):
#   "s3vault keystore (epoch N, part i of n)"   the newest keystore epoch, block S3VAULT KEYSTORE
#                                          keystore.s3vks.part<i> (base64), with its epoch, sha256 and a restore
#                                          line; n > 1 only when one note is too small. Items of older epochs are
#                                          deleted permanently once the new one reads back (retention, 4.6).
#   "s3vault recovery"            the recovery slot key (block S3VAULT RECOVERY SLOT
#                                          recovery-slot.key, text), the mirror read key (S3VAULT MIRROR
#                                          READ KEY mirror-read.toml) and the kit pointer (sha256, mirror object).
#
# Usage:
#   kh-bitwarden-place.sh put-keystore FILE          store, read back, compare sha256; prints "sha256 <hex>"
#   kh-bitwarden-place.sh get-keystore OUT           restore the keystore copy (refuses to overwrite)
#   kh-bitwarden-place.sh put-block NAME FILE        recovery-slot.key | mirror-read.toml | kit-pointer.txt
#                                                    into the "recovery" item (replaces that block only)
#   kh-bitwarden-place.sh get-block NAME OUT
#   kh-bitwarden-place.sh status                     item names, block names and sizes (no content)
#
# Environment: BW (bw binary, default `bw`; tests point it at a fake), BW_SESSION (if set, the Keychain is not
# touched), KH_BW_PREFIX (item name prefix, default "s3vault"), KH_BW_MARKER (note block marker, default "S3VAULT"),
# KH_BW_KEYCHAIN_ITEM (Keychain item for the session, default "s3vault-bw-session"). Nothing is printed but names, sizes and
# digests; bw never prompts (BW_NOINTERACTION).
set -euo pipefail

BWBIN=${BW:-bw}
PREFIX=${KH_BW_PREFIX:-s3vault}
KS_ITEM="$PREFIX keystore"
REC_ITEM="$PREFIX recovery"
KC_ITEM=${KH_BW_KEYCHAIN_ITEM:-s3vault-bw-session}
MARK=${KH_BW_MARKER:-S3VAULT}   # block marker inside the notes; keep the value used when the items were written
export BW_NOINTERACTION=true

die() { printf 'kh-bitwarden-place: %s\n' "$*" >&2; exit 1; }
bw() { command "$BWBIN" --nointeraction "$@"; }
command -v jq >/dev/null || die "jq not found"
# shellcheck source=bw-note-blocks.sh
. "${KH_BWN_LIB:-$(dirname "$0")/bw-note-blocks.sh}" || die "bw-note-blocks.sh not found"

TMP=$(mktemp -d); chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT
sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }

# --- unlock (the bw CLI pattern: bash reads the password once; the session lives in the macOS Keychain) -------
bw_status() { bw status 2>/dev/null | jq -r '.status // "unknown"'; }
if [ -z "${BW_SESSION:-}" ]; then
  BW_SESSION=$(security find-generic-password -a "$USER" -s "$KC_ITEM" -w 2>/dev/null || true)
  export BW_SESSION
  if [ -z "$BW_SESSION" ] || [ "$(bw_status)" != "unlocked" ]; then
    [ -t 0 ] || die "vault locked and no terminal to ask for the master password"
    printf 'Bitwarden master password: ' >&2; IFS= read -rs PW; printf '\n' >&2
    PWFILE="$TMP/pw"; (umask 077; printf '%s' "$PW" > "$PWFILE"); unset PW
    BW_SESSION=$(bw unlock --passwordfile "$PWFILE" --raw 2>/dev/null) || true
    rm -f "$PWFILE"
    [ -n "$BW_SESSION" ] || die "unlock failed"
    export BW_SESSION
    security add-generic-password -U -a "$USER" -s "$KC_ITEM" -w "$BW_SESSION" >/dev/null
  fi
fi
[ "$(bw_status)" = "unlocked" ] || die "vault is not unlocked"
bw sync >/dev/null 2>&1 || true

item_id() {   # exact name -> id or ""
  bw list items --search "$1" | jq -r --arg n "$1" '[.[] | select(.name == $n)][0].id // ""'
}
notes_of() { bw get item "$1" | jq -r '.notes // ""'; }
create_item() {   # name notes-file -> id
  jq -n --arg name "$1" --rawfile notes "$2" '{type: 2, name: $name, notes: $notes, secureNote: {type: 0}}' \
    | bw encode | bw create item | jq -r '.id'
}
edit_notes() {   # id notes-file
  bw get item "$1" | jq --rawfile notes "$2" '.notes = $notes' | bw encode | bw edit item "$1" >/dev/null
}
fits() { [ "$(bwn_enc_len "$1")" -le "$BWN_BUDGET" ]; }

# Keystore items are named per epoch: "<KS_ITEM> (epoch N, part i of n)". A new epoch is written as NEW items,
# read back, and only then are the items of other epochs deleted (permanently), so a crash in the middle never
# leaves a mixed or missing copy: get-keystore takes the highest epoch whose parts are all present and intact.
ks_items() {   # -> "id<TAB>epoch<TAB>part<TAB>of" lines
  bw list items --search "$KS_ITEM" | jq -r --arg n "$KS_ITEM (epoch " '.[] | select(.name | startswith($n)) |
    (.name | capture("\\(epoch (?<e>[0-9]+), part (?<i>[0-9]+) of (?<n>[0-9]+)\\)$")) as $m |
    [.id, $m.e, $m.i, $m.n] | @tsv'
}

put_keystore() {
  local f=$1 sha epoch n i parts=1
  [ -f "$f" ] || die "no file $f"
  sha=$(sha256 "$f")
  epoch=$(od -An -tu1 -j24 -N8 -v "$f" | tr -s ' \n' ' ' | awk '{v=0; for (i=1;i<=NF;i++) v=v*256+$i; printf "%d\n", v}')
  base64 < "$f" | tr -d '\n' > "$TMP/b64"
  while :; do
    n=$(( ($(wc -c < "$TMP/b64") + parts - 1) / parts ))
    rm -f "$TMP"/part.* "$TMP"/note.*
    split -b "$n" "$TMP/b64" "$TMP/part."
    local ok=1 k=0
    for p in "$TMP"/part.*; do
      k=$((k + 1))
      { printf 's3vault keystore copy: epoch %s sha256 %s, part %s of %s, stored %s\n' "$epoch" "$sha" "$k" "$parts" "$(date -u '+%Y-%m-%d %H:%M UTC')"
        printf 'Restore: join the base64 lines of every part in order, base64 -d > keystore.s3vks, check the sha256.\n'
        bwn_begin "$MARK KEYSTORE" "keystore.s3vks.part$k"; printf '\n'
        fold -w 64 < "$p"; printf '\n'
        bwn_end "$MARK KEYSTORE" "keystore.s3vks.part$k"; printf '\n'
      } > "$TMP/note.$k"
      fits "$TMP/note.$k" || ok=0
    done
    [ "$ok" = 1 ] && break
    parts=$((parts + 1))
    [ "$parts" -le 20 ] || die "keystore too large for 20 notes"
  done
  ks_items > "$TMP/items"
  if awk -F'\t' -v e="$epoch" '$2 == e' "$TMP/items" | grep -q .; then
    # this epoch is there already (a rerun): it must be intact and equal, otherwise it is replaced
    if get_epoch "$epoch" "$TMP/existing" 2>/dev/null && [ "$(sha256 "$TMP/existing")" = "$sha" ]; then
      printf 'sha256 %s epoch %s parts %s (already stored)\n' "$sha" "$epoch" "$parts"
      cleanup_except "$epoch"
      return
    fi
    awk -F'\t' -v e="$epoch" '$2 == e {print $1}' "$TMP/items" | while read -r id; do bw delete item "$id" --permanent >/dev/null; done
  fi
  for i in $(seq 1 "$parts"); do
    create_item "$KS_ITEM (epoch $epoch, part $i of $parts)" "$TMP/note.$i" >/dev/null
  done
  bw sync >/dev/null 2>&1 || true
  rm -f "$TMP/back"
  get_epoch "$epoch" "$TMP/back"
  [ "$(sha256 "$TMP/back")" = "$sha" ] || die "read-back differs from the uploaded keystore"
  cleanup_except "$epoch"
  printf 'sha256 %s epoch %s parts %s\n' "$sha" "$epoch" "$parts"
}

cleanup_except() {   # permanently delete keystore items of every other epoch (retention: only the newest copy)
  ks_items | awk -F'\t' -v e="$1" '$2 != e {print $1}' | while read -r id; do bw delete item "$id" --permanent >/dev/null; done
}

get_epoch() {   # epoch out
  local e=$1 out=$2 parts k id
  ks_items > "$TMP/items.$e"
  parts=$(awk -F'\t' -v e="$e" '$2 == e {print $4; exit}' "$TMP/items.$e")
  [ -n "$parts" ] || return 1
  : > "$TMP/joined"
  for k in $(seq 1 "$parts"); do
    id=$(awk -F'\t' -v e="$e" -v k="$k" '$2 == e && $3 == k {print $1; exit}' "$TMP/items.$e")
    [ -n "$id" ] || return 1
    notes_of "$id" > "$TMP/n.$k"
    grep -qxF -e "$(bwn_begin "$MARK KEYSTORE" "keystore.s3vks.part$k")" "$TMP/n.$k" || return 1
    awk -v b="$(bwn_begin "$MARK KEYSTORE" "keystore.s3vks.part$k")" \
        -v e="$(bwn_end "$MARK KEYSTORE" "keystore.s3vks.part$k")" -v m=base64 "$BWN_AWK" < "$TMP/n.$k" \
      | tr -d '\n' >> "$TMP/joined"
  done
  (umask 077; base64 -d < "$TMP/joined" > "$out") || return 1
  # the sha256 recorded in part 1's metadata line must match the joined copy
  [ "$(sha256 "$out")" = "$(sed -n '1s/.* sha256 \([0-9a-f]*\),.*/\1/p' "$TMP/n.1")" ] || { rm -f "$out"; return 1; }
  # the copy names its own epoch: a part from another epoch cannot slip in
  [ "$(od -An -tu1 -j24 -N8 -v "$out" | tr -s ' \n' ' ' | awk '{v=0; for (i=1;i<=NF;i++) v=v*256+$i; printf "%d\n", v}')" = "$e" ]
}

get_keystore() {   # the highest epoch that is complete
  local out=$1 e
  [ -e "$out" ] && die "$out exists"
  for e in $(ks_items | cut -f2 | sort -un -r); do
    if get_epoch "$e" "$TMP/try.$e"; then (umask 077; cp "$TMP/try.$e" "$out"); return 0; fi
    printf 'kh-bitwarden-place: epoch %s is incomplete, trying an older one\n' "$e" >&2
  done
  die "no complete keystore copy in Bitwarden"
}

put_block() {   # name file: replace that block in the recovery item
  local name=$1 f=$2 mode id
  [ -f "$f" ] || die "no file $f"
  mode=$(bwn_mode "$f")
  id=$(item_id "$REC_ITEM")
  if [ -n "$id" ]; then notes_of "$id" > "$TMP/cur"; else printf 's3vault recovery item (key hierarchy 4.7)\n' > "$TMP/cur"; fi
  # drop the old block of this name, append the new one
  awk -v b="$(bwn_begin "$MARK" "$name")" -v e="$(bwn_end "$MARK" "$name")" \
    '{sub(/\r$/, "")} $0 == b {skip = 1} !skip {print} $0 == e {skip = 0}' "$TMP/cur" > "$TMP/new"
  { printf '%s (%s, sha256 %s)\n' "$name" "$mode" "$(sha256 "$f")"; bwn_block "$MARK" "$name" "$f" "$mode"; } >> "$TMP/new"
  fits "$TMP/new" || die "the recovery item would exceed the note limit"
  if [ -n "$id" ]; then edit_notes "$id" "$TMP/new"; else create_item "$REC_ITEM" "$TMP/new" >/dev/null; fi
  bw sync >/dev/null 2>&1 || true
  get_block "$name" "$TMP/back.$name" "$mode"
  [ "$(sha256 "$TMP/back.$name")" = "$(sha256 "$f")" ] || die "read-back of $name differs"
  printf 'sha256 %s %s\n' "$(sha256 "$f")" "$name"
}

get_block() {   # name out [mode]
  local name=$1 out=$2 mode=${3:-} id
  [ -e "$out" ] && die "$out exists"
  id=$(item_id "$REC_ITEM"); [ -n "$id" ] || die "no recovery item in Bitwarden"
  notes_of "$id" > "$TMP/rec"
  [ -n "$mode" ] || mode=$(awk -v n="$name" 'index($0, n " (") == 1 {sub(/^[^(]*\(/, ""); sub(/,.*/, ""); m=$0} END {print m}' "$TMP/rec")
  [ -n "$mode" ] || die "no block $name"
  (umask 077; bwn_extract "$MARK" "$name" "$mode" "$out" < "$TMP/rec")
  [ -s "$out" ] || die "block $name is empty"
}

case "${1:-}" in
  put-keystore) put_keystore "${2:?file}" ;;
  get-keystore) get_keystore "${2:?out}"; printf 'restored %s sha256 %s\n' "$2" "$(sha256 "$2")" ;;
  put-block) put_block "${2:?name}" "${3:?file}" ;;
  get-block) get_block "${2:?name}" "${3:?out}"; printf 'restored %s\n' "$2" ;;
  status)
    ks_items | awk -F'\t' '{print "keystore epoch " $2 " part " $3 " of " $4}' 
    id=$(item_id "$REC_ITEM"); [ -n "$id" ] && { echo "$REC_ITEM:"; notes_of "$id" | bwn_names "$MARK" | sed 's/^/  /'; }
    true ;;
  *) sed -n '2,25p' "$0"; exit 2 ;;
esac
