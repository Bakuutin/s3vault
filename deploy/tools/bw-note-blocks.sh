# shellcheck shell=bash
# Shared helpers (sourced, not run) for the Bitwarden backup scripts in this directory: a file is stored INSIDE a
# secure note's text (no attachments; those need Bitwarden Premium) as a delimited block:
#   -----BEGIN <TAG> <file name>-----
#   <base64 of the file, wrapped at 64>      (mode base64)
#   <the file as-is>                          (mode text-nl / text-nonl: a text file with / without a final newline)
#   -----END <TAG> <file name>-----
# Nothing here prints file contents to the terminal; output goes to the caller's pipes and files.
# Works under macOS /bin/bash 3.2.

# Bitwarden limits a note to 10,000 characters AFTER encryption. Keep a margin below that.
# shellcheck disable=SC2034  # used by the scripts that source this file
BWN_LIMIT=10000
# shellcheck disable=SC2034
BWN_BUDGET=9500

bwn_begin() { printf -- '-----BEGIN %s %s-----' "$1" "$2"; }   # tag fname
bwn_end()   { printf -- '-----END %s %s-----' "$1" "$2"; }

# Length of a note's encrypted string ("2.<iv>|<ciphertext>|<mac>", AES-256-CBC, base64 parts) for a plaintext of
# the given file's size in bytes (the notes are ASCII, so bytes = characters).
bwn_enc_len() {   # file
  local n c
  n=$(wc -c < "$1" | tr -d ' ')
  c=$(( (n / 16 + 1) * 16 ))
  echo $(( 2 + 24 + 1 + ((c + 2) / 3) * 4 + 1 + 44 ))   # base64 length of c bytes: ceil(c/3)*4
}

# How a file should be stored: text-nl / text-nonl if it is printable ASCII lines (no CR, no control bytes),
# otherwise base64.
bwn_mode() {   # file
  local bad last
  bad=$(LC_ALL=C tr -d '\n -~' < "$1" | wc -c | tr -d ' ')
  if [ "$bad" != 0 ]; then echo base64; return; fi
  last=$(tail -c 1 "$1" | od -An -tx1 | tr -d ' \n')
  if [ "$last" = 0a ]; then echo text-nl; else echo text-nonl; fi
}

# Write the block for a file to stdout (into a pipe or file of the caller, never the terminal).
bwn_block() {   # tag fname file mode
  bwn_begin "$1" "$2"; printf '\n'
  case "$4" in
    base64)    base64 < "$3" | tr -d '\n' | fold -w 64; printf '\n' ;;
    text-nl)   cat "$3" ;;
    text-nonl) cat "$3"; printf '\n' ;;
    *) return 1 ;;
  esac
  bwn_end "$1" "$2"; printf '\n'
}

# Number of blocks for fname in note text on stdin.
bwn_count() {   # tag fname
  local b; b=$(bwn_begin "$1" "$2")
  tr -d '\r' | awk -v b="$b" '$0 == b {n++} END {print n + 0}'
}

# All file names that have a block with this tag in note text on stdin, one per line.
bwn_names() {   # tag
  tr -d '\r' | awk -v p="-----BEGIN $1 " 'index($0, p) == 1 && substr($0, length($0) - 4) == "-----" {
    s = substr($0, length(p) + 1); print substr(s, 1, length(s) - 5) }'
}

# The awk program that cuts a block out of note text and restores the exact file bytes (base64 mode prints the
# base64 lines, to be piped through base64 -d). Also used verbatim in the restore line written into the notes.
# shellcheck disable=SC2016  # an awk program, not shell
BWN_AWK='{sub(/\r$/, "")} $0 == e {p = 0} p {if (m == "base64") print; else printf "%s%s", (n++ ? "\n" : ""), $0} $0 == b {p = 1} END {if (m == "text-nl") printf "\n"}'

# Decode the block for fname from note text on stdin into the file out.
bwn_extract() {   # tag fname mode out
  local b e; b=$(bwn_begin "$1" "$2"); e=$(bwn_end "$1" "$2")
  if [ "$3" = base64 ]; then
    awk -v b="$b" -v e="$e" -v m="$3" "$BWN_AWK" | base64 -d > "$4"
  else
    awk -v b="$b" -v e="$e" -v m="$3" "$BWN_AWK" > "$4"
  fi
}

# The shell command (as text for the note) that restores the file from the note of item "name" to dest.
bwn_restore_cmd() {   # item-name tag fname mode dest
  local b e tail=""
  b=$(bwn_begin "$2" "$3"); e=$(bwn_end "$2" "$3")
  [ "$4" = base64 ] && tail=" | base64 -d"
  printf "bw list items --search '%s' | jq -r '.[] | select(.name == \"%s\") | .notes' | awk -v b='%s' -v e='%s' -v m=%s '%s'%s > %s" \
    "$1" "$1" "$b" "$e" "$4" "$BWN_AWK" "$tail" "$5"
}
