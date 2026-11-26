#!/usr/bin/env python3
"""Fetch a bucket's manifest from the s3vault admin API (index rows only; never the fallback).

  manifest.py --bucket B [--admin http://127.0.0.1:9101] [--token-file /etc/s3vault/secrets/admin.token]
              [--keys-out KEYS.txt]

Prints `<sha256> <size> <key>` per live object (the format of s3sum.py, so the two can be diffed) and
writes the keys to --keys-out for `s3sum.py --keys-from`. The token is read from a file, never printed.
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bucket", required=True)
    p.add_argument("--admin", default="http://127.0.0.1:9101")
    p.add_argument("--token-file", default="/etc/s3vault/secrets/admin.token")
    p.add_argument("--keys-out")
    a = p.parse_args()
    tok = open(a.token_file).read().strip()
    after, rows = "", []
    while True:
        q = urllib.parse.urlencode({"bucket": a.bucket, "limit": "10000", "after": after})
        req = urllib.request.Request(f"{a.admin}/manifest?{q}", headers={"Authorization": "Bearer " + tok})
        m = json.load(urllib.request.urlopen(req))
        rows += m["items"]
        if not m.get("next_after"):
            break
        after = m["next_after"]
    live = [r for r in rows if not r["tombstone"]]
    for r in live:
        print("%s %d %s" % (r["sha256"], r["size"], r["key"]))
    if a.keys_out:
        with open(a.keys_out, "w") as f:
            f.writelines(r["key"] + "\n" for r in live)
    print("# %d rows, %d live" % (len(rows), len(live)), file=sys.stderr)


if __name__ == "__main__":
    main()
