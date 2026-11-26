#!/usr/bin/env python3
"""List a bucket through any S3 endpoint and print `<sha256> <size> <key>` for every object (stdlib only).

Used for deploy pass checks: run it before and after an update and compare the outputs (`diff`), so every
object reads back byte-identical through the gateway.

  s3sum.py --endpoint http://127.0.0.1:9100 --access-key ID --secret-file FILE --bucket B [--prefix P]
  s3sum.py ... --bucket B --keys-from KEYS.txt     read only these keys (one per line), no listing
  s3sum.py ... --list-only [--region garage --toml-credentials]   list `<size> <key>` (e.g. the store itself)
  s3sum.py ... --prefix o/<tag>/ --pull-to DIR    raw copy of one tenant's objects (a per-tenant follower copy)
  s3sum.py ... --push-from DIR [--skip-existing]  upload them back (a restore; replay the ledger afterwards), or
                                                  copy a tenant to a new store (README, B2 switch); PUTs retry

For a bucket with a read-through fallback, use --keys-from with the keys of the admin `GET /manifest`
(keys already in the store), so the check never reads through from (or fills from) the fallback.

The secret is read from a file and never printed. Path-style requests, SigV4, region us-east-1.
"""

import argparse
import datetime
import hashlib
import hmac
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

EMPTY = hashlib.sha256(b"").hexdigest()


def sign(method, url, ak, sk, region="us-east-1", payload_hash=EMPTY):
    u = urllib.parse.urlsplit(url)
    now = datetime.datetime.now(datetime.timezone.utc)
    amz = now.strftime("%Y%m%dT%H%M%SZ")
    day = now.strftime("%Y%m%d")
    q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    cq = "&".join(
        f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}" for k, v in sorted(q)
    )
    headers = {"host": u.netloc, "x-amz-content-sha256": payload_hash, "x-amz-date": amz}
    sh = ";".join(sorted(headers))
    ch = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers))
    creq = "\n".join([method, urllib.parse.quote(u.path, safe="/-_.~"), cq, ch, sh, payload_hash])
    scope = f"{day}/{region}/s3/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = ("AWS4" + sk).encode()
    for part in (day, region, "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders={sh}, Signature={sig}"
    del headers["host"]
    return headers


REGION = "us-east-1"


def get(url, ak, sk):
    req = urllib.request.Request(url, headers=sign("GET", url, ak, sk, REGION))
    return urllib.request.urlopen(req, timeout=120)


RETRY_STATUS = {408, 429, 500, 502, 503, 504}


def put(url, ak, sk, body, attempts=6):
    """PUT with bounded exponential backoff and jitter (B2 answers 500/503 under load); a whole-object PUT
    is idempotent, so every attempt re-signs and resends the same bytes."""
    import random
    import time
    payload = hashlib.sha256(body).hexdigest()
    for n in range(1, attempts + 1):
        try:
            req = urllib.request.Request(url, data=body, method="PUT", headers=sign("PUT", url, ak, sk, REGION, payload))
            return urllib.request.urlopen(req, timeout=600).read()
        except urllib.error.HTTPError as e:
            if e.code not in RETRY_STATUS or n == attempts:
                raise
            err = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if n == attempts:
                raise
            err = type(e).__name__
        cap = min(30.0, 0.5 * 2 ** (n - 1))
        d = random.uniform(cap / 2, cap)
        print(f"# put attempt {n} failed ({err}), retrying in {d:.1f}s", file=sys.stderr)
        time.sleep(d)


def digest(a, sk, key):
    h = hashlib.sha256()
    size = 0
    with get(f"{a.endpoint}/{a.bucket}/{urllib.parse.quote(key, safe='/-_.~')}", a.access_key, sk) as r:
        while True:
            b = r.read(1 << 20)
            if not b:
                break
            h.update(b)
            size += len(b)
    return f"{h.hexdigest()} {size}"


def list_sizes(a, sk):
    """`{key: size}` of the bucket (under --prefix)."""
    ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
    out, token = {}, None
    while True:
        q = {"list-type": "2", "max-keys": "1000"}
        if a.prefix:
            q["prefix"] = a.prefix
        if token:
            q["continuation-token"] = token
        url = f"{a.endpoint}/{a.bucket}?" + urllib.parse.urlencode(sorted(q.items()), quote_via=urllib.parse.quote)
        root = ET.fromstring(get(url, a.access_key, sk).read())
        for c in root.findall(f"{ns}Contents"):
            out[c.find(f"{ns}Key").text] = int(c.findtext(f"{ns}Size"))
        t = root.find(f"{ns}NextContinuationToken")
        if root.findtext(f"{ns}IsTruncated") == "true" and t is not None:
            token = t.text
        else:
            return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--endpoint", required=True)
    p.add_argument("--access-key", required=True)
    p.add_argument("--secret-file", required=True)
    p.add_argument("--bucket", required=True)
    p.add_argument("--prefix", default="")
    p.add_argument("--keys-from")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--list-only", action="store_true", help="print `<size> <key>` without reading objects")
    p.add_argument("--toml-credentials", action="store_true", help="the secret file is a TOML credentials file")
    p.add_argument("--pull-to", help="copy every listed object (raw bytes) into this directory (a follower copy)")
    p.add_argument("--skip-existing", action="store_true", help="with --push-from: skip keys the bucket already holds with the same size (resume)")
    p.add_argument("--push-from", help="upload every file below this directory under its relative path (a restore)")
    a = p.parse_args()
    global REGION
    REGION = a.region
    sk = open(a.secret_file).read().strip()
    if a.toml_credentials:
        sk = [l.split("=", 1)[1].strip().strip('"') for l in sk.splitlines() if l.startswith("secret_access_key")][0]
    if a.push_from:
        import os
        have = list_sizes(a, sk) if a.skip_existing else {}
        n = skipped = 0
        for root, _, files in os.walk(a.push_from):
            for f in sorted(files):
                path = os.path.join(root, f)
                key = os.path.relpath(path, a.push_from)
                if have.get(key) == os.path.getsize(path):
                    skipped += 1
                    continue
                with open(path, "rb") as fh:
                    put(f"{a.endpoint}/{a.bucket}/{urllib.parse.quote(key, safe='/-_.~')}", a.access_key, sk, fh.read())
                n += 1
        print(f"# pushed {n} objects, skipped {skipped} already present with the same size", file=sys.stderr)
        return
    if a.keys_from:
        keys = [k.rstrip("\n") for k in open(a.keys_from) if k.strip()]
        for key in keys:
            print(f"{digest(a, sk, key)} {key}")
        print(f"# {len(keys)} objects", file=sys.stderr)
        return
    ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
    token = None
    n = 0
    while True:
        q = {"list-type": "2", "max-keys": "1000"}
        if a.prefix:
            q["prefix"] = a.prefix
        if token:
            q["continuation-token"] = token
        url = f"{a.endpoint}/{a.bucket}?" + urllib.parse.urlencode(sorted(q.items()), quote_via=urllib.parse.quote)
        root = ET.fromstring(get(url, a.access_key, sk).read())
        for c in root.findall(f"{ns}Contents"):
            key = c.find(f"{ns}Key").text
            if a.pull_to:
                import os
                dst = os.path.join(a.pull_to, key)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with get(f"{a.endpoint}/{a.bucket}/{urllib.parse.quote(key, safe='/-_.~')}", a.access_key, sk) as r, open(dst, "wb") as f:
                    f.write(r.read())
                print(f"pulled {key}")
            elif a.list_only:
                print(f"{c.findtext(f'{ns}Size')} {key}")
            else:
                print(f"{digest(a, sk, key)} {key}")
            n += 1
        t = root.find(f"{ns}NextContinuationToken")
        if root.findtext(f"{ns}IsTruncated") == "true" and t is not None:
            token = t.text
        else:
            break
    print(f"# {n} objects", file=sys.stderr)


if __name__ == "__main__":
    main()
