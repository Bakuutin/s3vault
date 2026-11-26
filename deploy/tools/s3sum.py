#!/usr/bin/env python3
"""List a bucket through any S3 endpoint and print `<sha256> <size> <key>` for every object (stdlib only).

Used for deploy pass checks: run it before and after an update and compare the outputs (`diff`), so every
object reads back byte-identical through the gateway.

  s3sum.py --endpoint http://127.0.0.1:9100 --access-key ID --secret-file FILE --bucket B [--prefix P]
  s3sum.py ... --bucket B --keys-from KEYS.txt     read only these keys (one per line), no listing

For a bucket with a read-through fallback, use --keys-from with the keys of the admin `GET /manifest`
(keys already in the store), so the check never reads through from (or fills from) the fallback.

The secret is read from a file and never printed. Path-style requests, SigV4, region us-east-1.
"""

import argparse
import datetime
import hashlib
import hmac
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

EMPTY = hashlib.sha256(b"").hexdigest()


def sign(method, url, ak, sk, region="us-east-1"):
    u = urllib.parse.urlsplit(url)
    now = datetime.datetime.now(datetime.timezone.utc)
    amz = now.strftime("%Y%m%dT%H%M%SZ")
    day = now.strftime("%Y%m%d")
    q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    cq = "&".join(
        f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}" for k, v in sorted(q)
    )
    headers = {"host": u.netloc, "x-amz-content-sha256": EMPTY, "x-amz-date": amz}
    sh = ";".join(sorted(headers))
    ch = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers))
    creq = "\n".join([method, urllib.parse.quote(u.path, safe="/-_.~"), cq, ch, sh, EMPTY])
    scope = f"{day}/{region}/s3/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = ("AWS4" + sk).encode()
    for part in (day, region, "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders={sh}, Signature={sig}"
    del headers["host"]
    return headers


def get(url, ak, sk):
    req = urllib.request.Request(url, headers=sign("GET", url, ak, sk))
    return urllib.request.urlopen(req, timeout=120)


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


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--endpoint", required=True)
    p.add_argument("--access-key", required=True)
    p.add_argument("--secret-file", required=True)
    p.add_argument("--bucket", required=True)
    p.add_argument("--prefix", default="")
    p.add_argument("--keys-from")
    a = p.parse_args()
    sk = open(a.secret_file).read().strip()
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
