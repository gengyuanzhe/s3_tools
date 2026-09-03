#!/usr/bin/env python3
"""
S3 对象列举性能对比脚本（仅使用 Python 标准库）

方法1: 对指定 prefix 下每个子目录并发列举（只用 continuation-token 翻页, 不用 delimiter）
方法2: 用 delimiter=/ BFS 逐层列举

用法:
    python3 list_s3_compare.py --ak <AK> --sk <SK> --host <IP> --port <PORT> \
        --bucket <桶名> --prefix <目录前缀> --concurrency <并发数> \
        [--sign v2|v4] [--region us-east-1] [--https]

输出(每种方法):
    List 调用次数 / List 平均时延 / 总时延 / 对象数 / 子前缀数
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import http.client
import queue as _q
import ssl
import sys
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from collections import deque
from concurrent.futures import ThreadPoolExecutor

ALGORITHM = "AWS4-HMAC-SHA256"
SERVICE = "s3"


# ---------------- SigV4 签名工具 ----------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def derive_signing_key(sk: str, datestamp: str, region: str) -> bytes:
    k_date = hmac_sha256(("AWS4" + sk).encode("utf-8"), datestamp)
    k_region = hmac_sha256(k_date, region)
    k_service = hmac_sha256(k_region, SERVICE)
    return hmac_sha256(k_service, "aws4_request")


def uri_encode(s: str) -> str:
    # RFC 3986 编码, 保留无符号字符
    return urllib.parse.quote(s, safe="-_.~")


# ---------------- 统计 ----------------

class Stats:
    __slots__ = ("_lock", "calls", "latency_sum", "objects", "prefixes")

    def __init__(self):
        self._lock = threading.Lock()
        self.calls = 0
        self.latency_sum = 0.0
        self.objects = 0
        self.prefixes = 0

    def record(self, latency: float, n_obj: int, n_pre: int):
        with self._lock:
            self.calls += 1
            self.latency_sum += latency
            self.objects += n_obj
            self.prefixes += n_pre

    @property
    def avg_ms(self) -> float:
        return (self.latency_sum / self.calls * 1000.0) if self.calls else 0.0


# ---------------- 列举器 ----------------

class S3Lister:
    def __init__(self, host, port, bucket, ak, sk,
                 region="us-east-1", use_https=False, concurrency=16, sign="v4"):
        self.host = host
        self.port = port
        self.bucket = bucket
        self.ak = ak
        self.sk = sk
        self.region = region
        self.use_https = use_https
        self.concurrency = max(1, concurrency)
        self.sign = sign.lower()
        if self.sign not in ("v2", "v4"):
            raise ValueError(f"sign must be v2 or v4, got: {sign}")
        self.stats = Stats()
        self._local = threading.local()

    # 线程本地持久连接(HTTP/1.1 keep-alive), 避免每次握手
    def _get_conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            if self.use_https:
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(self.host, self.port, timeout=60, context=ctx)
            else:
                conn = http.client.HTTPConnection(self.host, self.port, timeout=60)
            self._local.conn = conn
        return conn

    def _reset_conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    @staticmethod
    def _parse(body: bytes):
        root = ET.fromstring(body)

        def findtext(el, name):
            for c in el:
                if c.tag.split("}")[-1] == name:
                    return c.text
            return None

        contents, common = [], []
        for child in root:
            tag = child.tag.split("}")[-1]
            if tag == "Contents":
                for sub in child:
                    if sub.tag.split("}")[-1] == "Key":
                        contents.append(sub.text)
                        break
            elif tag == "CommonPrefixes":
                for sub in child:
                    if sub.tag.split("}")[-1] == "Prefix":
                        common.append(sub.text)
                        break
        return {
            "contents": contents,
            "common_prefixes": common,
            "is_truncated": findtext(root, "IsTruncated") == "true",
            "next_token": findtext(root, "NextContinuationToken"),
        }

    def _build_headers_v4(self, canonical_uri, canonical_query, host_header, payload_hash):
        t = datetime.datetime.utcnow()
        amz_date = t.strftime("%Y%m%dT%H%M%SZ")
        datestamp = t.strftime("%Y%m%d")
        hdrs = {
            "host": host_header,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        sorted_hdrs = sorted(hdrs.items())
        canonical_headers = "".join(f"{k}:{v.strip()}\n" for k, v in sorted_hdrs)
        signed_headers = ";".join(k for k, _ in sorted_hdrs)
        canonical_request = "\n".join([
            "GET", canonical_uri, canonical_query,
            canonical_headers, signed_headers, payload_hash,
        ])
        credential_scope = f"{datestamp}/{self.region}/{SERVICE}/aws4_request"
        string_to_sign = "\n".join([
            ALGORITHM, amz_date, credential_scope,
            sha256_hex(canonical_request.encode("utf-8")),
        ])
        signing_key = derive_signing_key(self.sk, datestamp, self.region)
        signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        authorization = (
            f"{ALGORITHM} Credential={self.ak}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        return {
            "Host": host_header,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
            "Authorization": authorization,
        }

    def _build_headers_v2(self, canonical_resource, host_header):
        # V2: StringToSign = METHOD\nContent-MD5\nContent-Type\nDate\n(CanonicalizedAmzHeaders)\nCanonicalizedResource
        t = datetime.datetime.utcnow()
        date_str = t.strftime("%a, %d %b %Y %H:%M:%S GMT")  # RFC 1123
        string_to_sign = "\n".join(["GET", "", "", date_str, canonical_resource])
        sig = base64.b64encode(
            hmac.new(self.sk.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha1).digest()
        ).decode("ascii")
        return {
            "Host": host_header,
            "Date": date_str,
            "Authorization": f"AWS {self.ak}:{sig}",
        }

    def _list_once(self, params: dict):
        # canonical query string (按 key 排序, RFC3986 编码)
        pairs = sorted(((k, str(v)) for k, v in params.items() if v is not None), key=lambda x: x[0])
        encoded_query = "&".join(f"{uri_encode(k)}={uri_encode(v)}" for k, v in pairs)
        canonical_uri = "/" + uri_encode(self.bucket)
        path = canonical_uri + ("?" + encoded_query if encoded_query else "")

        # host 头带端口(非默认端口时)
        if (self.use_https and self.port == 443) or ((not self.use_https) and self.port == 80):
            host_header = self.host
        else:
            host_header = f"{self.host}:{self.port}"

        if self.sign == "v4":
            payload_hash = sha256_hex(b"")
            out_headers = self._build_headers_v4(canonical_uri, encoded_query, host_header, payload_hash)
        else:
            # V2: canonicalized resource 用原始 bucket 名 + 已排序的 name=value(value 已 URL 编码)
            canonical_resource = "/" + self.bucket + (("?" + encoded_query) if encoded_query else "")
            out_headers = self._build_headers_v2(canonical_resource, host_header)

        last_err = None
        for attempt in range(3):  # 连接断开自动重建长连接重试
            conn = self._get_conn()
            t0 = time.perf_counter()
            try:
                conn.request("GET", path, headers=out_headers)
                resp = conn.getresponse()
                body = resp.read()
                t1 = time.perf_counter()
                if resp.status != 200:
                    raise RuntimeError(f"S3 list status={resp.status} body={body[:256]!r}")
                return self._parse(body), (t1 - t0)
            except (http.client.HTTPException, ConnectionError, OSError) as e:
                last_err = e
                self._reset_conn()
                continue
        raise RuntimeError(f"request failed after retries: {last_err}")

    def list(self, prefix="", delimiter=None, token=None):
        params = {"list-type": "2"}
        if prefix:
            params["prefix"] = prefix
        if delimiter:
            params["delimiter"] = delimiter
        if token:
            params["continuation-token"] = token
        r, lat = self._list_once(params)
        self.stats.record(lat, len(r["contents"]), len(r["common_prefixes"]))
        return r

    # ----- 方法1: 子目录并发 + nextmarker 翻页 -----
    def method1(self, top_prefix: str):
        # 1) 先用 delimiter=/ 列出 top_prefix 下的所有子目录(单次调用)
        r = self.list(prefix=top_prefix, delimiter="/")
        subdirs = list(r["common_prefixes"])
        if not subdirs:
            return 0
        n_sub = len(subdirs)

        def worker(prefix: str):
            token = None
            while True:
                rr = self.list(prefix=prefix, token=token)
                if not rr["is_truncated"] or not rr["next_token"]:
                    break
                token = rr["next_token"]

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futs = [pool.submit(worker, sd) for sd in subdirs]
            for f in futs:
                f.result()
        return n_sub

    # ----- 方法2: delimiter=/ BFS 逐层列举 -----
    def method2(self, top_prefix: str):
        work = deque()
        work.append(top_prefix)
        pending = [1]
        lock = threading.Lock()
        cv = threading.Condition(lock)

        def worker():
            while True:
                with cv:
                    while not work and pending[0] > 0:
                        cv.wait()
                    if not work and pending[0] == 0:
                        return
                    prefix = work.popleft()
                try:
                    r = self.list(prefix=prefix, delimiter="/")
                    new_prefixes = r["common_prefixes"]
                except Exception:
                    with cv:
                        pending[0] -= 1
                        cv.notify_all()
                    raise
                with cv:
                    for np in new_prefixes:
                        work.append(np)
                        pending[0] += 1
                    pending[0] -= 1
                    cv.notify_all()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(self.concurrency)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()


def run_method(label, fn, *args, **kwargs):
    t0 = time.perf_counter()
    extra = fn(*args, **kwargs)
    t1 = time.perf_counter()
    return t0, t1, extra


def main():
    ap = argparse.ArgumentParser(description="S3 列举性能对比")
    ap.add_argument("--ak", required=True)
    ap.add_argument("--sk", required=True)
    ap.add_argument("--host", required=True, help="IP/域名")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--bucket", required=True, help="桶名")
    ap.add_argument("--prefix", default="", help="指定目录前缀, 如 'data/'")
    ap.add_argument("--concurrency", type=int, default=16, help="并发线程数")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--https", action="store_true", help="使用 HTTPS(默认 HTTP)")
    ap.add_argument("--sign", choices=["v2", "v4"], default="v4", help="签名版本, 默认 v4")
    args = ap.parse_args()

    print(f"目标: http{'s' if args.https else ''}://{args.host}:{args.port}/{args.bucket}"
          f"  prefix={args.prefix!r}  concurrency={args.concurrency}  sign={args.sign}")
    print()

    common = dict(host=args.host, port=args.port, bucket=args.bucket,
                  ak=args.ak, sk=args.sk, region=args.region,
                  use_https=args.https, concurrency=args.concurrency, sign=args.sign)

    # 方法1
    l1 = S3Lister(**common)
    t0, t1, n_sub = run_method("方法1", l1.method1, args.prefix)
    s = l1.stats
    print("方法1: 子目录并发 + nextmarker 翻页")
    print(f"  子目录数:     {n_sub}")
    print(f"  List 调用次数: {s.calls}")
    print(f"  List 平均时延: {s.avg_ms:.2f} ms")
    print(f"  总时延:        {(t1 - t0):.3f} s")
    print(f"  对象数:        {s.objects}   子前缀数: {s.prefixes}")
    print()

    # 方法2
    l2 = S3Lister(**common)
    t0, t1, _ = run_method("方法2", l2.method2, args.prefix)
    s = l2.stats
    print("方法2: delimiter=/ BFS 逐层列举")
    print(f"  List 调用次数: {s.calls}")
    print(f"  List 平均时延: {s.avg_ms:.2f} ms")
    print(f"  总时延:        {(t1 - t0):.3f} s")
    print(f"  对象数:        {s.objects}   子前缀数: {s.prefixes}")


if __name__ == "__main__":
    main()
