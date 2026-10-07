#!/usr/bin/env python3
"""Ephemeral local TLS/SigV4 object-store model -> bridge -> stock VLESS test.
Not a VK, Android-device, or mobile-allowlist test. All artifacts stay in .lab.
"""
import concurrent.futures
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import re
import select
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import transport_lab as lab
from s3_profile import profile

WORK = ROOT / ".lab" / "s3-integration"
BIN = ROOT / ".lab/bin/xray-s3"
STORE_PORT, MAP_PORT, PANEL_PORT = 18443, 18444, 18445
OBJECTS = {}
LOCK = threading.Lock()
COUNTS = {"signed_requests": 0, "mapping_connections": 0, "denied": 0}
SECRETS = {"CLIENT": "client-fixture-secret", "SERVER": "server-fixture-secret"}


def mac(key, text):
    return hmac.new(key, text.encode(), hashlib.sha256).digest()


def verify(req, body):
    auth = req.headers.get("Authorization", "")
    m = re.fullmatch(r"AWS4-HMAC-SHA256 Credential=([^/]+)/([^,]+), SignedHeaders=([^,]+), Signature=([0-9a-f]+)", auth)
    if not m or m[1] not in SECRETS:
        return False
    date, region, service, terminal = m[2].split("/")
    if region != "ru-msk" or service != "s3" or terminal != "aws4_request":
        return False
    parsed = urllib.parse.urlsplit(req.path)
    q = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    enc = lambda s: urllib.parse.quote(s, safe="-_.~")
    query = "&".join(enc(k) + "=" + enc(v) for k, v in sorted(q))
    headers = "".join(k + ":" + " ".join(req.headers.get(k, "").split()) + "\n" for k in m[3].split(";"))
    digest = hashlib.sha256(body).hexdigest()
    canonical = "\n".join([req.command, parsed.path, query, headers, m[3], digest])
    sts = "\n".join(["AWS4-HMAC-SHA256", req.headers.get("X-Amz-Date", ""), m[2], hashlib.sha256(canonical.encode()).hexdigest()])
    key = mac(("AWS4" + SECRETS[m[1]]).encode(), date)
    for value in [region, service, terminal]:
        key = mac(key, value)
    return hmac.compare_digest(mac(key, sts).hex(), m[4]) and req.headers.get("X-Amz-Content-Sha256") == digest


class Store(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *_):
        pass
    def handle(self):
        try:
            super().handle()
        except (ConnectionError, OSError):
            pass
    def reply(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def operation(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 1024 * 1024:
            return self.reply(413)
        body = self.rfile.read(length)
        if not verify(self, body):
            COUNTS["denied"] += 1
            return self.reply(403)
        COUNTS["signed_requests"] += 1
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/test-bucket" and self.command == "GET":
            prefix = q.get("prefix", [""])[0]
            if not prefix.startswith("probe-tests/data/device1/"):
                return self.reply(403)
            delimiter = q.get("delimiter", [""])[0]
            with LOCK:
                keys = sorted(k for k in OBJECTS if k.startswith(prefix))
            files, folders = [], set()
            for key in keys:
                rest = key[len(prefix):]
                if delimiter and delimiter in rest:
                    folders.add(prefix + rest.split(delimiter)[0] + delimiter)
                else:
                    files.append(key)
            result = '<ListBucketResult><IsTruncated>false</IsTruncated>'
            result += ''.join('<Contents><Key>' + escape(k) + '</Key></Contents>' for k in files)
            result += ''.join('<CommonPrefixes><Prefix>' + escape(k) + '</Prefix></CommonPrefixes>' for k in sorted(folders))
            return self.reply(200, (result + '</ListBucketResult>').encode())
        key = urllib.parse.unquote(u.path).removeprefix("/test-bucket/")
        if not key.startswith("probe-tests/data/device1/"):
            return self.reply(403)
        with LOCK:
            if self.command == "PUT":
                OBJECTS[key] = body
                code, result = 200, b""
            elif self.command == "GET":
                code, result = (200, OBJECTS[key]) if key in OBJECTS else (404, b"")
            elif self.command == "DELETE":
                OBJECTS.pop(key, None)
                code, result = 204, b""
            else:
                code, result = 405, b""
        self.reply(code, result)
    do_GET = operation
    do_PUT = operation
    do_DELETE = operation


class Mapping(socketserver.BaseRequestHandler):
    def handle(self):
        COUNTS["mapping_connections"] += 1
        with socket.create_connection(("127.0.0.1", STORE_PORT), timeout=10) as upstream:
            sockets = [self.request, upstream]
            try:
                while True:
                    ready, _, _ = select.select(sockets, [], [], 30)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is self.request else self.request).sendall(data)
            except OSError:
                pass


def launch(name, config, binary=BIN):
    path = WORK / (name + ".json")
    path.write_text(json.dumps(config))
    env = dict(os.environ, SSL_CERT_FILE=str(WORK / "ca.pem"), GOMEMLIMIT="128MiB")
    log = (WORK / (name + ".log")).open("wb")
    p = subprocess.Popen([str(binary), "run", "-c", str(path)], env=env, stdout=log, stderr=log)
    log.close()
    time.sleep(.5)
    if p.poll() is not None:
        raise RuntimeError(name + " failed to start; inspect private local log")
    return p


def main():
    os.umask(0o077)
    WORK.mkdir(parents=True, exist_ok=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", str(WORK / "key.pem"),
        "-out", str(WORK / "ca.pem"), "-subj", "/CN=s3-lab.invalid", "-addext", "subjectAltName=DNS:s3-lab.invalid"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    store = http.server.ThreadingHTTPServer(("127.0.0.1", STORE_PORT), Store)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(WORK / "ca.pem", WORK / "key.pem")
    store.socket = tls.wrap_socket(store.socket, server_side=True)
    lab.SOCKS_PORT, lab.TARGET_PORT = 18488, 18489
    mapping = lab.TCPServer(("127.0.0.1", MAP_PORT), Mapping)
    echo = lab.TCPServer(("127.0.0.1", lab.TARGET_PORT), lab.Echo)
    for server in [store, mapping, echo]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    keys = subprocess.check_output([str(BIN), "vlessenc"], text=True)
    decryption = re.search(r'"decryption": "([^"]+)"', keys)[1]
    encryption = re.search(r'"encryption": "([^"]+)"', keys)[1].replace(".0rtt.", ".1rtt.")
    identity = str(uuid.uuid4())
    storage = dict(endpoint="https://hb.ru-msk.vkcloud-storage.ru", region="ru-msk", bucket="test-bucket",
                   prefix="probe-tests/data/device1", accessKey="CLIENT", secretKey=SECRETS["CLIENT"])
    server_storage = dict(storage, prefix="probe-tests/data", accessKey="SERVER", secretKey=SECRETS["SERVER"])
    _, bridge, client = profile(f"vless://{identity}@127.0.0.1:{PANEL_PORT}?type=tcp&encryption={encryption}", storage, server_storage, PANEL_PORT)
    # Only fixture endpoints change: production generator always targets VK.
    for config, section, port in [(bridge, "inbounds", STORE_PORT), (client, "outbounds", MAP_PORT)]:
        stream = config[section][0]["streamSettings"]
        secret = json.loads(stream["xdriveSettings"]["secrets"][0])
        secret["endpoint"] = "https://s3-lab.invalid"
        stream["xdriveSettings"]["secrets"] = [json.dumps(secret)]
        stream.update(address="127.0.0.1", port=port)
        stream["xdriveSettings"].update(pollIntervalMs=20, maxPollIntervalMs=100)
    client["inbounds"][0]["port"] = lab.SOCKS_PORT
    panel = {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": PANEL_PORT, "protocol": "vless",
        "settings": {"clients": [{"id": identity}], "decryption": decryption}}], "outbounds": [{"protocol": "freedom", "settings": {
        "finalRules": [{"action": "allow", "network": "tcp", "ip": ["127.0.0.1"], "port": str(lab.TARGET_PORT)}]}}]}
    processes = []
    report = {"scope": "LOCAL_TLS_SIGV4_MODEL_NOT_VK_OR_ANDROID", "tests": []}
    try:
        processes.append(launch("panel", panel, ROOT / ".lab/xray"))
        processes.append(launch("bridge", bridge))
        processes.append(launch("client", client))
        for size in [4096, 1048576]:
            report["tests"].append({"name": "encrypted_vless_through_native_s3_and_panel", **lab.roundtrip(size)})
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lab.roundtrip, [65536] * 4))
        report["tests"].append({"name": "four_parallel_sessions", "passed": True})
        r = subprocess.run(["curl", "--silent", "--show-error", "--fail", "--noproxy", "", "--proxy", f"socks5h://127.0.0.1:{lab.SOCKS_PORT}", "--max-time", "30", "https://example.com/"], capture_output=True, timeout=35)
        assert r.returncode == 0 and b"Example Domain" in r.stdout
        report["tests"].append({"name": "external_https", "passed": True})
        assert COUNTS["signed_requests"] > 0 and COUNTS["mapping_connections"] > 0 and COUNTS["denied"] == 0
        report["counts"] = dict(COUNTS)
        report["all_passed"] = True
        (WORK / "results.json").write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
    finally:
        for p in reversed(processes):
            lab.stop(p)
        for server in [store, mapping, echo]:
            server.shutdown(); server.server_close()


if __name__ == "__main__":
    main()
