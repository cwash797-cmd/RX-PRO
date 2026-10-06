#!/usr/bin/env python3
"""Reproducible stock-Xray experiments against a local object-store model.

NOT a VK integration test, production proxy, or implementation of AWS IAM.
Run from this directory: python3 transport_lab.py
The HTTP listener is loopback-only. /healthz exposes only redacted results.
All generated files and ephemeral credentials stay in .lab/ (mode 0700).
"""
import concurrent.futures
import copy
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import struct
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent
WORK = ROOT / ".lab"
XRAY = WORK / "xray"
STORE_PORT = 18080
SOCKS_PORT = 18088
TARGET_PORT = 18089
TOKEN = secrets.token_hex(32)
PREFIX = "cap/" + secrets.token_hex(32) + "/"
LOCK = threading.Lock()
OBJECTS = {}
COUNTS = {}
SAMPLES = []
TRACE = []
RESULTS = {"scope": "LOCAL_MODEL_ONLY_NOT_VK_OR_MOBILE_NETWORK", "tests": []}
PUBLIC_MARKER = b"xdrive-lab-plaintext-marker-" + secrets.token_bytes(16)


def record(name, passed, **details):
    row = {"name": name, "passed": bool(passed), **details}
    RESULTS["tests"].append(row)
    print(json.dumps(row), flush=True)


class Store(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def reply(self, status, body=b"", content_type="application/octet-stream"):
        with LOCK:
            path = urllib.parse.urlsplit(self.path).path
            if path != "/bucket":
                TRACE.append({"method": self.command, "path": path.replace(PREFIX, "REDACTED/"),
                              "status": status, "bytes": len(body), "request_bytes": self.headers.get("Content-Length")})
                if len(TRACE) > 1000:
                    del TRACE[0]
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", content_type)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def handle_op(self):
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        method = self.command
        with LOCK:
            COUNTS[method] = COUNTS.get(method, 0) + 1
        if parsed.path == "/healthz" and method == "GET":
            return self.reply(200, json.dumps(RESULTS).encode(), "application/json")
        # The target endpoint is never proxied here: this service only stores bytes.
        length = int(self.headers.get("Content-Length", "0"))
        if length > 8 * 1024 * 1024:
            self.close_connection = True
            return self.reply(413)
        body = self.rfile.read(length)
        if parsed.path == "/bucket" and method == "GET":
            # Static restricted-list capability, NOT a real AWS signature validator.
            if query.get("token") != [TOKEN] or query.get("prefix") != [PREFIX]:
                return self.reply(403)
            with LOCK:
                keys = sorted(k for k in OBJECTS if k.startswith(PREFIX))
            xml = "<ListBucketResult><IsTruncated>false</IsTruncated>" + "".join(
                "<Contents><Key>" + key + "</Key></Contents>" for key in keys
            ) + "</ListBucketResult>"
            return self.reply(200, xml.encode(), "application/xml")
        key = parsed.path.removeprefix("/bucket/")
        # Explicit capability-prefix model; no claim VK accepts this policy yet.
        if not parsed.path.startswith("/bucket/") or not key.startswith(PREFIX):
            return self.reply(403)
        with LOCK:
            if method == "PUT":
                OBJECTS[key] = body
                SAMPLES.append(body)
                result = (200, b"")
            elif method == "GET":
                result = (200, OBJECTS[key]) if key in OBJECTS else (404, b"")
            elif method == "DELETE":
                OBJECTS.pop(key, None)
                result = (204, b"")
            else:
                result = (405, b"")
        self.reply(*result)

    do_GET = handle_op
    do_PUT = handle_op
    do_DELETE = handle_op
    do_POST = handle_op
    do_CONNECT = handle_op


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except (TimeoutError, ConnectionError, OSError):
            pass


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def exact(sock, size):
    parts = bytearray()
    while len(parts) < size:
        data = sock.recv(size - len(parts))
        if not data:
            raise EOFError("proxy stream closed")
        parts.extend(data)
    return bytes(parts)


def connect_proxy():
    sock = socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=15)
    try:
        sock.sendall(b"\x05\x01\x00")
        assert exact(sock, 2) == b"\x05\x00"
        sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", TARGET_PORT))
        header = exact(sock, 4)
        assert header[1] == 0, "SOCKS connect failed"
        addr_len = {1: 4, 4: 16}.get(header[3])
        if header[3] == 3:
            addr_len = exact(sock, 1)[0]
        exact(sock, addr_len + 2)
        return sock
    except BaseException:
        sock.close()
        raise


def roundtrip(size):
    payload = PUBLIC_MARKER + os.urandom(size - len(PUBLIC_MARKER))
    start = time.monotonic()
    with connect_proxy() as sock:
        # Alternating request/response proves interactivity, not just file copying.
        received = bytearray()
        for start_byte in range(0, size, 65536):
            block = payload[start_byte:start_byte + 65536]
            sock.sendall(block)
            received.extend(exact(sock, len(block)))
        assert received == payload, "payload mismatch"
    return {"bytes_each_direction": size, "seconds": round(time.monotonic() - start, 3),
            "sha256": hashlib.sha256(payload).hexdigest()}


def settings(transport):
    base = f"http://127.0.0.1:{STORE_PORT}"
    if transport == "xhttp":
        return {"network": "xhttp", "security": "none", "xhttpSettings": {
            "mode": "packet-up", "path": "/bucket/" + PREFIX,
            "extra": {"uplinkHTTPMethod": "PUT", "scMinPostsIntervalMs": 10}}}
    return {"network": "xdrive", "security": "none", "xdriveSettings": {
        "service": "template", "remoteFolder": PREFIX.rstrip("/"), "secrets": [TOKEN],
        "segmentBytes": 262144, "flushIntervalMs": 10, "pollIntervalMs": 10,
        "maxPollIntervalMs": 50, "concurrency": 4, "sessionTtlSeconds": 30,
        "template": {"flatten": True, "concurrency": 8, "auth": {"type": "none"},
            "put": {"method": "PUT", "url": base + "/bucket/{folder}/{name}"},
            "get": {"method": "GET", "url": base + "/bucket/{folder}/{name}"},
            "delete": {"method": "DELETE", "url": base + "/bucket/{folder}/{name}"},
            "list": {"method": "GET", "url": base + "/bucket?prefix=" + PREFIX + "&token={secret0}",
                     "namesRegex": "<Key>" + PREFIX + "([^<]+)</Key>"},
            "retry": {"status": [429, 500, 502, 503]}}}}


def save(name, value):
    path = WORK / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(value, f, indent=2)
    return path


def config_pair(transport="xdrive", encrypted=True):
    identity = str(uuid.uuid4())
    encryption = decryption = "none"
    if encrypted:
        output = subprocess.check_output([str(XRAY), "vlessenc"], text=True)
        decryption = re.search(r'"decryption": "([^"]+)"', output).group(1)
        encryption = re.search(r'"encryption": "([^"]+)"', output).group(1).replace(".0rtt.", ".1rtt.")
    stream = settings(transport)
    server = {"log": {"loglevel": "warning"}, "inbounds": [{
        "listen": "127.0.0.1", "port": 18100, "protocol": "vless",
        "settings": {"clients": [{"id": identity}], "decryption": decryption},
        "streamSettings": stream}], "outbounds": [{"protocol": "freedom", "settings": {
            # v26.9.30 blocks loopback by default. Permit ONLY the lab echo port.
            # This exception must never be copied into a production exit config.
            "finalRules": [{"action": "allow", "network": "tcp", "ip": ["127.0.0.1"],
                            "port": str(TARGET_PORT)}]}}]}
    client = {"log": {"loglevel": "warning"}, "inbounds": [{
        "listen": "127.0.0.1", "port": SOCKS_PORT, "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False}}], "outbounds": [{
        "protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": STORE_PORT,
        "users": [{"id": identity, "encryption": encryption}]}]},
        "streamSettings": copy.deepcopy(stream), "mux": {"enabled": True, "concurrency": 8}}]}
    return server, client


def launch(name, config):
    path = save(name + ".json", config)
    log = open(WORK / (name + ".log"), "wb")
    process = subprocess.Popen([str(XRAY), "run", "-c", str(path)], stdout=log, stderr=subprocess.STDOUT)
    log.close()
    time.sleep(0.6)
    if process.poll() is not None:
        raise RuntimeError(name + " failed; inspect private .lab log")
    return process


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def run_tests():
    RESULTS["core"] = subprocess.check_output([str(XRAY), "version"], text=True).splitlines()[0]
    server, client = config_pair(encrypted=os.environ.get("LAB_PLAINTEXT") != "1")
    if os.environ.get("LAB_NO_MUX") == "1":
        client["outbounds"][0]["mux"]["enabled"] = False
    RESULTS["encrypted"] = os.environ.get("LAB_PLAINTEXT") != "1"
    RESULTS["mux"] = client["outbounds"][0]["mux"]["enabled"]
    procs = []
    try:
        procs.append(launch("xdrive-server", server))
        procs.append(launch("xdrive-client", client))
        for size in [4096, 1048576, 5242880]:
            record("vless_xdrive_echo", True, encrypted=RESULTS["encrypted"], **roundtrip(size))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            values = list(pool.map(roundtrip, [65536] * 8))
        record("eight_parallel_connections", len(values) == 8, results=values)
        # No local destination test can establish German egress. This only tests
        # stock core proxying a real external HTTPS request through the model.
        result = subprocess.run(["curl", "--silent", "--show-error", "--fail", "--noproxy", "",
            "--proxy", f"socks5h://127.0.0.1:{SOCKS_PORT}", "--max-time", "30", "https://example.com/"],
            capture_output=True, timeout=35)
        record("external_https_via_object_model", result.returncode == 0 and b"Example Domain" in result.stdout,
               curl_exit=result.returncode, response_bytes=len(result.stdout))
        with LOCK:
            visible = any(PUBLIC_MARKER in item for item in SAMPLES)
            operations = dict(COUNTS)
        record("object_payload_encryption_control", visible != RESULTS["encrypted"],
               plaintext_marker_visible=visible, encrypted=RESULTS["encrypted"], operations=operations)
        stop(procs.pop())
        # The same client, but without a functioning list capability, must not
        # silently turn into a direct connection.
        bad = copy.deepcopy(client)
        bad["outbounds"][0]["streamSettings"]["xdriveSettings"]["secrets"] = ["wrong-token"]
        procs.append(launch("denied-client", bad))
        try:
            roundtrip(4096)
            denied = False
        except (TimeoutError, EOFError, OSError, AssertionError):
            denied = True
        record("invalid_storage_capability_no_fallback", denied)
        stop(procs.pop())
    finally:
        save("trace.json", TRACE)
        for p in reversed(procs):
            stop(p)

    # Packet-up can issue PUT, but stock XHTTP requires a streaming downlink.
    _, client = config_pair("xhttp", encrypted=False)
    client["outbounds"][0]["mux"]["enabled"] = False
    p = launch("xhttp-client", client)
    before = dict(COUNTS)
    try:
        try:
            roundtrip(4096)
            failed = False
        except (TimeoutError, EOFError, OSError, AssertionError):
            failed = True
        time.sleep(0.2)
        record("xhttp_put_with_object_get_fails_as_expected", failed,
               operation_delta={k: v - before.get(k, 0) for k, v in COUNTS.items()})
    finally:
        stop(p)

    with urllib.request.urlopen(f"http://127.0.0.1:{STORE_PORT}/healthz") as r:
        assert r.status == 200
    RESULTS["all_passed"] = all(t["passed"] for t in RESULTS["tests"])
    save("results.json", RESULTS)
    print("LAB_COMPLETE all_passed=" + str(RESULTS["all_passed"]), flush=True)


def main():
    os.umask(0o077)
    WORK.mkdir(mode=0o700, exist_ok=True)
    os.chmod(WORK, 0o700)
    if not XRAY.is_file():
        raise SystemExit("Place verified official Xray v26.9.30 at .lab/xray first")
    store = http.server.ThreadingHTTPServer(("127.0.0.1", STORE_PORT), Store)
    echo = TCPServer(("127.0.0.1", TARGET_PORT), Echo)
    for srv in (store, echo):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"LAB_READY HTTP={STORE_PORT}; waiting for .lab/start", flush=True)
    try:
        for _ in range(1200):
            if (WORK / "start").exists():
                break
            time.sleep(0.1)
        else:
            raise TimeoutError("start signal not received")
        try:
            run_tests()
        except Exception as exc:
            RESULTS["error"] = type(exc).__name__ + ": " + str(exc)
            RESULTS["object_sizes"] = {k.replace(PREFIX, "REDACTED/"): len(v) for k, v in OBJECTS.items()}
            RESULTS["operations"] = dict(COUNTS)
            RESULTS["all_passed"] = False
            save("results.json", RESULTS)
            print(json.dumps({"LAB_FAILED": RESULTS["error"]}), flush=True)
        # Leave a redacted results page available, not a public proxy.
        threading.Event().wait()
    finally:
        store.shutdown()
        echo.shutdown()


if __name__ == "__main__":
    main()
