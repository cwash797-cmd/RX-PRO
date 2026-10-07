#!/usr/bin/env python3
"""Wrap a 3x-ui VLESS identity with private VK S3 settings; never change the bucket.

Reads existing Fedarisha configs OR flat storage JSON. Writes private files only.
The panel must already use the matching VLESS decryption key and plain TCP on
loopback. Ordinary VLESS encryption=none is intentionally rejected.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import urllib.parse
import uuid

VK_HOSTS = {"hb.ru-msk.vkcloud-storage.ru", "hb.vkcloud-storage.ru"}


def load_storage(path, server=False):
    data = json.loads(Path(path).read_text())
    if "storage" in data:
        data = data["storage"]
    elif "inbounds" in data or "outbounds" in data:
        section = "inbounds" if server else "outbounds"
        candidates = [i.get("settings", {}).get("storage") for i in data.get(section, [])]
        data = next((i for i in candidates if i), None)
        if data is None:
            raise ValueError("No storage settings in supplied config")
    fields = ["endpoint", "region", "bucket", "prefix", "accessKey", "secretKey"]
    result = {k: data[k] for k in fields}
    if any(not isinstance(v, str) or not v.strip() or any(c in v for c in "\r\n") for v in result.values()):
        raise ValueError("Missing or invalid storage settings")
    u = urllib.parse.urlsplit(result["endpoint"])
    if u.scheme != "https" or u.hostname not in VK_HOSTS or u.port not in (None, 443) or u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
        raise ValueError("Expected a verified VK HTTPS endpoint")
    if not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*/?", result["prefix"]):
        raise ValueError("An isolated prefix is required")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", result["bucket"]):
        raise ValueError("Invalid bucket name")
    return result


def safe_name(value):
    name = urllib.parse.unquote(value).strip()
    if (not name or len(name) > 80 or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or any(s in name.lower() for s in ("://", "%3a", "s3=", "secretkey", "accesskey"))):
        return "VK S3"
    return name


def profile(link, client, server, panel_port, encryption_override=None):
    u = urllib.parse.urlsplit(link.strip())
    if u.scheme != "vless" or not u.username or not 1 <= panel_port <= 65535:
        raise ValueError("Expected a VLESS link and valid local panel port")
    identity = str(uuid.UUID(u.username))
    q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
    if any(len(v) != 1 for v in q.values()):
        raise ValueError("Duplicate VLESS parameters")
    get = lambda name, default="": q.get(name, [default])[0]
    if get("type", "tcp") not in ("tcp", "raw") or get("security", "none") != "none" or get("flow"):
        raise ValueError("Create a separate loopback VLESS TCP inbound without TLS, REALITY, Vision or WS")
    encryption = (encryption_override or get("encryption")).strip()
    # Prefer replay-resistant first contact for the object-store transport.
    encryption = encryption.replace(".0rtt.", ".1rtt.")
    if not encryption.startswith("mlkem768x25519plus.") or ".1rtt." not in encryption:
        raise ValueError("VLESS Encryption is mandatory: provide the public encryption value paired with the panel decryption key")
    for k in ["endpoint", "bucket", "region"]:
        if client[k].rstrip("/") != server[k].rstrip("/"):
            raise ValueError("Client/server storage endpoints must match")
    if not (client["prefix"].rstrip("/")+"/").startswith(server["prefix"].rstrip("/")+"/"):
        raise ValueError("Client prefix must be within server scope")
    prefix = client["prefix"].rstrip("/")

    def stream(storage):
        creds = {k: v for k, v in storage.items() if k != "prefix"}
        return {"network": "xdrive", "security": "none", "xdriveSettings": {
            "service": "S3", "remoteFolder": prefix, "secrets": [json.dumps(creds, separators=(",", ":"))],
            "segmentBytes": 262144, "flushIntervalMs": 30, "pollIntervalMs": 150,
            "maxPollIntervalMs": 1200, "concurrency": 4, "sessionTtlSeconds": 300}}

    bridge = {"log": {"loglevel": "warning"}, "inbounds": [{"tag": "s3-input",
        "listen": "127.0.0.1", "port": 11600, "protocol": "dokodemo-door",
        "settings": {"address": "127.0.0.1", "port": panel_port, "network": "tcp"},
        "streamSettings": stream(server)}], "outbounds": [{"protocol": "freedom", "settings": {
            "finalRules": [{"action": "allow", "network": "tcp", "ip": ["127.0.0.1"], "port": str(panel_port)},
                           {"action": "block"}]}}]}
    host = urllib.parse.urlsplit(client["endpoint"]).hostname
    node_stream = stream(client)
    node_stream.update(address=host, port=443)
    pc = {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": 10808,
        "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}], "outbounds": [{
        "protocol": "vless", "settings": {"vnext": [{"address": host, "port": 443,
        "users": [{"id": identity, "encryption": encryption}]}]}, "streamSettings": node_stream,
        "mux": {"enabled": True, "concurrency": 8}}]}
    payload = dict(client, version=1, prefix=prefix)
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    params = urllib.parse.urlencode({"type": "xdrive", "service": "s3", "encryption": encryption, "s3": encoded})
    name = urllib.parse.quote(safe_name(u.fragment), safe="")
    return f"vless://{identity}@{host}:443?{params}#{name}", bridge, pc


def write_private(path, value):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(value)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--client-storage", required=True)
    p.add_argument("--server-storage", required=True)
    p.add_argument("--vless-link-file", required=True)
    p.add_argument("--encryption-file", help="Optional file containing public VLESS encryption value, NOT the server private key")
    p.add_argument("--panel-port", type=int, default=10001)
    p.add_argument("--output", required=True, help="New private directory; existing directories are never overwritten")
    a = p.parse_args()
    try:
        client = load_storage(a.client_storage)
        server = load_storage(a.server_storage, True)
        enc = Path(a.encryption_file).read_text().strip() if a.encryption_file else None
        link, bridge, pc = profile(Path(a.vless_link_file).read_text(), client, server, a.panel_port, enc)
        out = Path(a.output)
        out.mkdir(mode=0o700, parents=False, exist_ok=False)
        write_private(out / "rxpro-link.txt", link + "\n")
        write_private(out / "server.json", json.dumps(bridge, indent=2) + "\n")
        write_private(out / "client-core.json", json.dumps(pc, indent=2) + "\n")
        print("Created private rxpro-link.txt, server.json and client-core.json in", out)
        print("No network requests or changes to VK or 3x-ui were made. Do not share these files publicly.")
    except (ValueError, KeyError, TypeError, OSError) as exc:
        # Never echo input configs/links, JSON parser snippets, or credentials.
        if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError):
            print("Configuration rejected:", str(exc) if len(str(exc)) < 250 else "invalid configuration")
        else:
            print("Input/output error:", type(exc).__name__)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
