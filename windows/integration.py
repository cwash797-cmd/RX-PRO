#!/usr/bin/env python3
"""Windows-only disposable CI: actual packaged core through TLS/SigV4 and VLESS.
All credentials/certificates are synthetic. Never use this on a personal machine.
"""
import concurrent.futures
import ctypes
import hashlib
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('fixture', ROOT / 'tools/integration_s3.py')
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
APP = ROOT / 'windows/artifacts/app'
BINARY = APP / 'core/xray-s3.exe'
HARNESS = ROOT / 'windows/RxPro.Tests/bin/Release/net10.0-windows/RxPro.Tests.dll'
BODY = b'RX-PRO-Windows-S3-fixture\n' * 12000


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]


def stage(name):
    print('STAGE: ' + name, flush=True)


def powershell(text):
    return subprocess.check_output(['pwsh', '-NoProfile', '-NonInteractive', '-Command',
                                    '$ErrorActionPreference=\'Stop\'; ' + text], text=True, timeout=30).strip()


class BoundedServer(http.server.ThreadingHTTPServer):
    # Never perform the TLS handshake in accept()/the serve_forever thread:
    # one incomplete handshake must not prevent server.shutdown() from returning.
    def __init__(self, address, handler, tls=None):
        self.tls = tls
        self.tls_failures = 0
        super().__init__(address, handler)

    def process_request_thread(self, request, address):
        request.settimeout(10)
        if self.tls is not None:
            try:
                request = self.tls.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError):
                self.tls_failures += 1
                request.close()
                return
        super().process_request_thread(request, address)

    def handle_error(self, request, address):
        # Test credentials must never appear in HTTP server tracebacks.
        print('FIXTURE: request handler failed', flush=True)


class Target(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Length', str(len(BODY))); self.end_headers()
        self.wfile.write(BODY)


def main():
    if sys.platform != 'win32' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('Refusing trust-store/proxy fixtures outside disposable Windows CI')
    root = ROOT / '.lab'; root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root, prefix='windows-integration-') as tmp:
        work = Path(tmp); processes = []; servers = []; thumbprint = None
        stage('create ephemeral TLS certificate')
        try:
            openssl = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/usr/bin/openssl.exe'
            subprocess.run([str(openssl), 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-keyout', str(work / 'key.pem'), '-out', str(work / 'ca.pem'), '-subj', '/CN=s3-lab.invalid',
                '-addext', 'subjectAltName=DNS:s3-lab.invalid'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            # CurrentUser Root insertion can show a native Windows trust-confirmation
            # dialog, even with pwsh -NonInteractive. This disposable elevated runner
            # uses certutil -f and LocalMachine Root; production trust stays unchanged.
            thumbprint = hashlib.sha1(ssl.PEM_cert_to_DER_cert((work / 'ca.pem').read_text())).hexdigest()
            stage('trust fixture CA in disposable machine store')
            subprocess.run(['certutil', '-f', '-addstore', 'Root', str(work / 'ca.pem')],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            stage('start bounded local TLS object store')
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(work / 'ca.pem', work / 'key.pem')
            store = BoundedServer(('127.0.0.1', 0), fixture.Store, tls)
            target = BoundedServer(('127.0.0.1', 0), Target)
            servers = [store, target]
            for server in servers: threading.Thread(target=server.serve_forever, daemon=True).start()
            stage('generate ephemeral VLESS key pair')
            keys = subprocess.check_output([str(BINARY), 'vlessenc'], text=True, stderr=subprocess.DEVNULL, timeout=30)
            dec = re.search(r'"decryption": "([^"]+)"', keys)[1]
            enc = re.search(r'"encryption": "([^"]+)"', keys)[1].replace('.0rtt.', '.1rtt.')
            panel_port, http_port, socks_port = free_port(), free_port(), free_port()
            identity = str(uuid.uuid4())
            storage = dict(endpoint='https://hb.ru-msk.vkcloud-storage.ru', region='ru-msk', bucket='test-bucket',
                           prefix='probe-tests/data/device1', accessKey='CLIENT', secretKey=fixture.SECRETS['CLIENT'])
            server_storage = dict(storage, accessKey='SERVER', secretKey=fixture.SECRETS['SERVER'])
            link, bridge, _ = fixture.profile(f'vless://{identity}@127.0.0.1:{panel_port}?type=tcp&encryption={enc}', storage, server_storage, panel_port)
            request = {'link': link, 'output': str(work / 'client.json'), 'http': http_port, 'socks': socks_port}
            (work / 'request.json').write_text(json.dumps(request))
            stage('import manager link with production C# parser')
            subprocess.run(['dotnet', str(HARNESS), '--fixture-config', str(work / 'request.json')], check=True, timeout=30)
            client = json.loads((work / 'client.json').read_text())
            # Only the test changes endpoint/mapping to local TLS; production import cannot do this.
            for config, section in [(bridge, 'inbounds'), (client, 'outbounds')]:
                stream = config[section][0]['streamSettings']
                secret = json.loads(stream['xdriveSettings']['secrets'][0]); secret['endpoint'] = 'https://s3-lab.invalid'
                stream['xdriveSettings']['secrets'] = [json.dumps(secret)]
                stream.update(address='127.0.0.1', port=store.server_port)
            panel = {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': panel_port,
                'protocol': 'vless', 'settings': {'clients': [{'id': identity}], 'decryption': dec}}],
                'outbounds': [{'protocol': 'freedom', 'settings': {'finalRules': [
                    {'action': 'allow', 'network': 'tcp', 'ip': ['127.0.0.1'], 'port': str(target.server_port)}, {'action': 'block'}]}}]}
            stage('start native panel and S3 bridge')
            for config in (panel, bridge):
                process = subprocess.Popen([str(BINARY), 'run', '-format', 'json', '-config', 'stdin:'],
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                processes.append(process); process.stdin.write(json.dumps(config).encode()); process.stdin.close()
            (work / 'client.json').write_text(json.dumps(client))
            serve = {'binary': str(BINARY), 'config': str(work / 'client.json'), 'http': http_port, 'socks': socks_port, 'ready': str(work / 'ready'), 'snapshot': str(work / 'proxy-before.json')}
            (work / 'serve.json').write_text(json.dumps(serve))
            stage('start production CoreHost and journal system proxy')
            owner = subprocess.Popen(['dotnet', str(HARNESS), '--serve-fixture', str(work / 'serve.json')], stdin=subprocess.PIPE)
            processes.append(owner)
            for _ in range(100):
                if (work / 'ready').exists(): break
                if owner.poll() is not None: raise RuntimeError('Production CoreHost failed to start')
                time.sleep(.2)
            else: raise RuntimeError('Production CoreHost readiness timeout')
            stage('start packaged recovery watchdog')
            ready = json.loads((work / 'ready').read_text())
            watcher = subprocess.Popen([str(APP / 'RX-PRO Windows.exe'), '--watchdog', str(owner.pid), str(ready['ownerTicks'])])
            processes.append(watcher)
            time.sleep(.5)
            assert watcher.poll() is None, 'Recovery watchdog failed before test'
            def download(_):
                connection = http.client.HTTPConnection('127.0.0.1', http_port, timeout=60)
                try:
                    connection.request('GET', f'http://127.0.0.1:{target.server_port}/')
                    response = connection.getresponse(); body = response.read()
                    assert response.status == 200 and hashlib.sha256(body).digest() == hashlib.sha256(BODY).digest()
                finally: connection.close()
            stage('download through TLS, SigV4 and encrypted VLESS')
            download(0)
            stage('four concurrent downloads')
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: list(pool.map(download, range(4)))
            assert fixture.COUNTS['signed_requests'] > 0 and fixture.COUNTS['denied'] == 0
            print('PASS: manager-generated link -> C# importer/config -> production CoreHost stdin -> Windows S3/SigV4/TLS -> encrypted VLESS; four parallel HTTP downloads')
            # Kill the owner abruptly: its Job Object must kill the credential-bearing core.
            stage('kill owner and verify proxy recovery')
            core_pid = ready['corePid']; owner.kill(); owner.wait(timeout=10)
            assert watcher.wait(timeout=15) == 0
            subprocess.run(['dotnet', str(HARNESS), '--check-proxy-snapshot', str(work / 'proxy-before.json')], check=True, timeout=30)
            time.sleep(1)
            running = powershell(f"[bool](Get-Process -Id {core_pid} -ErrorAction SilentlyContinue)")
            assert running == 'False', 'Orphan core survived abrupt owner termination'
            print('PASS: abrupt owner termination kills Windows core via Job Object')
            # Launch the exact portable EXE, wait for a real WPF window, then close normally.
            stage('open and close packaged WPF window')
            gui = subprocess.Popen([str(APP / 'RX-PRO Windows.exe')]); processes.append(gui)
            user32 = ctypes.windll.user32
            user32.FindWindowW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
            user32.FindWindowW.restype = ctypes.c_void_p
            user32.PostMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t]
            user32.PostMessageW.restype = ctypes.c_int
            user32.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
            handle = None
            for _ in range(100):
                handle = user32.FindWindowW(None, 'RX-PRO Windows · S3')
                if handle: break
                if gui.poll() is not None: raise RuntimeError('Packaged GUI exited before showing window')
                time.sleep(.2)
            assert handle, 'Packaged WPF window not found'
            window_pid = ctypes.c_uint32()
            user32.GetWindowThreadProcessId(handle, ctypes.byref(window_pid))
            assert window_pid.value == gui.pid, 'Found a different process window'
            assert user32.PostMessageW(handle, 0x0010, 0, 0), 'WM_CLOSE was not queued'
            assert gui.wait(timeout=15) == 0
            print('PASS: packaged self-contained WPF executable opens and closes normally')
        finally:
            stage('cleanup children, proxy and fixture certificate')
            cleanup_errors = []
            for p in reversed(processes):
                try:
                    if p.poll() is None: p.kill(); p.wait(timeout=10)
                except (OSError, subprocess.TimeoutExpired): cleanup_errors.append('child process')
            if (work / 'proxy-before.json').exists():
                try:
                    subprocess.run(['dotnet', str(HARNESS), '--restore-proxy-snapshot', str(work / 'proxy-before.json')],
                                   check=True, timeout=30)
                except (OSError, subprocess.SubprocessError): cleanup_errors.append('proxy restore')
            for server in servers:
                server.shutdown(); server.server_close()
            if thumbprint and re.fullmatch('[0-9A-Fa-f]{40}', thumbprint):
                try:
                    subprocess.run(['certutil', '-delstore', 'Root', thumbprint], check=True,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                except (OSError, subprocess.SubprocessError): cleanup_errors.append('certificate removal')
            print('FIXTURE COUNTS:', dict(fixture.COUNTS), flush=True)
            if cleanup_errors: raise RuntimeError('Cleanup failed: ' + ', '.join(cleanup_errors))



if __name__ == '__main__': main()
