#!/usr/bin/env python3
"""Package only published Windows files and license notices, never local profiles."""
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'windows/artifacts'
APP = OUT / 'app'
VERSION = '0.1.0'


def main():
    files = sorted(p for p in APP.rglob('*') if p.is_file() and p != APP / 'SOURCE.json')
    assert (APP / 'RX-PRO Windows.exe').is_file() and (APP / 'core/xray-s3.exe').is_file()
    for p in files:
        assert not p.is_symlink() and p.suffix.lower() not in ('.dpapi', '.pdb', '.sqlite', '.key', '.pem')
    source = {'version': VERSION, 'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
              'xray_commit': 'b26a91de4f3294e26a0ad0a970b81a386a41f789', 'unsigned': True,
              'files': {str(p.relative_to(APP)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}}
    (APP / 'SOURCE.json').write_text(json.dumps(source, indent=2), encoding='utf-8')
    files = sorted(p for p in APP.rglob('*') if p.is_file())
    archive = OUT / f'RX-PRO-Windows-{VERSION}-x64.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in files:
            info = zipfile.ZipInfo('RX-PRO Windows/' + str(p.relative_to(APP)).replace('\\', '/'), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, p.read_bytes())
    (OUT / 'SHA256SUMS.txt').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')
    print('Packaged:', archive.name)


if __name__ == '__main__': main()
