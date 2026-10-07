#!/usr/bin/env python3
"""Build Windows core in a separate disposable workspace; never run Android targets."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / '.lab/windows-native'
spec = importlib.util.spec_from_file_location('pinned_s3_build', ROOT / 's3-core/build.py')
upstream = importlib.util.module_from_spec(spec); spec.loader.exec_module(upstream)
# The imported helper's default cwd was bound at import time; rebind explicitly.
def run_upstream(*args, cwd=None, env=None):
    subprocess.run(args, cwd=cwd if cwd is not None else upstream.SRC, env=env, check=True)
upstream.run = run_upstream


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', choices=['test', 'windows'])
    args = parser.parse_args()
    upstream.WORK = WORK; upstream.SRC = WORK / 'xray-src'
    sys.argv = ['build.py', 'test' if args.target == 'test' else 'prepare']
    upstream.main()
    if args.target == 'test': return
    go = os.environ.get('GO', 'go')
    env = dict(os.environ, GOPATH=str(WORK / 'gopath'), GOCACHE=str(WORK / 'go-cache'),
               TMPDIR=str(WORK / 'tmp'), GOMAXPROCS='2', GOFLAGS='-p=2', GOTOOLCHAIN='local',
               GOOS='windows', GOARCH='amd64', CGO_ENABLED='0')
    subprocess.run([go, 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-ldflags=-s -w',
                    '-o', str(WORK / 'bin/xray-s3.exe'), './main'], cwd=upstream.SRC, env=env, check=True)
    (WORK / 'bin/core.sha256').write_text(hashlib.sha256((WORK / 'bin/xray-s3.exe').read_bytes()).hexdigest())
    cache = Path(subprocess.check_output([go, 'env', 'GOMODCACHE'], env=env).decode().strip())
    for source, name in [(ROOT / 'LICENSE', 'CLIENT-LICENSE'), (upstream.SRC / 'LICENSE', 'XRAY-LICENSE'),
                         (cache / 'github.com/aws/aws-sdk-go-v2@v1.36.3/LICENSE.txt', 'AWS-LICENSE')]:
        shutil.copyfile(source, WORK / 'bin' / name)
    print('Windows core built and hashed; Android files were not touched.')


if __name__ == '__main__': main()
