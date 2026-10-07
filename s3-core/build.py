#!/usr/bin/env python3
"""Build a pinned upstream Xray with the native S3 backend. Workspace-local caches."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = "b26a91de4f3294e26a0ad0a970b81a386a41f789"
WORK = ROOT / ".lab"
SRC = WORK / "xray-src"


def run(*args, cwd=SRC, env=None):
    subprocess.run(args, cwd=cwd, env=env, check=True)


def replace(path, old, new):
    text = path.read_text()
    if text.count(old) != 1:
        raise RuntimeError("Pinned source mismatch: " + str(path.relative_to(SRC)))
    path.write_text(text.replace(old, new))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", choices=["prepare", "test", "linux", "android"])
    args = parser.parse_args()
    for p in [WORK, WORK / "tmp", WORK / "gopath", WORK / "go-cache", WORK / "bin"]:
        p.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOPATH=str(WORK / "gopath"), GOCACHE=str(WORK / "go-cache"),
               TMPDIR=str(WORK / "tmp"), GOMAXPROCS="2", GOFLAGS="-p=2")
    go = os.environ.get("GO", str(WORK / "go/bin/go") if (WORK / "go/bin/go").exists() else "go")
    if not SRC.exists():
        run("git", "clone", "--filter=blob:none", "--no-checkout", "https://github.com/XTLS/Xray-core.git", str(SRC), cwd=ROOT)
    # This directory is a disposable build checkout, never the user's repository.
    run("git", "reset", "--hard", PIN)
    for name in ["s3.go", "s3_test.go"]:
        source = ROOT / "s3-core" / name
        if source.exists():
            shutil.copyfile(source, SRC / "transport/internet/xdrive" / ("rx_" + name))
    replace(SRC / "transport/internet/xdrive/storage.go", 'case "local":',
            'case "S3":\n\t\treturn sharedStorage(streamSettings, config, func() (Storage, error) { return newS3Storage(streamSettings, config) })\n\tcase "local":')
    replace(SRC / "infra/conf/transport_method.go", 'switch c.Service {\n\tcase "local":',
            'switch c.Service {\n\tcase "S3":\n\t\tif len(c.Secrets) != 1 { return nil, errors.New("S3 requires one credentials JSON") }\n\tcase "local":')
    # Prevent a fast producer spawning an unbounded number of queued uploads.
    wal = SRC / "transport/internet/xdrive/wal.go"
    replace(wal, '\n\tn := len(w.buf)\n', '\n\tselect { case w.sem <- struct{}{}: case <-w.ctx.Done(): w.err = w.ctx.Err(); return w.err }\n\tn := len(w.buf)\n')
    replace(wal, '''	select {
	case w.sem <- struct{}{}:
	case <-w.ctx.Done():
		return
	}
	defer func() { <-w.sem }()

	if err := w.storage.Put(w.ctx, objectName(w.prefix, seq, segSuffix), chunk); err != nil {''', '''	err := w.storage.Put(w.ctx, objectName(w.prefix, seq, segSuffix), chunk)
	<-w.sem // release before acquiring mu: flushLocked may hold mu waiting for a slot
	if err != nil {''')
    replace(SRC / "transport/internet/xdrive/xdrive.go", 'if l.active[session] || !l.handled[session].IsZero() {',
            'if len(l.active) >= 32 || l.active[session] || !l.handled[session].IsZero() {')
    run(go, "mod", "edit", "-require=github.com/aws/aws-sdk-go-v2@v1.36.3", env=env)
    run(go, "mod", "tidy", env=env)
    run(go, "mod", "verify", env=env)
    if args.target == "prepare":
        return
    if args.target == "test":
        run(go, "test", "-race", "-timeout=180s", "./transport/internet/xdrive", env=env)
        return
    output = WORK / "bin" / ("xray-s3" if args.target == "linux" else "libs3xray.so")
    env.update(GOOS="linux" if args.target == "linux" else "android", GOARCH="amd64" if args.target == "linux" else "arm64", CGO_ENABLED="0")
    command = [go, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=-s -w"]
    if args.target == "android":
        # Same Android-only linkname compatibility flag as pinned upstream CI.
        command[-1] = "-ldflags=-s -w -checklinkname=0"
        command.append("-buildmode=pie")
    run(*command, "-o", str(output), "./main", env=env)
    if args.target == "android":
        dest = ROOT / "app/executableSo/arm64-v8a"
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(output, dest / "libs3xray.so")
        (dest / "libs3xray.so").chmod(0o755)
    print("Built:", output)


if __name__ == "__main__":
    main()
