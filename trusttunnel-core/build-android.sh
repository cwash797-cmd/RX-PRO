#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NDK="${ANDROID_NDK_HOME:-${ANDROID_HOME}/ndk/27.0.12077973}"
TOOL="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
export GOOS=android GOARCH=arm64 CGO_ENABLED=1
export CC="$TOOL/aarch64-linux-android21-clang"
export CXX="$TOOL/aarch64-linux-android21-clang++"
export CGO_LDFLAGS='-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384'
cd "$ROOT/trusttunnel-core"
go mod download
go mod verify
mkdir -p "$ROOT/app/executableSo/arm64-v8a"
go build -mod=readonly -p 2 -trimpath -buildvcs=false -buildmode=pie \
 -ldflags="-s -w -linkmode external -extldflags '-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384'" \
 -o "$ROOT/app/executableSo/arm64-v8a/libtrusttunnel.so" .
"$TOOL/llvm-readelf" -l "$ROOT/app/executableSo/arm64-v8a/libtrusttunnel.so" | grep -E 'LOAD|interpreter'
