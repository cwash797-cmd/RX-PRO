#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd .. && pwd)"
: "${GOPATH:?Set a workspace-local GOPATH}"
SOURCE="$ROOT/.lab/sources/gomobile"
if [ ! -d "$SOURCE/.git" ]; then
  git clone --no-checkout https://github.com/MatsuriDayo/gomobile.git "$SOURCE"
fi
git -C "$SOURCE" checkout 17d6af34f6bd6d7e1e428e0c652c8b54a46bda4f
(cd "$SOURCE" && go build -o "$GOPATH/bin/gomobile-matsuri" ./cmd/gomobile && go build -o "$GOPATH/bin/gobind-matsuri" ./cmd/gobind)
# Both tools were built from the pinned fork above. Its init command fetches
# an unrelated moving gobind@latest; bind only needs this cache directory.
mkdir -p "$GOPATH/pkg/gomobile"
