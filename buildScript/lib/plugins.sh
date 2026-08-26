#!/bin/bash
set -e

# RX-PRO: bundle official plugin binaries (mieru, naive) into the APK.
# Versions are PINNED and verified by SHA256 so builds are reproducible
# and can't silently change if upstream re-tags a release.

MIERU_VER="3.35.0"
NAIVE_VER="v150.0.7871.63-1"

DEST="app/executableSo"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch_so() {
  local url="$1" sha="$2" abi="$3"
  local apk="$TMP/$(basename "$url")"
  echo ">> fetching $(basename "$url")"
  curl -fsSL -o "$apk" "$url"
  echo "$sha  $apk" | sha256sum -c - >/dev/null || {
    echo "!! SHA256 MISMATCH for $url" >&2
    exit 1
  }
  mkdir -p "$DEST/$abi"
  unzip -o -j -q "$apk" "lib/$abi/*.so" -d "$DEST/$abi/"
}

# ---- mieru (official enfein builds) ----
fetch_so \
  "https://github.com/enfein/NekoBoxPlugins/releases/download/mieru-${MIERU_VER}/mieru-plugin-${MIERU_VER}-arm64-v8a.apk" \
  "80590a95d6a7c6d9817b21d768c63bb823336db7f94732abf4d353e8e276689d" \
  "arm64-v8a"

# ---- naive (official klzgrad builds) ----
fetch_so \
  "https://github.com/klzgrad/naiveproxy/releases/download/${NAIVE_VER}/naiveproxy-plugin-${NAIVE_VER}-arm64-v8a.apk" \
  "733fbbbebb383a91f42036992c21cfd19b99e089ac3d15d7c077df79fc471a89" \
  "arm64-v8a"

fetch_so \
  "https://github.com/klzgrad/naiveproxy/releases/download/${NAIVE_VER}/naiveproxy-plugin-${NAIVE_VER}-armeabi-v7a.apk" \
  "d52b01d0a55cd0807fe196e72abd5aa4859a783798b1bc1b3cf1bfa9ad8f7ae4" \
  "armeabi-v7a"

fetch_so \
  "https://github.com/klzgrad/naiveproxy/releases/download/${NAIVE_VER}/naiveproxy-plugin-${NAIVE_VER}-x86.apk" \
  "101d8e52c7473005b8ad072b7d446db624c76ba77ccce116564fadcc2cd4e0d7" \
  "x86"

fetch_so \
  "https://github.com/klzgrad/naiveproxy/releases/download/${NAIVE_VER}/naiveproxy-plugin-${NAIVE_VER}-x86_64.apk" \
  "a6800d30bb70798d7b9ad3d0218469c58776c250b462926a7cc2e7795d915f78" \
  "x86_64"

echo ">> bundled plugin binaries:"
find "$DEST" -name "*.so" -exec ls -la {} \;
