#!/bin/bash
set -e

# RX-PRO: bundle official plugin binaries (mieru, naive) into the APK.
# Versions are PINNED and verified by SHA256 so builds are reproducible
# and can't silently change if upstream re-tags a release.

MIERU_VER="3.35.0"
NAIVE_VER="v150.0.7871.63-1"
# Xray-core: the only core implementing the XHTTP transport (VLESS XHTTP profiles)
XRAY_VER="v26.7.28"

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

# ---- Xray-core (official XTLS builds) — for VLESS XHTTP support ----
# Xray publishes zips containing a raw "xray" ELF binary (not a plugin APK),
# so we verify the zip hash AND the inner binary hash, then install it as
# libxray.so. Official Android builds exist only for arm64-v8a and amd64.
fetch_xray() {
  local zipname="$1" zipsha="$2" binsha="$3" abi="$4"
  local zip="$TMP/$zipname"
  echo ">> fetching $zipname"
  curl -fsSL -o "$zip" "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/$zipname"
  echo "$zipsha  $zip" | sha256sum -c - >/dev/null || {
    echo "!! SHA256 MISMATCH for $zipname (zip)" >&2
    exit 1
  }
  unzip -o -q "$zip" xray -d "$TMP/xray-$abi"
  echo "$binsha  $TMP/xray-$abi/xray" | sha256sum -c - >/dev/null || {
    echo "!! SHA256 MISMATCH for $zipname (inner xray binary)" >&2
    exit 1
  }
  mkdir -p "$DEST/$abi"
  install -m 755 "$TMP/xray-$abi/xray" "$DEST/$abi/libxray.so"
}

fetch_xray "Xray-android-arm64-v8a.zip" \
  "a442892c175fa648fc56866ec872aac441c5a6b8946a1b60f0258ae16a7fb402" \
  "0695fcf6b06fdf96071628224a7c6d52328cce94d26078b5cc977e9db281e4f3" \
  "arm64-v8a"

fetch_xray "Xray-android-amd64.zip" \
  "5b05c41dc0ae5edb14c234dff6e440dd081d6f5a1105c9c9892debcc5e0f8066" \
  "e33d2f8894888a2e6135a1583a845e020b9200a6d16a51e670161d805e9d428f" \
  "x86_64"

echo ">> bundled plugin binaries:"
find "$DEST" -name "*.so" -exec ls -la {} \;
