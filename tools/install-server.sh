#!/usr/bin/env bash
# Run on the user's Linux VPS, never on an Android device.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo 'Run as root on the VPS.' >&2; exit 1; fi
if [ "$(uname -m)" != x86_64 ]; then echo 'This bundle requires Linux x86_64.' >&2; exit 1; fi
CONFIG="${1:?Usage: bash install-server.sh /absolute/server.json device1}"
NAME="${2:?Supply an administrative device name}"
[[ "$NAME" =~ ^[a-zA-Z0-9_-]{1,40}$ ]] || { echo 'Invalid device name.' >&2; exit 1; }
DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$DIR/xray-s3"
test -x "$BINARY" && test -s "$CONFIG"
if [ -e "/etc/s3-rixxx/$NAME.json" ]; then
  echo 'Existing device config will not be overwritten. Stop its service and back it up before updating.' >&2
  exit 1
fi
"$BINARY" run -test -c "$CONFIG"
if ! id s3rixxx >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin s3rixxx
fi
install -d -o root -g root -m 0755 /opt/s3-rixxx
install -d -o root -g s3rixxx -m 0750 /etc/s3-rixxx
install -m 0755 "$BINARY" /opt/s3-rixxx/xray-s3
install -o root -g s3rixxx -m 0640 "$CONFIG" "/etc/s3-rixxx/$NAME.json"
cat > /etc/systemd/system/s3-rixxx@.service <<'UNIT'
[Unit]
Description=S3 RIXXX node %i
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=3

[Service]
User=s3rixxx
Group=s3rixxx
ExecStart=/opt/s3-rixxx/xray-s3 run -c /etc/s3-rixxx/%i.json
Restart=on-failure
RestartSec=10
RestartPreventExitStatus=23
TimeoutStopSec=35
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
UMask=0077
MemoryMax=384M
CPUQuota=50%
TasksMax=128
Environment=GOMEMLIMIT=256MiB
Environment=GOMAXPROCS=2

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now "s3-rixxx@$NAME"
sleep 2
systemctl --no-pager --full status "s3-rixxx@$NAME"
echo 'Existing 3x-ui, Caddy and firewall settings were not changed.'
echo 'CPU quota is a test guard, not a final throughput setting.'
