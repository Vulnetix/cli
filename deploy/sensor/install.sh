#!/bin/sh
# Install the Vulnetix runtime sensor as a systemd service on EC2 or an EMR
# node. Run as root, from the SSM document or as an EMR bootstrap action.
#
#   install.sh <version> <feed-url> <feed-key> [mode] [listen] [upstream]
#
# The binary is checked against the release's checksums.txt before it is
# installed; a mismatch stops the install. Credentials are not taken as
# arguments (they would land in the process list and the SSM history): put
# VULNETIX_ORG_ID and VULNETIX_API_KEY in /etc/vulnetix-sensor.env first, for
# example from Secrets Manager in the same SSM run.
set -eu

VERSION="${1:?version, e.g. v3.130.0}"
FEED="${2:?published feed URL}"
FEED_KEY="${3:?feed public key, base64}"
MODE="${4:-monitor}"
LISTEN="${5:-}"
UPSTREAM="${6:-}"

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

BASE="https://github.com/Vulnetix/cli/releases/download/${VERSION}"
NAME="vulnetix-sensor-linux-${ARCH}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fsSL "${BASE}/${NAME}" -o "${TMP}/${NAME}"
curl -fsSL "${BASE}/checksums.txt" -o "${TMP}/checksums.txt"
WANT="$(grep " \*\?${NAME}\$" "${TMP}/checksums.txt" | awk '{print $1}')"
GOT="$(sha256sum "${TMP}/${NAME}" | awk '{print $1}')"
if [ -z "$WANT" ] || [ "$WANT" != "$GOT" ]; then
  echo "checksum mismatch for ${NAME}: refusing to install" >&2
  exit 1
fi
install -m 0755 "${TMP}/${NAME}" /usr/local/bin/vulnetix-sensor

if [ ! -f /etc/vulnetix-sensor.env ]; then
  umask 077
  cat > /etc/vulnetix-sensor.env <<'EOF'
# VULNETIX_ORG_ID=
# VULNETIX_API_KEY=
EOF
  echo "wrote /etc/vulnetix-sensor.env; set the credentials before the sensor can report" >&2
fi

ARGS="--mode ${MODE} --feed ${FEED} --feed-key ${FEED_KEY} --egress-listen 127.0.0.1:3128"
if [ -n "$LISTEN" ] && [ -n "$UPSTREAM" ]; then
  ARGS="${ARGS} --listen ${LISTEN} --upstream ${UPSTREAM}"
fi

cat > /etc/systemd/system/vulnetix-sensor.service <<EOF
[Unit]
Description=Vulnetix runtime sensor
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/vulnetix-sensor.env
ExecStart=/usr/local/bin/vulnetix-sensor ${ARGS}
Restart=always
RestartSec=5
StateDirectory=vulnetix-sensor
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
MemoryMax=256M

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vulnetix-sensor
echo "vulnetix-sensor ${VERSION} installed in ${MODE} mode"
