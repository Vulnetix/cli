#!/bin/sh
# Build the Lambda layer zip for one architecture, from the repository root:
#
#   deploy/sensor/lambda/build-layer.sh arm64 v3.130.0 dist/
#
# Layout inside the layer (mounted at /opt):
#   extensions/vulnetix-sensor   the launcher Lambda starts as an extension
#   vulnetix/vulnetix-sensor     the binary
#   vulnetix/wrapper             set AWS_LAMBDA_EXEC_WRAPPER=/opt/vulnetix/wrapper
set -eu

ARCH="${1:?amd64 or arm64}"
VERSION="${2:-dev}"
OUT="${3:-dist}"
HERE="$(cd "$(dirname "$0")" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/extensions" "$STAGE/vulnetix" "$OUT"
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath \
  -ldflags "-s -w -X main.version=${VERSION} -X main.pinnedFeedKey=${VULNETIX_FEED_PUBLIC_KEY:-}" -o "$STAGE/vulnetix/vulnetix-sensor" ./cmd/vulnetix-sensor
cp "$HERE/extensions/vulnetix-sensor" "$STAGE/extensions/vulnetix-sensor"
cp "$HERE/wrapper" "$STAGE/vulnetix/wrapper"
chmod 0755 "$STAGE/extensions/vulnetix-sensor" "$STAGE/vulnetix/wrapper" "$STAGE/vulnetix/vulnetix-sensor"

OUT_ABS="$(cd "$OUT" && pwd)"
(cd "$STAGE" && zip -qr -X "$OUT_ABS/vulnetix-sensor-lambda-layer-${ARCH}.zip" extensions vulnetix)
echo "$OUT_ABS/vulnetix-sensor-lambda-layer-${ARCH}.zip"
