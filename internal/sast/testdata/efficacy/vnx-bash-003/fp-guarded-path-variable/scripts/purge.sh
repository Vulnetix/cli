#!/bin/bash
# Each path variable is constant, defaulted or checked before rm uses it.

rm -rf "${BUILD_DIR:?BUILD_DIR must be set}/"*

[ -n "$STAGE_DIR" ] && rm -rf "$STAGE_DIR/"*

DIST=/opt/app/dist
rm -rf "$DIST"/*

rm -rf "${TMP_ROOT:-/tmp/app}/"cache

if [ -z "$OUTPUT_DIR" ]; then
  echo "OUTPUT_DIR is required" >&2
  exit 1
fi
rm -rf "$OUTPUT_DIR"/reports

rm -rf "$HOME/.cache/app"
rm -rf "$tmpdir"
