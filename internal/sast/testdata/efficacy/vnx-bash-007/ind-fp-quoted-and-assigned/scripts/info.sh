#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
files=$(find "$ROOT_DIR" -name '*.conf')
cd "$(dirname "$0")"
cp "$(ls -t backups/*.sql | head -1)" /restore/
OUT_DIR=${OUT_DIR:-$(mktemp -d)}
echo "size: $(wc -c < "$ROOT_DIR/README.md") bytes in $files $OUT_DIR"
