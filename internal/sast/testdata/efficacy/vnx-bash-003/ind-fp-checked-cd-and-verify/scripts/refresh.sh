#!/bin/bash
WORK_DIR="${WORK_DIR:-/var/lib/refresh}"

cd "$WORK_DIR" || exit 1
rm -rf ./staging
cd "$WORK_DIR/cache" && rm -f ./*.tmp

if ! sha256sum -c release.sha256; then
  echo "checksum mismatch" >&2
  exit 1
fi
gpg --verify release.asc release.tar.gz || { echo "bad signature" >&2; exit 1; }
rm -rf "${WORK_DIR:?}/old"
tar -xzf release.tar.gz
