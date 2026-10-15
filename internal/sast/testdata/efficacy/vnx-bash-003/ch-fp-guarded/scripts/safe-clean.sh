#!/bin/bash
cd "$1" || exit 1
rm -rf build
cd /tmp && rm -rf scratch
rm -rf "${OUT_DIR:?}/"*
if ! sha256sum -c SHA256SUMS; then
  exit 1
fi
sha256sum -c SHA256SUMS || { echo bad; exit 1; }
