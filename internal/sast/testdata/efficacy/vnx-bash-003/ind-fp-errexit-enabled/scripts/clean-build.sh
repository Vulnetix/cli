#!/usr/bin/env bash
set -euo pipefail
BUILD_DIR=${BUILD_DIR:-build/out}

cd "$BUILD_DIR"
rm -rf ./*
sha256sum -c checksums.txt
rm -rf "$1/cache"
