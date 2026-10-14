#!/usr/bin/env bash
set -Eeuo pipefail

cd "$BUILD_DIR"
rm -rf ./*
sha256sum -c app.tar.gz.sha256
tar -xzf app.tar.gz
rm -rf "$1"/build
