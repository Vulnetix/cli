#!/usr/bin/env bash
set -euo pipefail
curl -fsSL https://example.org/install.sh -o install.sh
echo "${INSTALL_SHA256}  install.sh" | sha256sum -c -
bash install.sh
curl -fsSL -o tool.tar.gz https://example.org/tool.tar.gz
curl -fsSL -o tool.tar.gz.asc https://example.org/tool.tar.gz.asc
gpg --verify tool.tar.gz.asc tool.tar.gz
tar -xzf tool.tar.gz
