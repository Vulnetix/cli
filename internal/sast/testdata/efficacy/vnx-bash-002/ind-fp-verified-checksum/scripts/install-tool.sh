#!/usr/bin/env bash
set -euo pipefail

TOOL_SHA256="5f2b0a8c1e7d4f6a9b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a"

curl -fsSL https://get.example-tool.dev/install.sh -o /tmp/install-tool.sh
echo "${TOOL_SHA256}  /tmp/install-tool.sh" | sha256sum --check -
bash /tmp/install-tool.sh --prefix /opt/tool
rm -f /tmp/install-tool.sh
