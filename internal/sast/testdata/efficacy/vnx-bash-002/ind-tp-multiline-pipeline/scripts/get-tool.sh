#!/usr/bin/env bash
set -euo pipefail
~>curl --retry 3 --fail --silent --show-error --location \
  https://get.example-tool.dev/install.sh \
  | bash -s -- --version 1.8.0 --bin-dir /usr/local/bin
