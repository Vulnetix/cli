#!/usr/bin/env bash
set -euo pipefail
~>curl -sSL https://get.example.io/agent.sh | sudo bash -s -- --channel stable
~>wget -qO- https://example.org/install.sh | sh
~>curl -fsSL https://example.org/bootstrap | sudo -E bash -
