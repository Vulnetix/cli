#!/usr/bin/env bash
set -euo pipefail
wget -k -p -E https://docs.internal/index.html
wget -mkEpnp https://docs.internal/
curl -K "$HOME/.config/release.curlrc" https://downloads.internal/latest
