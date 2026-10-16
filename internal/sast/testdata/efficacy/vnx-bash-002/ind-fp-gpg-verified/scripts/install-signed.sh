#!/bin/bash
set -euo pipefail
curl -sSL https://example.org/releases/install.sh -o install.sh
curl -sSL https://example.org/releases/install.sh.asc -o install.sh.asc
gpg --batch --verify install.sh.asc install.sh
bash install.sh
