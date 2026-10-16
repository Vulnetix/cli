#!/usr/bin/env bash
set -euo pipefail
LOG_ROOT="${1:-/var/log/app}"

~>find "$LOG_ROOT" -type f -name '*.log' -mtime +7 -exec bash -c 'gzip -9 {} && echo compressed {}' \;
