#!/usr/bin/env bash
# eval of strings that contain no expansion of their own.
eval "set -euo pipefail"
eval 'echo "home is $HOME"'
eval "echo \$HOME"
eval 'cleanup() { rm -f "$tmpfile"; }'
eval "trap 'cleanup' EXIT"
eval "$((1 + 2))" >/dev/null 2>&1 || true
eval "exit $?"
