#!/usr/bin/env bash
set -euo pipefail

# The value travels as a positional argument, never as code.
sh -c 'echo "processing $1"' _ "$file"
find . -name '*.log' -exec sh -c 'gzip -9 "$1"' sh {} \;
bash -c "make test"
bash -c 'source ~/.profile && nvm use 20'
xargs -n1 sh -c 'curl -fsS "$0" >/dev/null' < urls.txt
