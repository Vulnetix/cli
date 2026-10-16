#!/usr/bin/env bash
set -euo pipefail
~>chmod 600 $(find /etc/myapp -name '*.key' -o -name '*.pem')
~>chown app:app `find /var/lib/myapp -maxdepth 1 -type f`
