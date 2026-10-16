#!/bin/bash
set -euo pipefail
~>umask 000
exec /usr/local/bin/app --data /data
