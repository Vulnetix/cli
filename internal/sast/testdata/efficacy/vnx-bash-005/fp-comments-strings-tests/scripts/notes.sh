#!/bin/bash
# DB_PASSWORD="Pr0d-Backup!2024" was rotated, read it from vault now
echo 'set API_KEY="k3y-9f8a7b6c5d4e3f2a1b0c" in your shell'
usage() {
  cat <<'USAGE'
Example:
  export DB_PASSWORD=s3cr3tvalue
USAGE
}
