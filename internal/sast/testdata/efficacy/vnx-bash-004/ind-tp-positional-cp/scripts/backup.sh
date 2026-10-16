#!/usr/bin/env bash
set -euo pipefail

src=$1
dest=/var/backups/$(date +%F)
mkdir -p "$dest"
~>cp -a $src "$dest/"
~>tar -czf "$dest.tgz" -C /var/backups $2
