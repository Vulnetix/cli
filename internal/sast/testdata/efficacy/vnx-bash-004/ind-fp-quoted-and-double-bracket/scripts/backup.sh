#!/usr/bin/env bash
set -euo pipefail

src="$1"
cp -a "$src" /var/backups/
if [[ -n $src && $src == /srv/* ]]; then
  tar -czf "/var/backups/$(basename "$src").tgz" "$src"
fi
case $src in
  /srv/*) echo "srv path" ;;
esac
count=$(( $# + 1 ))
echo "copied $src"
printf 'done %s\n' $src
