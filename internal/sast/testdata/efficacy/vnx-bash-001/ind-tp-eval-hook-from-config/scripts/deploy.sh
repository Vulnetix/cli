#!/usr/bin/env bash
set -euo pipefail

config_file="${1:-deploy.conf}"
post_hook=$(grep '^post_hook=' "$config_file" | cut -d= -f2-)

rsync -a --delete dist/ /srv/www/app/

if [ -n "$post_hook" ]; then
  echo "running post-deploy hook"
~>  eval "$post_hook"
fi
