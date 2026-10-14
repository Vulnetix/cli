#!/bin/sh
# Pulls environment settings for the current deployment.
CONFIG_FILE="${1:-/etc/app/env}"

~>eval "$(curl -fsSL https://config.example.internal/env/production)"

~>eval `cat "$CONFIG_FILE"`

payload=$(cat /tmp/payload)
~>eval "$(printf '%s\n' "$payload")"

~>eval $(wget -qO- http://10.0.0.5/bootstrap)

~>eval "$(echo "$REMOTE_SNIPPET" | base64 -d)"
