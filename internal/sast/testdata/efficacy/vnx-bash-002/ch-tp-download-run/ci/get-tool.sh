#!/usr/bin/env bash
TMP=$(mktemp)
curl -fsSL -o "$TMP" https://releases.example.com/tool/install.sh
chmod +x "$TMP"
~>"$TMP" --prefix /usr/local
