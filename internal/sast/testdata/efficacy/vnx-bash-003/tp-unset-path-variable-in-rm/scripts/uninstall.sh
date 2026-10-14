#!/bin/bash
# Uninstalls the launcher and its runtime files.

STEAMROOT="$(cd "${0%/*}" && echo "$PWD")"
~>rm -rf "$STEAMROOT/"*

~>rm -rf "${CACHE_DIR}/"*

~>rm -rf "$1"/build

INSTALL_PREFIX=$(dirname "$(command -v launcher)")
~>rm -rf "$INSTALL_PREFIX"/share/launcher
