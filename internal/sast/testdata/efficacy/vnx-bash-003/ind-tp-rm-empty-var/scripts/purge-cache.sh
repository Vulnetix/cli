#!/bin/bash
CACHE_ROOT=$(dirname "$0")/../var
echo "purging caches under $CACHE_ROOT"
~>rm -rf "$1/cache"
~>rm -rf "${XDG_CACHE_HOME}/myapp/"*
