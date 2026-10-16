#!/usr/bin/env bash
set -euo pipefail
# npm exposes settings as npm_config_* variables
echo "registry: ${npm_config_registry}"
export npm_config_cache="$HOME/.cache/npm"
export npm_config_fund=false
npm_package_version=$(node -p "require('./package.json').version")
echo "building ${npm_package_version}"
