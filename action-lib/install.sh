#!/usr/bin/env bash
# Installs the Vulnetix CLI for the composite actions in this repository.
#
# Inputs arrive as environment variables, never as ${{ }} expressions:
#   VX_VERSION      release tag (v3.158.0), major channel (v3) or latest
#   VX_BINARY_PATH  an already-built binary to use instead of a download
#
# The binary is a release download, not a build from source: building needs
# private Go modules, which a runner in another repository cannot read.
# A second Vulnetix action in the same job finds the first one's install
# (VULNETIX_CLI_INSTALLED) and skips the download.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bindir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/vulnetix-bin"
want="${VX_BINARY_PATH:-${VX_VERSION:-latest}}"

if [ "${VULNETIX_CLI_INSTALLED:-}" = "$want" ] && [ -x "$bindir/vulnetix" ]; then
  echo "Vulnetix CLI already installed in this job ($want)"
  "$bindir/vulnetix" version
  exit 0
fi

mkdir -p "$bindir"

if [ -n "${VX_BINARY_PATH:-}" ]; then
  if [ ! -f "$VX_BINARY_PATH" ]; then
    echo "::error::binary-path $VX_BINARY_PATH does not exist"
    exit 1
  fi
  cp "$VX_BINARY_PATH" "$bindir/vulnetix"
  chmod +x "$bindir/vulnetix"
  echo "Using the Vulnetix CLI at $VX_BINARY_PATH"
else
  version="${VX_VERSION:-latest}"
  args=(--install-dir "$bindir")
  # install.sh takes a release tag or a major channel, both starting with v;
  # accept 3.59.4 and 3 as well.
  case "$version" in
    "" | latest) ;;
    v*) args+=(--version "$version") ;;
    *) args+=(--version "v$version") ;;
  esac
  # The installer shipped with this action ref, so the channel logic always
  # matches the ref the workflow pinned.
  sh "$root/install.sh" "${args[@]}"
fi

if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$bindir" >>"$GITHUB_PATH"
fi
if [ -n "${GITHUB_ENV:-}" ]; then
  echo "VULNETIX_CLI_INSTALLED=$want" >>"$GITHUB_ENV"
fi
"$bindir/vulnetix" version
