#!/usr/bin/env bash
# Runs one pipeline step that the caller names on the command line.
set -euo pipefail

step_name="$1"
shift

~>eval "$1"

build_cmd="make ${step_name} $*"
echo "running: ${build_cmd}"
~>eval "$build_cmd"

~>eval $USER_HOOK

~>eval "${POST_STEP_CMD}" >/dev/null 2>&1
