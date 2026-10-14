#!/usr/bin/env bash

usage() {
  cat <<EOF
Usage: $0 [command]

To load the environment into your shell:
  eval "\$($0 env)"
  eval "\$MY_TOOL_INIT"
EOF
}

usage
