#!/usr/bin/env bash
set -euo pipefail

OPTS=$(getopt -o hvo: --long help,verbose,output: -n "$0" -- "$@")
eval set -- "$OPTS"

while true; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -v|--verbose) VERBOSE=1; shift ;;
    -o|--output) OUTPUT="$2"; shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done

parse_more() {
  eval set -- "$(getopt -o a:b -- "$@")"
}
