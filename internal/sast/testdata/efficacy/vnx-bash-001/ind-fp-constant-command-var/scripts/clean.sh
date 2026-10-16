#!/usr/bin/env bash
set -euo pipefail

CLEAN_CMD="make distclean"
RESET_OPTS='set -o noclobber'

eval "$CLEAN_CMD"
eval "$RESET_OPTS"
eval 'shopt -s nullglob globstar'
