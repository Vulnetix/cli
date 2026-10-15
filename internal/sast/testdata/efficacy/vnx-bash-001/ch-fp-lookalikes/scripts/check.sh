#!/usr/bin/env bash
# eval "$cmd" would be dangerous here, so we do not do it
echo "Do not use eval \"\$input\" in production"
evaluate_config "$1"
retrieval_mode=$2
log "running bash -c with $retrieval_mode"
printf 'eval %s\n' "$retrieval_mode"
