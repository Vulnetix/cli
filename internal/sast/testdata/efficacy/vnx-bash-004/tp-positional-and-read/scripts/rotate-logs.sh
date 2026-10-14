#!/usr/bin/env bash
set -eu

read -r -p "Log directory: " logdir
~>find $logdir -name '*.log' -mtime +7 -delete

while getopts "u:" opt; do
  case $opt in
    u) user=$OPTARG ;;
  esac
done
~>sudo -u $user /usr/local/bin/rotate \
  --force
local_host="${1:-localhost}"
~>ssh $local_host 'uptime'
