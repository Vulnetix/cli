#!/usr/bin/env bash
for host in "$@"; do
~>  ssh -o BatchMode=yes $host 'sudo systemctl restart nginx'
done
