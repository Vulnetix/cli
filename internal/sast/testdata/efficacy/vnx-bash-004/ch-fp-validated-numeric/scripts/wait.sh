#!/bin/bash
if ! [[ $1 =~ ^[0-9]+$ ]]; then
  echo "usage: $0 SECONDS" >&2
  exit 2
fi
sleep $1
