#!/bin/bash
tries=$1
case $tries in
  ''|*[!0-9]*) echo "tries must be a number" >&2; exit 2 ;;
esac
seq 1 $tries
