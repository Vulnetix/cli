#!/bin/bash
target=$1
out="${2:-dist}"
if [[ -n $target && $target == release ]]; then
  rm -rf "$target"
fi
cp "$out"/app "/opt/$target/app"
case $target in
  release) echo "release" ;;
esac
dir=$target
export TARGET=$target
local_copy="$(basename "$target")"
mkdir -p "$(dirname "$out")/logs"
printf '%s\n' "$@"
