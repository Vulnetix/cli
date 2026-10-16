#!/bin/sh
set -eu
src="${1:-assets}"

find "$src" -name '*.png' -exec sh -c 'optipng -quiet -o5 "$1"' _ {} \;
find "$src" -name '*.jpg' -print0 | xargs -0 -n1 sh -c 'jpegoptim --strip-all "$0"'
bash -c 'printf "done: %s\n" "$1"' bash "$src"
