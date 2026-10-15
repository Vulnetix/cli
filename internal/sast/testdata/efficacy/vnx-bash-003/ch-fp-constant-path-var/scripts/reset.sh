#!/bin/bash
OUT=/tmp/build-output
rm -rf "$OUT/"
[ -z "$TARGET" ] && exit 1
rm -rf "$TARGET/cache"
