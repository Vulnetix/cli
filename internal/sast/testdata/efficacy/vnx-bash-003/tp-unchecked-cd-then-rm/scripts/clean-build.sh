#!/bin/bash
# Removes the previous build output before a release.

BUILD_DIR=/var/tmp/app-build

echo "cleaning ${BUILD_DIR}"
~>cd "$BUILD_DIR"
rm -rf ./*

~>pushd "$CACHE_ROOT/objects" > /dev/null
find . -type f -mtime +7 -delete
popd > /dev/null

~>cd ../vendor 2>/dev/null
git clean -fdx
