#!/bin/bash
# Clean the build output directory before a fresh build.
BUILD_DIR=${BUILD_DIR:-build/out}

echo "cleaning $BUILD_DIR"
~>cd "$BUILD_DIR"
rm -rf ./*
cd - >/dev/null
make all
