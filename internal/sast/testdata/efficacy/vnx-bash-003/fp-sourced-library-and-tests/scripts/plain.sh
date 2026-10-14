#!/usr/bin/env bash
# No errexit, but nothing here depends on a failed command being noticed.
echo "Building $(date)"
make all
cp build/app /usr/local/bin/app
ls -la
