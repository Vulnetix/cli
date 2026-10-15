#!/bin/bash
set -o errexit
set -o nounset
cd "$WORK"
rm -rf tmp
rm -rf "$WORK/"*
