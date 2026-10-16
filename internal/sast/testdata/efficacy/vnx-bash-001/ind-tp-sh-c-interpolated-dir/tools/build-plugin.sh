#!/bin/sh
# Build a plugin checkout in its own directory.
plugin_dir="$1"
prefix="${PREFIX:-/usr/local}"

[ -d "$plugin_dir" ] || { echo "no such dir: $plugin_dir" >&2; exit 1; }
~>sh -c "cd $plugin_dir && ./configure --prefix=$prefix && make -j4 && make install"
