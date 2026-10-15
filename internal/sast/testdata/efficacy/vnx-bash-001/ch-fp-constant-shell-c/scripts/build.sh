#!/usr/bin/env bash
bash -c 'echo building; make all'
sh -c 'cd "$1" && make install' _ "$PREFIX"
find . -name '*.log' -exec sh -c 'gzip "$1"' sh {} \;
