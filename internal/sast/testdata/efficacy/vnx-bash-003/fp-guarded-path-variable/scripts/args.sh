#!/bin/bash
if [ $# -ne 1 ]; then
  echo "usage: $0 <dir>" >&2
  exit 2
fi
rm -rf "$1"/build
