#!/bin/bash
x=$(cat file.txt)
echo "$(date)"
cd "$(dirname "$0")"
sleep $(( RANDOM % 5 ))
mkdir -p "$(git rev-parse --show-toplevel)/build"
if [[ $(uname) == Linux ]]; then echo linux; fi
make -j$(nproc)
case $(uname -s) in
  Darwin) echo mac ;;
esac
local_n=$(nproc)
# rm -f $(find . -name '*.tmp')
echo "use rm -f \$(find .) carefully"
