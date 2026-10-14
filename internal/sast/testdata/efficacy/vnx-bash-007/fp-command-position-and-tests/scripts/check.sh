#!/bin/bash
if ! $(grep -q needle haystack.txt); then
  echo missing
fi
if [[ $(whoami) == root ]]; then echo root; fi
$(command -v python3) --version
version=$(cat VERSION)
local_dir="$(cd "$(dirname "$0")" && pwd)"
read -r first <<< $(head -1 list.txt)
