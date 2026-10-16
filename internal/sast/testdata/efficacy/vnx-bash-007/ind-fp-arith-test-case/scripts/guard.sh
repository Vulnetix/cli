#!/usr/bin/env bash
if (( $(wc -l < queue.txt) > 100 )); then
  echo "queue too long"
fi
if [[ $(uname -s) == Darwin ]]; then
  sed_inplace=(-i '')
fi
case $(uname -m) in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
esac
total=$(( $(cat a.count) + 1 ))
read -r first <<< $(head -1 hosts.txt)
echo "$arch $total $first"
