#!/bin/sh
target=""
while getopts "t:h" opt; do
  case $opt in
    t) target=$OPTARG ;;
    h) echo "usage: sync.sh -t DIR"; exit 0 ;;
  esac
done

~>rsync -a --delete ./public/ $target
