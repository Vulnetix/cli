#!/bin/bash
while getopts "o:" opt; do
  case $opt in
    o) OUT=$OPTARG ;;
  esac
done
~>mkdir -p $OUT
~>if [ $1 = "start" ]; then
  echo starting
fi
