#!/bin/bash
while getopts "d:" opt; do
  case "$opt" in
~>    d) IFS=$OPTARG ;;
  esac
done
read -ra cols < input.txt
echo "${cols[0]}"
