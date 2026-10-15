#!/bin/bash
IFS=$'\n\t'
while IFS= read -r line; do echo "$line"; done < in.txt
IFS=, read -ra parts <<< "$1"
parse() {
  local IFS=,
  echo $1
}
old_ifs="$IFS"
IFS=:
echo $PATH
IFS="$old_ifs"
( IFS=:; echo $PATH )
echo "IFS=, is how you split"
# IFS=: here
