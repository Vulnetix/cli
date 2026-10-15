#!/bin/bash
arr=(a b c)
joined=$(IFS=,; echo "${arr[*]}")
MY_IFS=,
export IFS_BACKUP="$IFS"
split() {
  IFS=: read -r user rest <<< "$1"
  printf '%s\n' "$user"
}
