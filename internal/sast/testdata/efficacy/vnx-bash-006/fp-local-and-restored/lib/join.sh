#!/bin/bash
join_by() {
  local IFS="$1"
  shift
  echo "$*"
}

split_csv() {
  local IFS
  IFS=,
  read -ra cols <<< "$1"
  echo "${#cols[@]}"
}

lines_of() {
  local saved_ifs=$IFS
  IFS=$'\n'
  set -- $(cat "$1")
  IFS=$saved_ifs
  echo "$#"
}

OLDIFS="$IFS"
IFS=,
read -ra fields <<< "$CSV_LINE"
IFS="$OLDIFS"

IFS=:
set -- $PATH
unset IFS
