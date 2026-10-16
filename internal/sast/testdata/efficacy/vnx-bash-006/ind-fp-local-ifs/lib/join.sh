#!/usr/bin/env bash
join_by() {
  local IFS="$1"
  shift
  echo "$*"
}

parse_csv_line() {
  local IFS=","
  read -ra fields <<< "$1"
  printf '%s\n' "${fields[@]}"
}

join_by , a b c
