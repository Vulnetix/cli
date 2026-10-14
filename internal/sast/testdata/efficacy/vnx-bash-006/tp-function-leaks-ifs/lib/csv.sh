#!/bin/bash
split_fields() {
~>  IFS=,
  set -- $1
  echo "$#"
}

parse_path() {
~>  IFS=':'; read -ra parts <<< "$PATH"
  printf '%s\n' "${parts[@]}"
}
