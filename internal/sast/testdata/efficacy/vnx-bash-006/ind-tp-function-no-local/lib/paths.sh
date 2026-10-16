#!/bin/bash
add_dirs_to_path() {
~>  IFS=:
  for d in $EXTRA_PATHS; do
    PATH="$PATH:$d"
  done
}

add_dirs_to_path
for f in $(ls /etc/profile.d); do echo "$f"; done
