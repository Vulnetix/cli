#!/usr/bin/env bash
items=(api worker scheduler)
joined=$(IFS=,; echo "${items[*]}")
( IFS=:; echo "${items[*]}" > services.txt )

OLDIFS="$IFS"
IFS=';'
read -ra parts <<< "$BUILD_FLAGS"
IFS="$OLDIFS"

saved_ifs=$IFS
IFS=$'\n'
mapfile -t lines < files.txt
unset IFS
echo "$joined ${parts[*]} ${#lines[@]} $saved_ifs"
