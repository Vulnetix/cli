#!/bin/bash
while IFS= read -r line; do
  echo "$line"
done < input.txt
IFS=, read -r a b c <<< "$row"
joined=$(IFS=,; echo "${items[*]}")
( IFS=:; for d in $PATH; do echo "$d"; done )
