#!/bin/bash
~>IFS=$'\n'
for f in $(find . -type f); do
  echo "$f"
done
