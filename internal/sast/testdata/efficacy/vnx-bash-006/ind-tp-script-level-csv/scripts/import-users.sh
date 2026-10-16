#!/usr/bin/env bash
set -eu
~>IFS=','
while read -r user email role; do
  useradd -m -c "$email" "$user"
  usermod -aG "$role" "$user"
done < users.csv

for group in $(getent group | cut -d: -f1); do
  echo "$group"
done
