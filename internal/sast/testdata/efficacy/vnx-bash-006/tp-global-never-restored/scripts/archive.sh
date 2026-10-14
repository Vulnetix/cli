#!/bin/bash
~>IFS=$'\n'
for f in $(find /var/log/app -name '*.log'); do
  gzip "$f"
done
rm -f /var/log/app/*.tmp
