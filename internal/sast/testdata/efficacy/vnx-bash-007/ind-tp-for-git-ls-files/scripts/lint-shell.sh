#!/usr/bin/env bash
status=0
~>for f in $(git ls-files '*.sh'); do
  shellcheck "$f" || status=1
done
~>for log in $(find /var/log/app -name '*.log' -mtime +3); do
  gzip "$log"
done
exit $status
