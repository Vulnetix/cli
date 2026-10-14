#!/bin/bash
for file in "$@"; do
~>  cd $(dirname "$file")
done
~>export $(grep -v '^#' .env | xargs)
~>chmod 600 $(find /etc/app -name '*.key')
~>tar -czf backup.tgz $(cat filelist.txt)
~>kill $(cat /run/app.pid) 2>/dev/null || true
~>ln -sf $(pwd)/config/app.conf /etc/app.conf
