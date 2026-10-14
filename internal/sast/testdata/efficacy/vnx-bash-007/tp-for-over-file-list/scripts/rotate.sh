#!/bin/bash
~>for f in $(ls /var/log/app/*.log); do
  gzip "$f"
done
~>for f in $(find . -name '*.tmp'); do rm -- "$f"; done
~>for host in $(cat hosts.txt); do
  ssh "$host" uptime
done
~>for p in $(git diff --name-only HEAD~1); do echo "$p"; done
