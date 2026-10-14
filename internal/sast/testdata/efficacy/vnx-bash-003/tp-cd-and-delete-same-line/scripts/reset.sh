#!/bin/sh
~>cd /opt/app/cache; rm -rf *
~>(cd "$WORKTREE"; git reset --hard origin/main)
~>cd "$1" ; rm -f *.log
