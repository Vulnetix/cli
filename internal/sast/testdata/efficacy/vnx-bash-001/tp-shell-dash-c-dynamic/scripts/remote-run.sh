#!/usr/bin/env bash
set -eu

target="$1"
query="$2"

~>bash -c "$TASK_COMMAND"
~>sh -c "cd $target && make install"
~>docker exec app-db sh -c "psql -U app -c \"$query\""
~>sudo -u deploy bash -lc "git checkout $target"
~>kubectl exec "$POD" -- sh -c "rm -rf /cache/$target"
~>zsh -c $USER_SNIPPET
