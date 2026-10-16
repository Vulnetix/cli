#!/usr/bin/env bash
repo_path="$HOME/src/$1"

~>pushd "$repo_path" >/dev/null
git fetch origin
git reset --hard origin/main
git clean -fdx
popd >/dev/null
