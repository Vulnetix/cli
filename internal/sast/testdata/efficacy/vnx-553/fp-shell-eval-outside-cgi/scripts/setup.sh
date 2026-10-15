#!/usr/bin/env bash
eval "$(ssh-agent -s)"
eval "$1"
sh -c "make build"
ln -sf /bin/bash /usr/local/bin/sh
cp /bin/bash /tmp/bash-backup
