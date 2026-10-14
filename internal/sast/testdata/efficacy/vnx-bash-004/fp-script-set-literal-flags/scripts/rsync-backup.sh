#!/bin/bash
RSYNC_OPTS="-a --delete --exclude .git"
SRC=/srv/data
rsync $RSYNC_OPTS $SRC /mnt/backup/
VERSION=$(cat VERSION)
docker build -t app:$VERSION .
for i in $(seq 1 3); do
  echo $i
done
