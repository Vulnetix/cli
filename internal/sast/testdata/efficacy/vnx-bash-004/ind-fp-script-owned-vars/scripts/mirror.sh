#!/bin/bash
RSYNC_OPTS="-a --delete --exclude=.git"
SRC_DIR=/srv/repo
DEST_DIR=/mnt/mirror
rsync $RSYNC_OPTS $SRC_DIR/ $DEST_DIR/
[ -d $DEST_DIR ] && echo ok
exit $?
