#!/bin/bash
rsync -a \
~>  $(sed 's/^/--exclude=/' excludes.txt) \
  src/ dst/
~>cp `ls -t backups/*.sql | head -1` /restore/latest.sql
LATEST=`ls -t backups/*.sql | head -1`
echo "latest: `date`"
