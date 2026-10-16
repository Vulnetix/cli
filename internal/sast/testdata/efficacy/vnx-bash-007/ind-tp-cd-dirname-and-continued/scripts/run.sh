#!/bin/bash
~>cd $(dirname "$0")/..
rsync -a \
~>  $(sed 's/^/--exclude=/' .rsyncignore) \
  ./ deploy@web01:/srv/app/
