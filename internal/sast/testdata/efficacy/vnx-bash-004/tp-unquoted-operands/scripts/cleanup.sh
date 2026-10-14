#!/bin/bash
# Remove a build directory passed by the caller.
target_dir=$1
~>rm -rf $target_dir
~>cp $2 /var/backups/
~>chown -R deploy:deploy ${target_dir}/cache
mkdir -p "$target_dir"
for f in "$@"; do
~>  mv $f /srv/archive/
done
~>tar -czf /tmp/out.tgz $@
