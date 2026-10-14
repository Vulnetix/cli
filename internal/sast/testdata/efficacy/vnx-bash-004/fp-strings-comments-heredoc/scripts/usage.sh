#!/bin/bash
dest=$1
# rm -rf $dest would be dangerous here
echo 'rm -rf $1 is an example'
cat <<EOT
Usage: $0 <dest>
  copies files to $dest
  rm $1 is not run
EOT
cat <<'USAGE'
cp $1 /tmp
USAGE
echo $dest
log "copying $dest"
