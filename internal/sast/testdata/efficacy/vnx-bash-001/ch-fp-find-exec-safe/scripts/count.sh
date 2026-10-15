#!/bin/bash
find "$UPLOAD_DIR" -name '*.txt' -exec sh -c 'wc -l "$1"' sh {} \;
find . -type f -exec sh -c 'for f; do gzip "$f"; done' sh {} +
su postgres -c 'createdb app'
