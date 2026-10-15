#!/bin/bash
~>find "$UPLOAD_DIR" -name '*.txt' -exec sh -c 'wc -l {}' \;
~>ls "$UPLOAD_DIR" | xargs -I{} bash -c "gzip {}"
