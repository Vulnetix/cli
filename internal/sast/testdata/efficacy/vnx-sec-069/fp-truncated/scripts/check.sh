#!/bin/sh
grep -q '^AGE-SECRET-KEY-1' "$KEYFILE" || { echo "not an age identity"; exit 1; }
