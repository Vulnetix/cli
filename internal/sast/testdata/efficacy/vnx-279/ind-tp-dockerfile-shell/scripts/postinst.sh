#!/bin/sh
set -e
~>install -m 4755 -o root -g root build/helper /usr/lib/app/helper
~>chmod 4755 /usr/lib/app/chrome-sandbox
