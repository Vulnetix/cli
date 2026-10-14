#!/bin/sh
set -e

BINDIR=${BINDIR:-/usr/local/bin}
~>chmod ug+s "$BINDIR/helper"
~>sudo chmod 6755 /usr/local/bin/helper
~>install -Dm4755 helper "$pkgdir/usr/bin/helper"
