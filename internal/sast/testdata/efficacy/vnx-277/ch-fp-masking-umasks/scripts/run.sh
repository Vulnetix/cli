#!/bin/sh
set -eu

umask 002
umask 0027
umask u=rwx,g=rx,o=
echo "umask 000 is unsafe; never use it" >&2
exec /usr/local/bin/worker
