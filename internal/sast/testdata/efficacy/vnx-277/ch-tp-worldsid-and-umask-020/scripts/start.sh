#!/bin/sh
set -eu

~>umask 020
exec /usr/local/bin/worker --spool /var/spool/worker
