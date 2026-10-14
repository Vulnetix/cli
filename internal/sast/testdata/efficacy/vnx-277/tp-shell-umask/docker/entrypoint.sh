#!/bin/sh
set -e

~>umask 000
mkdir -p /data/uploads

start_worker() {
~>    umask 0
    exec /usr/local/bin/worker
}

~>umask a=rwx
exec /usr/local/bin/server "$@"
