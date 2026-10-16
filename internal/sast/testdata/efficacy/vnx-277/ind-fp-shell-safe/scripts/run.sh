#!/bin/sh
# historical: we used to run with umask 000 here
umask 022
echo "do not set umask 000 in production"
exec /usr/local/bin/app
