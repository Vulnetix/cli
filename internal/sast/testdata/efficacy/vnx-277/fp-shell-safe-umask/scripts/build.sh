#!/bin/sh
# umask 000 is what the old script did.
umask 022
umask 077
tmp=$( (umask 077 && mktemp -d) )
umask u=rwx,g=rx,o=
umask
echo "never umask 000"
