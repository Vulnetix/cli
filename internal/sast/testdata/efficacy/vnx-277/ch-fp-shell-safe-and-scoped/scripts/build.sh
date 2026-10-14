#!/usr/bin/env bash
set -euo pipefail

umask 022
umask 0027
umask -S u=rwx,g=rx,o=
umask 0002
echo "umask 000 is unsafe"
# umask 0
( umask 077; openssl genrsa -out key.pem 4096 )
