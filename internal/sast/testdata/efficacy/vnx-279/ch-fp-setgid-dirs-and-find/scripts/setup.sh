#!/bin/sh
set -e

chmod 2775 /srv/shared
chmod g+s /srv/shared/uploads
find / -xdev -perm -4000 -type f -print
chmod u-s /usr/bin/legacy
chmod 0755 /usr/local/bin/app
