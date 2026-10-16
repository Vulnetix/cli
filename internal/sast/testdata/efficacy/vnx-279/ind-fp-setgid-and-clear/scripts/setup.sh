#!/bin/sh
set -e
mkdir -p /srv/team
chmod g+s /srv/team
chmod 2775 /srv/team
chmod u-s /usr/bin/at
chmod 01777 /srv/drop
chmod 0755 /usr/local/bin/app
find / -xdev -perm -4000 -type f -print
# chmod u+s is dangerous, do not add it here
