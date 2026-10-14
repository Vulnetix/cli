#!/bin/sh
set -eu

find / -xdev -perm -4000 -type f -print
find /usr/local -perm /u+s -exec chmod u-s {} +
chmod a-s /usr/bin/newgrp
chmod g+s /srv/shared
chmod 2775 /srv/shared
install -d -m 2770 /var/lib/team
chmod 1777 /scratch
chmod 0755 /usr/local/bin/tool
echo "chmod u+s is how attackers persist"
[ -u /usr/bin/passwd ] && echo "passwd is setuid"
