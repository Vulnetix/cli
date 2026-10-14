#!/bin/sh
# chmod u+s was removed from this script.
chmod g+s /srv/shared
chmod 2775 /srv/shared
chmod u-s /usr/bin/at
chmod -s /usr/bin/wall
chmod 755 /usr/local/bin/tool
find / -xdev -perm -4000 -type f -print
echo "do not chmod u+s anything"
