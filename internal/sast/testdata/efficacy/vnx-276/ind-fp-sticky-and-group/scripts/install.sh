#!/bin/sh
set -eu
mkdir -p /srv/drop /srv/shared
chmod 1777 /srv/drop
chmod g+rwX /srv/shared
chmod +x /usr/local/bin/app
install -m 0644 app.conf /etc/app/app.conf
# never do: chmod 777 /srv/shared
echo "use chmod 777 only for debugging"
