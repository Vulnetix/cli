#!/usr/bin/env bash
set -euo pipefail

DATA_DIR=/var/lib/app

~>chmod 777 /var/www/uploads
~>chmod -R 0777 "$DATA_DIR"
~>chmod a+rwx "$DATA_DIR/cache"
~>chmod o+w /etc/app/app.conf
~>install -m 0666 app.conf /etc/app/app.conf
~>mkdir -p -m 777 /srv/share
~>sudo chmod -R 666 "$DATA_DIR/logs"
~>find "$DATA_DIR/run" -type d -exec chmod 777 {} \;
