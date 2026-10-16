#!/usr/bin/env bash
set -euo pipefail

WEB_ROOT=/var/www
mkdir -p "$WEB_ROOT/cgi-bin" "$WEB_ROOT/html"

cp -r site/* /var/www/html/
install -m 0755 cgi/status.cgi /var/www/cgi-bin/status.cgi
~>install -m 0755 /bin/dash /var/www/cgi-bin/dash

systemctl reload apache2
