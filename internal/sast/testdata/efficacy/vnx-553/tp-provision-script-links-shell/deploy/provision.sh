#!/usr/bin/env bash
set -euo pipefail
apt-get install -y apache2
a2enmod cgi
~>install -m 0755 /usr/bin/zsh /usr/lib/cgi-bin/zsh
~>cp  /bin/dash  /var/www/html/cgi/dash.cgi
systemctl restart apache2
