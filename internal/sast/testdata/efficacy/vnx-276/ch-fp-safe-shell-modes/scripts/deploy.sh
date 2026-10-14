#!/usr/bin/env bash
set -euo pipefail

PREFIX=${PREFIX:-/opt/app}

chmod 755 "$PREFIX/bin/app"
chmod 1777 /srv/dropbox
chmod -R go-w /etc/app
chmod g+w /srv/team
chmod 0775 /srv/team
chmod u=rwx,g=rx,o= "$PREFIX"
chmod a+rX "$PREFIX/share"
chmod +x ./run.sh
chmod o-rwx "$PREFIX/secrets"
git update-index --chmod=+x scripts/run.sh
echo "never chmod 777 your web root"
mkdir -p -m 1777 /srv/scratch
install -d -m 0750 /var/lib/app
