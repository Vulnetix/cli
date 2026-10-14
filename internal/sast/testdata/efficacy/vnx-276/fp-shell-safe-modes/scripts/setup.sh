#!/bin/sh
# chmod 777 /srv is what the old installer did; never again.
chmod +x run.sh
chmod 755 bin/*
chmod 1777 /tmp/shared
chmod a+rwxt /srv/drop
chmod -R g+rwX /app
chmod u+w notes.txt
chmod +w file.txt
chmod 600 ~/.ssh/id_ed25519
chmod go-w /etc/app
chmod "$MODE" /etc/app/app.conf
echo "do not chmod 777 anything"
install -m 0755 app /usr/local/bin/app
mkdir -m 700 "$HOME/.app"
