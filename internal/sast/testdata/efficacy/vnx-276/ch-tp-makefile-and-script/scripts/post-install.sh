#!/bin/sh
set -e

mkdir -p /var/log/app
~>chmod -R a+rwX /var/log/app
~>sudo chmod 0666 /dev/ttyUSB0
~>[ -d /srv/share ] && chmod o+w /srv/share
