#!/bin/bash
set -euo pipefail

DATA_DIR=/srv/data
mkdir -p "$DATA_DIR"
~>chmod -R a+rwX "$DATA_DIR"
~>sudo chmod -R 777 /var/log/app
chown -R app:app /srv/app
