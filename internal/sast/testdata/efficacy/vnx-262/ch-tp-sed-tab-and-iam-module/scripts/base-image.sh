#!/bin/bash
set -euo pipefail
~>sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t99999/' /etc/login.defs
~>sudo chage -I -1 -m 0 -M 99999 -E -1 deploy
