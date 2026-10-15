#!/bin/sh
set -e
useradd -m deploy
~>chage -M -1 deploy
~>sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 99999/' /etc/login.defs
