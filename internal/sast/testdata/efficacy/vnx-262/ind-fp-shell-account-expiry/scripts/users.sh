#!/bin/sh
# account expiry, not password aging
chage -E -1 deploy
chage -M 90 -W 14 deploy
