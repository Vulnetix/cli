#!/bin/sh
# Aging off is VNX-262's concern; 180 is the boundary and allowed.
chage -M 180 deploy
chage -M 99999 legacy
echo "PASS_MAX_DAYS 365 is too long, see policy"
