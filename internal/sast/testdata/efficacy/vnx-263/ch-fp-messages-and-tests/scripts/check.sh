#!/bin/sh
# chage -M 400 would exceed the 180-day policy
max=$(grep '^PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}')
if [ "$max" -gt 180 ]; then
  echo "PASS_MAX_DAYS $max is above policy; run: chage -M 90 user"
fi
echo "net accounts /maxpwage:365 is not allowed"
