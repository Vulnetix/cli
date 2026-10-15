#!/bin/sh
echo "never run: chage -M 99999 $USER"
printf 'PASS_MAX_DAYS 99999 disables aging\n'
