#!/bin/sh
set -e

~>chmod 6755 /usr/lib/app/helper
~>chmod ug+s /usr/lib/app/mount-helper
~>chmod u=rwxs,go=rx /usr/lib/app/agent
