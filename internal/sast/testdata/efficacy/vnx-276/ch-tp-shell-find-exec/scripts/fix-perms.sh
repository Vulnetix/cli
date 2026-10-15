#!/bin/sh
set -e

~>find /var/www/html -type f -exec chmod 666 {} +
~>find /var/www/html -type d -print0 | xargs -0 chmod 777
