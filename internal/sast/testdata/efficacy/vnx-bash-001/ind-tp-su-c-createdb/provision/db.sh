#!/bin/bash
set -eu

DB_NAME="$1"
DB_OWNER="${2:-app}"

~>su - postgres -c "createdb -O $DB_OWNER $DB_NAME"
echo "created $DB_NAME"
