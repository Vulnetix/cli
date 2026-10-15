#!/bin/bash
DB_NAME=$1
~>su postgres -c "createdb $DB_NAME"
~>runuser -u app -- sh -c "cd /srv && ./migrate $DB_NAME"
