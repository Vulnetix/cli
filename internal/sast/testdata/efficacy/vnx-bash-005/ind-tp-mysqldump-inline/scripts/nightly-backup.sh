#!/usr/bin/env bash
set -euo pipefail
stamp=$(date +%Y%m%d)
~>mysqldump -u backup -pQx7vR2mLp9Kw --single-transaction appdb | gzip > "/backups/appdb-$stamp.sql.gz"
~>sshpass -p 'Bk#Upload42x' scp "/backups/appdb-$stamp.sql.gz" backup@archive01:/data/
