#!/usr/bin/env bash
set -euo pipefail

~>mysqldump -u "$DB_USER" -p"$DB_PASSWORD" shop > /backups/shop.sql
~>mysql --user=root --password="$MYSQL_ROOT_PASSWORD" -e "FLUSH PRIVILEGES"
~>sshpass -p "$SSH_PASS" ssh deploy@app.example.com 'systemctl restart app'
~>docker login -u "$REGISTRY_USER" -p "$REGISTRY_TOKEN" registry.example.com
~>curl -fsS -u "admin:$ADMIN_PASSWORD" https://ci.example.com/job/build
~>mysqladmin -uroot -p${MYSQL_ROOT_PASSWORD} status
