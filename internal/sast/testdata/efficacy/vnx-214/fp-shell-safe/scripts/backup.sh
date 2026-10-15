#!/usr/bin/env bash
set -euo pipefail

export MYSQL_PWD="$DB_PASSWORD"
mysqldump -u "$DB_USER" shop > /backups/shop.sql
mysql --defaults-extra-file=/run/secrets/my.cnf -e "SELECT 1"
echo "$REGISTRY_TOKEN" | docker login -u "$REGISTRY_USER" --password-stdin registry.example.com
sshpass -e ssh deploy@app.example.com uptime
mkdir -p "$BACKUP_DIR"
docker run -p "$PORT":80 nginx
ssh -p "$SSH_PORT" deploy@app.example.com
mysql -u root -p
# mysqldump -u root -p"$DB_PASSWORD" shop
rsync --password-file="$RSYNC_PASSWORD_FILE" ./dist rsync://host/dist
