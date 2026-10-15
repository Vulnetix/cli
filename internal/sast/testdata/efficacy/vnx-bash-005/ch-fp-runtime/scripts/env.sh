#!/bin/bash
DB_PASSWORD="${DB_PASSWORD:-}"
PASSWORD=$(cat /run/secrets/db_password)
TOKEN="$1"
API_KEY=$(vault kv get -field=key secret/app)
read -r -s -p "Password: " PASSWORD
mysql -u root -p appdb
mysql -u root -p"$MYSQL_PWD" appdb
curl -u "$API_USER:$API_PASS" https://example.org
docker login -u "$REG_USER" --password-stdin registry.example.com
