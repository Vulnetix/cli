#!/usr/bin/env bash
set -euo pipefail

echo "$REGISTRY_TOKEN" | docker login ghcr.io -u "$GITHUB_ACTOR" --password-stdin
MYSQL_PWD="$DB_PASSWORD" mysql -u app -h db -e 'SELECT 1'
PGPASSWORD="$PGPASS" psql -h db -U app -c 'select 1'
redis-cli -h cache --askpass < /run/secrets/redis
docker run -p "$PORT":8080 app:latest
mysql --port="$DB_PORT" -u app -h db -e 'SELECT 1'
sshpass -f "$PASS_FILE" ssh deploy@host true
echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > ~/.npmrc
git clone "https://github.com/acme/infra.git"
pg_dump "postgresql://app@db:5432/app" > backup.sql
redis-cli -h cache --pass-file /run/secrets/redis PING
