#!/bin/sh
docker run -d -p "$HOST_PORT:5432" postgres:16
mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p "$DB_NAME"
ssh -p "$SSH_PORT" deploy@"$HOST"
mkdir -p "$OUT_DIR"
echo "$REGISTRY_TOKEN" | docker login ghcr.io -u "$USER" --password-stdin
MYSQL_PWD="$DB_PASSWORD" mysqldump -u "$DB_USER" "$DB_NAME" > dump.sql
