#!/usr/bin/env bash
set -euo pipefail

mkdir -p build/out
printf '%s' "$REGISTRY_TOKEN" | docker login -u "$REGISTRY_USER" --password-stdin registry.example.com
docker run -d -p 8080:80 --name web nginx:1.27
ssh -p 2222 deploy@bastion 'uptime'
export PGPASSWORD="$DB_PASSWORD"
pg_dump -h db -U app app > dump.sql
openssl enc -aes-256-cbc -pass env:BACKUP_KEY -in dump.sql -out dump.sql.enc
sshpass -e ssh deploy@app01 true
