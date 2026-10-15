#!/usr/bin/env bash
set -euo pipefail

~>openssl pkcs12 -export -in cert.pem -inkey key.pem -out bundle.p12 -passout pass:"$P12_PASSWORD"
~>openssl enc -d -aes-256-cbc -in secrets.enc -out secrets.env -pass pass:${ENC_KEY}
openssl enc -d -aes-256-cbc -in secrets.enc -out secrets.env -pass env:ENC_KEY
openssl pkcs12 -export -in cert.pem -out b.p12 -passout file:/run/secrets/p12pass
~>pg_dump "postgresql://app:${DB_PASSWORD}@db:5432/app" > backup.sql
~>git clone "https://x-access-token:$GITHUB_TOKEN@github.com/acme/infra.git"
~>redis-cli -h cache -a "$REDIS_PASSWORD" PING
