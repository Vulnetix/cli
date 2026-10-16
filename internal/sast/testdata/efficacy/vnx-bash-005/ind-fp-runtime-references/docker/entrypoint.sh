#!/bin/sh
set -eu
DB_PASSWORD="$(cat /run/secrets/db_password)"
API_KEY="${API_KEY:?API_KEY must be set}"
GITHUB_TOKEN=$GH_TOKEN
SLACK_TOKEN=$(aws secretsmanager get-secret-value --secret-id prod/slack --query SecretString --output text)
export DB_PASSWORD API_KEY
echo "$REGISTRY_TOKEN" | docker login -u ci --password-stdin registry.example.com
exec "$@"
