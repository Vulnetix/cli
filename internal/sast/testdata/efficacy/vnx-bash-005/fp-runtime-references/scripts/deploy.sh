#!/bin/bash
DB_PASSWORD="$(cat /run/secrets/db_password)"
API_KEY="${API_KEY:?API_KEY must be set}"
GITHUB_TOKEN=$GH_TOKEN
TOKEN=`vault kv get -field=token secret/ci`
read -rsp "Password: " PASSWORD
export AWS_SECRET_ACCESS_KEY="$AWS_SECRET"
SECRET=$(aws secretsmanager get-secret-value --secret-id app --query SecretString --output text)
echo "$DB_PASSWORD" | docker login -u ci --password-stdin registry.example.com
mysql -u root -p"$MYSQL_ROOT_PASSWORD" app
sshpass -p "$SSH_PASS" ssh deploy@web01 uptime
curl -u "admin:$ADMIN_PASSWORD" https://jenkins.internal/api
