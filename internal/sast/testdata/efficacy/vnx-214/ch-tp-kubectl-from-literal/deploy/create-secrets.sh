#!/usr/bin/env bash
set -euo pipefail
~>kubectl create secret generic db-creds --from-literal=username=app --from-literal=password="$DB_PASSWORD"
~>aws configure set aws_secret_access_key "$AWS_SECRET_ACCESS_KEY"
~>htpasswd -bc /etc/nginx/.htpasswd admin "$ADMIN_PASS"
kubectl create secret generic db-creds --from-file=password=./db-password.txt
aws configure set region "$AWS_REGION"
