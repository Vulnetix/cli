#!/bin/bash
PASSWORD_FILE="/run/secrets/db_password"
TOKEN_URL="https://auth.example.com/oauth/token"
MAX_TOKENS=4096
SECRET_NAME=prod/app/db
API_KEY_HEADER=X-Api-Key
export PGPASSWORD=postgres
REDIS_PASSWORD=""
ENABLE_TOKEN=true
