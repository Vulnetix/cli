#!/bin/bash
PASSWORD_FILE=/etc/app/db.pass
TOKEN_URL=https://auth.example.org/oauth/token
SECRET_NAME=prod-db-credentials
PASSWORD_MIN_LENGTH=12
API_KEY_HEADER=X-Api-Key
echo "Set PASSWORD=yourpassword in the environment"
