#!/bin/sh
set -e

~>curl -fsS -u "deploy:${ARTIFACTORY_TOKEN}" -T dist/app.tar.gz "https://artifacts.example.com/libs/app-${VERSION}.tar.gz"
~>sshpass -p "$DEPLOY_PASSWORD" ssh deploy@app01 'sudo systemctl restart app'
