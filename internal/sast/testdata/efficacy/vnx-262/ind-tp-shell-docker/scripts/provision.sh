#!/usr/bin/env bash
set -euo pipefail

useradd --system --create-home --shell /bin/bash deploy
echo "deploy:${DEPLOY_PW}" | chpasswd
~>chage -M 99999 deploy
