#!/usr/bin/env bash
set -euo pipefail

INSTALLER_SHA256="9f2c1a0e5d4b3c2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a"

curl -fsSLo install.sh https://get.example.com/install.sh
echo "${INSTALLER_SHA256}  install.sh" | sha256sum -c -
bash install.sh

curl -fsSLo tool.sh https://tool.example.dev/tool.sh
curl -fsSLo tool.sh.asc https://tool.example.dev/tool.sh.asc
gpg --verify tool.sh.asc tool.sh
sh tool.sh --prefix /opt/tool

wget -O agent.sh https://agent.example.net/install.sh
cosign verify-blob --key agent.pub --signature agent.sh.sig agent.sh
sudo bash agent.sh
