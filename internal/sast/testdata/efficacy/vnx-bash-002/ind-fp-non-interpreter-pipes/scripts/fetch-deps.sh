#!/usr/bin/env bash
set -euo pipefail

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
curl -fsSL https://github.com/example/cli/releases/download/v2.1.0/cli_linux_amd64.tar.gz | tar -xz -C /usr/local/bin
latest=$(curl -s https://api.github.com/repos/example/cli/releases/latest | jq -r .tag_name)
wget -qO- https://example.org/manifest.json | tee manifest.json >/dev/null
echo "latest is $latest"
