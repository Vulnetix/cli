#!/bin/sh
set -eu

curl -fsSL https://releases.example.com/app.tar.gz | tar -xz -C /opt/app
sha=$(curl -sfSL "$url" | sha256sum)
curl -s https://api.example.com/releases/latest | jq -r .tag_name
curl -fsSL https://download.example.com/linux/gpg | sudo gpg --dearmor -o /usr/share/keyrings/example.gpg
wget -qO- https://download.example.com/linux/gpg | sudo apt-key add -
curl -s "$HEALTH_URL" | grep -q '"status":"ok"'
curl -fsSL https://example.com/repo.list | sudo tee /etc/apt/sources.list.d/example.list
curl -s https://example.com/script.sh | shellcheck -
curl -s https://example.com/fmt.sh | shfmt -d
curl -s https://example.com/data.csv | shasum -a 256
echo "$(curl -s https://example.com/version)"
