#!/usr/bin/env bash
tag=$(curl -s https://api.github.com/repos/o/r/releases/latest | jq -r .tag_name)
curl -fsSL https://example.org/key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/example.gpg
curl -fsSL https://example.org/app.tar.gz | tar -xz -C /opt
wget -qO- https://example.org/list.txt | grep -v '^#' | sort -u
curl -s https://example.org/health | bash_parse_status
cat ./install.sh | bash
