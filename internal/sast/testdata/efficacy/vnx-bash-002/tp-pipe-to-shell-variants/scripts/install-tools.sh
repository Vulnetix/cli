#!/usr/bin/env bash
set -euo pipefail

~>curl -fsSL https://get.example.com/install.sh | bash
~>curl -sSL "https://tooling.example.com/setup" | sudo bash
~>curl -sSL https://sh.example.dev | sudo -E bash -s -- --channel stable
~>curl https://releases.example.org/install-docker/20.10.sh|sh
~>curl -sfL https://get.k3s.example.io | INSTALL_K3S_EXEC=server sh -
~>wget -qO- https://install.example.net/agent.sh | /bin/bash
~>wget -O - "$INSTALLER_URL" | sh -s -- -y
~>command curl -o- https://raw.githubusercontent.com/example/tool/v1.2.0/install.sh | zsh
~>curl -fsSL https://deb.example.com/setup_lts.x | sudo -E env bash -
