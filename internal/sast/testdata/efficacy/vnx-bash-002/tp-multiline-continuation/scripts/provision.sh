#!/usr/bin/env bash
set -euo pipefail

~>curl --fail --silent --show-error --location \
  https://get.example.com/install.sh \
  | bash -s -- --version 1.4.2

echo "installing agent"
~>wget --quiet --output-document=- \
    "https://agent.example.net/install" |
  sudo sh
