#!/usr/bin/env bash
set -euo pipefail

~>curl -k https://releases.example.com/tool.tar.gz -o /tmp/tool.tar.gz
~>curl --insecure -fsSL https://get.example.com/setup.sh -o setup.sh
~>curl -sSLk "$URL" | tar xz -C /opt
~>VERSION=$(curl -fsk https://api.example.com/version)
~>sudo curl -kLo /usr/local/bin/tool https://dl.example.com/tool
~>if ! /usr/bin/curl -s -k https://health.example.com; then exit 1; fi
