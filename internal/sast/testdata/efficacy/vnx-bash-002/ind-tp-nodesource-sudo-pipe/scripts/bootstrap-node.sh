#!/usr/bin/env bash
set -euo pipefail

apt-get update
apt-get install -y ca-certificates curl
~>curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
apt-get install -y nodejs
