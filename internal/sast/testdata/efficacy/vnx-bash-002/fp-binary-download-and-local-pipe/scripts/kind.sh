#!/bin/bash
# Binary downloads are outside this rule (they are not piped into an interpreter).
curl -Lo ./kind https://kind.example.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Local files and generated scripts piped to a shell are not downloads.
cat ./generated/setup.sh | bash
./render-config.sh | sh
make print-env | sh
curl -fsSLo archive.tar.gz https://releases.example.com/app.tar.gz
tar -xzf archive.tar.gz
