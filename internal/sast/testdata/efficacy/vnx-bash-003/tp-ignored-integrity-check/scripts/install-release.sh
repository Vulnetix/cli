#!/usr/bin/env bash
VERSION="1.8.2"
URL="https://releases.example.com/app/${VERSION}/app.tar.gz"

curl -fsSLo app.tar.gz "$URL"
curl -fsSLo app.tar.gz.sha256 "$URL.sha256"
~>sha256sum -c app.tar.gz.sha256
tar -xzf app.tar.gz -C /opt/app

curl -fsSLo app.tar.gz.asc "$URL.asc"
~>gpg --batch --verify app.tar.gz.asc app.tar.gz
install -m 0755 /opt/app/bin/app /usr/local/bin/app

~>echo "${EXPECTED_SUM}  plugin.tgz" | sha256sum --check
tar -xzf plugin.tgz -C /opt/app/plugins

~>cosign verify-blob --key cosign.pub --signature agent.sig agent
./agent install

~>shasum -a 512 -c checksums.txt > /dev/null
echo "installed ${VERSION}"
