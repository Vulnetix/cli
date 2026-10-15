#!/bin/sh
docker run --rm -u 1000:1001 curlimages/curl:8.5.0 -sS https://status.acme.io/health
curl -fsSL https://get.acme.io/install.sh | sudo -u deploy:deploy sh
curl -sS https://acme.io/data.tgz -o data.tgz && chown -u 1000:1000 data.tgz
