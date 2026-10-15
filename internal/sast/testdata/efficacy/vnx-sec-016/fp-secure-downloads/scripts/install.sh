#!/usr/bin/env bash
curl -fsSL https://releases.example.com/tool.tar.gz -o /tmp/tool.tar.gz
curl --cacert /etc/ssl/internal-ca.pem https://internal.example.com/x
curl -K /etc/curlrc.d/api https://api.example.com
curl --key client.key --cert client.crt https://mtls.example.com
curl -s https://api.example.com/items | sort -k 2 -n
curl -s https://api.example.com/items | jq -r .name | cut -d, -f1 | sort -k1,1
wget -q https://mirror.example.com/pkg.deb
git config --global http.sslVerify true
npm config set strict-ssl true
export NODE_TLS_REJECT_UNAUTHORIZED=1
