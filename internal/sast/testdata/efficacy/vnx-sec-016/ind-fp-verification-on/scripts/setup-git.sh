#!/usr/bin/env bash
git config --global http.sslVerify true
export NODE_TLS_REJECT_UNAUTHORIZED=1
npm config set strict-ssl true
curl -fsSL https://get.example.org/agent.sh -o /tmp/agent.sh
wget https://get.example.org/other.sh
