#!/bin/bash
curl -s https://status.example.org/health | grep -q ok && sh ./local-restart.sh
curl -s https://status.example.org/metrics | jq . ; cat ./local.sh | bash
wget -qO- https://example.org/version.txt | sort -V | head -n1 > version.txt
