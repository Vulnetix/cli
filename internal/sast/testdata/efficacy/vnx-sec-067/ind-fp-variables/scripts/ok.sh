#!/bin/sh
curl -u "${NEXUS_USER}:${NEXUS_PASS}" https://nexus.acme-corp.io/
curl -u "$USER:$PASS" https://nexus.acme-corp.io/
curl -u deployer https://nexus.acme-corp.io/
curl -u "admin:$(cat /run/secrets/pw)" https://nexus.acme-corp.io/
curl --negotiate -u : https://kerb.acme-corp.io/
