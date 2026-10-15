#!/bin/sh
curl --user $MVNW_USERNAME:$MVNW_PASSWORD -o wrapper.jar "$url" -f
curl -u "${NEXUS_USER}:${NEXUS_PASS}" https://nexus.acme-corp.io/
curl -u "$USER:$(cat /run/secrets/pw)" https://nexus.acme-corp.io/
