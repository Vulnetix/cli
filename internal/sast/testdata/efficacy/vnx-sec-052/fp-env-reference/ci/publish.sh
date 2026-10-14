#!/bin/sh
curl -f -T build/app.tar.gz -H "X-JFrog-Art-Api: ${ARTIFACTORY_API_KEY}" \
  https://acme.jfrog.io/artifactory/releases/app.tar.gz
