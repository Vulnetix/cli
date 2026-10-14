#!/bin/sh
curl -f -T build/app.tar.gz \
~>  -H "X-JFrog-Art-Api: AKCp@@sample:[A-Za-z0-9]{69}@@" \
  https://acme.jfrog.io/artifactory/releases/app.tar.gz
