#!/usr/bin/env bash
set -euo pipefail
mvn -B verify sonar:sonar \
  -Dsonar.host.url=https://sonar.acme.internal \
~>  -Dsonar.token=squ_@@sample:[0-9a-f]{40}@@
