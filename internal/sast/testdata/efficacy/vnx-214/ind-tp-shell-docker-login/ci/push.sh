#!/usr/bin/env bash
set -euo pipefail

IMAGE="registry.example.com/acme/api:${GIT_SHA}"
~>docker login -u "$REGISTRY_USER" -p "$REGISTRY_TOKEN" registry.example.com
docker build -t "$IMAGE" .
docker push "$IMAGE"
