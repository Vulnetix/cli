#!/bin/sh
docker run -d --name dd-agent \
~>  -e DD_API_KEY="@@sample:[0-9a-f]{32}@@" \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  gcr.io/datadoghq/agent:7
