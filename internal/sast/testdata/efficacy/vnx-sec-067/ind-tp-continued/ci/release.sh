#!/bin/sh
curl -fsS -X PUT \
  -H 'Content-Type: application/zip' \
~>  -u "releaser:@@sample:[A-Za-z0-9]{16}@@" \
  --data-binary @dist.zip \
  https://artifacts.acme-corp.io/releases/dist.zip
