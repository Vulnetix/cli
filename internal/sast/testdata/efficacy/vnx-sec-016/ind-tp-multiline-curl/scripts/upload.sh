#!/bin/sh
curl -fsS -X POST \
  -H "Content-Type: application/json" \
~>  --insecure \
  -d @payload.json \
  https://ingest.internal.example/v1/events
