#!/bin/sh
curl -H "Authorization: Basic ${REGISTRY_AUTH}" https://registry.acme-corp.io/v2/
curl -H "Authorization: Basic $(printf '%s:%s' "$U" "$P" | base64)" https://registry.acme-corp.io/v2/
