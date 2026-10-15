#!/bin/sh
# Template a maintainer copies and fills in by hand.
REGISTRY_URL_TEMPLATE="https://USERNAME:API_KEY@registry.acme-corp.io/v2/"
MIRROR_TEMPLATE="https://ACCOUNT_ID:ACCESS_TOKEN@mirror.acme-corp.io/simple/"
echo "set REGISTRY_URL from ${REGISTRY_URL_TEMPLATE}"
