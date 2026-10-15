#!/bin/sh
curl https://api.linear.app/graphql \
  -H 'Content-Type: application/json' \
~>  -H 'Authorization: lin_api_@@sample:[A-Za-z0-9]{40}@@' \
  --data '{"query":"{ viewer { id } }"}'
