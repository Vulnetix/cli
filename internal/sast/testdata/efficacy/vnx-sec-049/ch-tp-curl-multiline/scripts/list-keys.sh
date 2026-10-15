#!/bin/sh
curl https://api.anthropic.com/v1/organizations/api_keys \
  --header "anthropic-version: 2023-06-01" \
~>  --header "x-api-key: sk-ant-admin01-@@sample:[A-Za-z0-9_-]{93}@@AA"
