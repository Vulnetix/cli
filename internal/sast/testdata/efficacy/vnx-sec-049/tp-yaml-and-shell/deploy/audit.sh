#!/bin/sh
~>curl -s -H "x-api-key: sk-ant-admin01-@@sample:[A-Za-z0-9]{93}@@AA" \
  -H "anthropic-version: 2023-06-01" \
  https://api.anthropic.com/v1/organizations/users
