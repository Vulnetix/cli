#!/bin/sh
set -eu
~>curl -s -H "x-api-key: @@sample:sk-ant-admin01-[A-Za-z0-9_-]{93}AA@@" \
  -H "anthropic-version: 2023-06-01" \
  https://api.anthropic.com/v1/organizations/users
