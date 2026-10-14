#!/usr/bin/env bash
set -euo pipefail
az storage blob upload-batch \
  --account-name contosodata \
~>  --account-key '@@sample:[A-Za-z0-9+/]{86}@@==' \
  --destination '$web' --source ./dist
