#!/usr/bin/env bash
set -euo pipefail
~>export AUTH_HEADER="Authorization: Bearer @@sample:[A-Za-z0-9]{32}@@"
curl -sS -H "$AUTH_HEADER" https://api.acme.io/v1/sync
