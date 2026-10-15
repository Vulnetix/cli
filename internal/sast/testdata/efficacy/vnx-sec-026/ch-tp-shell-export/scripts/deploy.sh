#!/usr/bin/env bash
set -euo pipefail
~>export DIGITALOCEAN_ACCESS_TOKEN='dop_v1_@@sample:[a-f0-9]{64}@@'
doctl apps create-deployment "$APP_ID"
