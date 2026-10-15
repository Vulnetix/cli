#!/usr/bin/env bash
set -euo pipefail
~>curl -sf -H "Authorization: Bearer eyJrIjoi@@sample:[A-Za-z0-9]{72}@@" \
  https://grafana.acme.io/api/search?type=dash-db > dashboards.json
