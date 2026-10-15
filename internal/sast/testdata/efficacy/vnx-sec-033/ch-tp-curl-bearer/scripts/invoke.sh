#!/usr/bin/env bash
set -euo pipefail
curl -sS -X POST "https://@@sample:b[e]dr[o]ck[-]ru[n]ti[m]e[.][u]s[-][e]as[t][-]1[.]am[a]zo[n]aw[s][.]c[o]m@@/model/anthropic.claude-v2/invoke" \
~>  -H "Authorization: Bearer @@sample:ABSKQmVkcm9ja0FQSUtleS[A-Za-z0-9+/]{120}@@" \
  -H "Content-Type: application/json" \
  -d @body.json
