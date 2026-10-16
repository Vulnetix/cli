#!/usr/bin/env bash
set -euo pipefail
JIRA_URL="https://acme.atlassian.net"
~>@@sample:ATATT3[A-Za-z0-9_-]{184}=[A-F0-9]{8}@@
curl -s -u "bot@acme.com:$TOKEN" "$JIRA_URL/rest/api/3/myself"
