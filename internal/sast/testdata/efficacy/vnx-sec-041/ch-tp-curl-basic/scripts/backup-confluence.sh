#!/bin/sh
curl -s \
~>  -u "svc@acme.io:@@sample:ATATT3xFfGF0[A-Za-z0-9_-]{180}=[A-F0-9]{8}@@" \
  https://acme.atlassian.net/wiki/rest/api/space
