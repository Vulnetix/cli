#!/usr/bin/env bash
set -euo pipefail
ARTIFACT=app-${VERSION}.tar.gz
~>curl -T "$ARTIFACT" ftp://deploy:Pa55word@files.acmecorp.net/releases/
echo "uploaded"
