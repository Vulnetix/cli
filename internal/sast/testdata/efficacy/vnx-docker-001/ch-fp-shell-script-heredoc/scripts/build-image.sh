#!/usr/bin/env bash
set -euo pipefail
cat > "$WORKDIR/Dockerfile" <<EOF
FROM ubuntu:22.04
RUN apt-get update
EOF
docker build -t local/tmp "$WORKDIR"
