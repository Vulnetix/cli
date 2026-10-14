# FROM ubuntu
# Base image history: we used FROM node:latest until 2023.
ARG BASE
FROM ${BASE}
LABEL org.opencontainers.image.base.name="docker.io/library/node:latest"
RUN echo "FROM alpine:latest" > /tmp/Dockerfile.example
COPY <<EOF /usr/share/doc/app/Dockerfile.sample
FROM alpine
CMD ["sh"]
EOF
RUN python3 - <<'PY'
from pathlib import Path
from os import path as p
PY
FROM ${REGISTRY}/${IMAGE_WITH_TAG}
CMD ["/app"]
