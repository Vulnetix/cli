FROM python:3.12.4-slim
~>RUN --mount=from=ghcr.io/astral-sh/uv,source=/uv,target=/bin/uv \
    uv pip install --system -r requirements.txt
~>RUN --mount=type=bind,from=alpine:latest,source=/etc/apk,target=/tmp/apk ls /tmp/apk
