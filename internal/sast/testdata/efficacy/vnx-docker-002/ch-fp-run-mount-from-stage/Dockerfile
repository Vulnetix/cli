FROM golang:1.22.5 AS build
RUN go build -o /out/app .
FROM debian:bookworm-slim
RUN --mount=type=bind,from=build,source=/out,target=/mnt cp /mnt/app /usr/local/bin/
RUN --mount=from=ghcr.io/astral-sh/uv:0.4.18,source=/uv,target=/bin/uv uv --version
RUN --mount=type=cache,target=/root/.cache pip install -r requirements.txt
