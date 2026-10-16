FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl=7.88.1-10+deb12u5 \
    ca-certificates=20230311 \
    && rm -rf /var/lib/apt/lists/*
RUN apk add --no-cache bash=5.2.26-r0
RUN dnf install -y gcc-11.4.1-3.el9
