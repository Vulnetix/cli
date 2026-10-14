# syntax=docker/dockerfile:1.7
FROM debian:bookworm-slim
ADD --checksum=sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc68d https://example.com/dist/tool-1.4.0.tar.gz /opt/
ADD --chmod=755 \
    --checksum=sha256:9b1f3a7e2c4d6e8f0a1b3c5d7e9f1a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f \
    https://example.com/dist/agent /usr/local/bin/agent
ADD https://github.com/example/plugins.git#3f9c2a1b7d8e4f6a0b2c4d6e8f0a1b3c5d7e9f1a /src/plugins
