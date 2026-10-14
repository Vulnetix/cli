FROM debian:bookworm-slim
ADD rootfs.tar.gz /
ADD config/ /etc/app/
COPY --from=ghcr.io/example/tools:1.2.0 /usr/bin/tool /usr/bin/tool
ARG TOOL_SHA256=24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc68d
RUN curl -fsSLo /tmp/tool.tgz https://example.com/dist/tool-1.4.0.tgz \
    && echo "${TOOL_SHA256}  /tmp/tool.tgz" | sha256sum -c - \
    && tar -xzf /tmp/tool.tgz -C /usr/local/bin
ADD ${ARTIFACT_URL} /opt/artifact
