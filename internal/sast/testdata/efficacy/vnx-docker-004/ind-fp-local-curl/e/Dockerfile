FROM alpine:3.20
COPY app.tar.gz /opt/
ADD rootfs.tar.xz /
RUN curl -fsSL https://example.com/tool.tgz -o /tmp/t.tgz
ARG SRC
ADD ${SRC} /opt/
