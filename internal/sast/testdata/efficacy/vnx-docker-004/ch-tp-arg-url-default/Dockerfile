FROM debian:bookworm-slim
ARG TINI_URL=https://github.com/krallin/tini/releases/download/v0.19.0/tini
~>ADD ${TINI_URL} /tini
ARG DOWNLOAD_URL
ADD $DOWNLOAD_URL /opt/download
ARG CHECKED_URL=https://dl.example.com/tool.tar.gz
ADD --checksum=sha256:@@sample:2[4]45[4]f8[3]0c[d]b5[7]1e[2]c4[a]d1[5]48[1]11[9]c4[3]b3[c]af[d]48[d]d8[6]9a[9]b2[9]45[d]10[3]6d[1]dc[6]8d@@ ${CHECKED_URL} /tmp/
