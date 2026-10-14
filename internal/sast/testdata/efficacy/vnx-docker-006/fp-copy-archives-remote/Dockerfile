FROM debian:bookworm-slim
COPY . /app
COPY --chown=app:app config/ /etc/app/
# ADD is the right instruction when the archive is meant to be unpacked
ADD rootfs.tar.gz /
ADD vendor/deps.tar.xz /opt/deps/
ADD ["dist/site.tgz", "/srv/www/"]
ADD third_party/toolchain.tar.bz2 /opt/toolchain/
# remote sources are VNX-DOCKER-004's concern
ADD https://example.com/dist/tool /usr/local/bin/tool
ADD --checksum=sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc68d https://example.com/dist/tool.tgz /opt/
ADD https://github.com/example/plugins.git#main /src/plugins
ADD ${BUNDLE} /opt/bundle/
ADD <<EOF /etc/motd
welcome
EOF
