# syntax=docker/dockerfile:1.7-labs
FROM docker:27.1-cli
~>LABEL RUN="docker run --privileged -v /:/host --name NAME IMAGE"
~>RUN --security=insecure mount -t tmpfs tmpfs /mnt && /usr/local/bin/build-rootfs.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
~>CMD ["docker", "run", "--privileged", "--rm", "ghcr.io/example/agent:1.0"]
