FROM docker:27.1-cli
~>RUN --security=insecure mount -t tmpfs tmpfs /mnt
~>LABEL INSTALL="podman run --rm --privileged IMAGE install"
~>ENTRYPOINT ["podman", "run", "--privileged", "--rm", "quay.io/example/agent:1.0"]
