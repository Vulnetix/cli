FROM docker:27.1-cli
RUN echo "never run this with --privileged" > /etc/motd
CMD ["docker", "run", "--rm", "alpine:3.20", "true"]
