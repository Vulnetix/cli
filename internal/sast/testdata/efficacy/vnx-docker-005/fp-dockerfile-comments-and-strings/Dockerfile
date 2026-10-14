FROM alpine:3.20
# Run with: docker run --privileged -d example/app   <- do NOT do this in production
RUN --security=sandbox apk add --no-cache iproute2=6.9.0-r0
RUN echo "this image never needs --privileged" > /etc/motd
LABEL org.example.note="no --privileged required; use --cap-add NET_ADMIN"
CMD ["docker", "run", "--privileged=false", "--rm", "ghcr.io/example/agent:1.0"]
