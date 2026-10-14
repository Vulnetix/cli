FROM golang:1.22-bookworm AS build
RUN useradd -u 10001 builder
USER builder
WORKDIR /src
COPY --chown=builder . .
RUN CGO_ENABLED=0 go build -o /tmp/out/api ./cmd/api

# The runtime stage starts from a fresh image: the builder's USER does not
# carry over, so this stage runs as root.
~>FROM debian:bookworm-slim
COPY --from=build /tmp/out/api /usr/local/bin/api
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/api"]
