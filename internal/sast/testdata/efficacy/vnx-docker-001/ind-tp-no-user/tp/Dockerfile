FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY . .
RUN go build -o /out/api ./cmd/api
USER builder

~>FROM debian:12-slim
COPY --from=build /out/api /usr/local/bin/api
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/api"]
