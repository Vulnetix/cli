FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/svc ./cmd/svc

FROM debian:bookworm-slim
COPY --from=build /out/svc /svc
USER 65532:65532
ENTRYPOINT ["/svc"]
