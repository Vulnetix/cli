# The Vulnetix runtime sensor image. Build from the repository root:
#
#   docker build -f deploy/sensor/Dockerfile --build-arg VERSION=v3.130.0 -t vulnetix-sensor .
#
# The binary is static (no CGO), so the final image is distroless with no
# shell, and it runs as a non-root user.
FROM golang:1.25-alpine AS build
ARG VERSION=dev
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/vulnetix-sensor ./cmd/vulnetix-sensor

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/vulnetix-sensor /usr/local/bin/vulnetix-sensor
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/vulnetix-sensor"]
