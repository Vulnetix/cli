ARG NODE_VERSION=20.15.1
ARG RUNTIME_IMAGE=gcr.io/distroless/nodejs20-debian12:nonroot

FROM node:${NODE_VERSION}-bookworm AS build
WORKDIR /src
COPY . .
RUN npm ci && npm run build

FROM --platform=$BUILDPLATFORM golang:1.22.5@sha256:0b9d1a5e8c1b8e9f6f2c33e4a4c5b6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3 AS gotools
RUN go install example.com/tool@v1.2.3

FROM alpine:latest@sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b AS certs
RUN apk add --no-cache ca-certificates=20240705-r0

FROM build AS test
RUN npm test

FROM ${RUNTIME_IMAGE}
COPY --from=build /src/dist /app
COPY --from=0 /src/package.json /app/package.json
COPY --from=gotools /go/bin/tool /usr/local/bin/tool
COPY --from=certs /etc/ssl/certs /etc/ssl/certs
COPY --from=ghcr.io/example/assets:2024.06 /assets /app/assets
CMD ["/app/server.js"]

FROM scratch AS export
COPY --from=build /src/dist /
