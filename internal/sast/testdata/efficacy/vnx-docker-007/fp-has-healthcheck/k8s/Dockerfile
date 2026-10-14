FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/api ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot AS base
HEALTHCHECK CMD ["/api", "healthcheck"]

# inherits the HEALTHCHECK of the base stage
FROM base
COPY --from=build /out/api /api
EXPOSE 8080
ENTRYPOINT ["/api"]
