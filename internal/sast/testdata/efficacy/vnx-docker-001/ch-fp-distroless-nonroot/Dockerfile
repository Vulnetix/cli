FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/svc ./cmd/svc

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/svc /svc
ENTRYPOINT ["/svc"]
