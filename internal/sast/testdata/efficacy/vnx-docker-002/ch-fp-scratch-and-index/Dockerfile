FROM golang:1.22.5 AS build
RUN go build -o /app .
FROM scratch
COPY --from=0 /app /app
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/app"]
