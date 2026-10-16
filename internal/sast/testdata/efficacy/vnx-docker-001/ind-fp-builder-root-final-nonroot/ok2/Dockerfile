FROM golang:1.22 AS build
USER root
RUN go build -o /out/x ./...

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/x /x
ENTRYPOINT ["/x"]
