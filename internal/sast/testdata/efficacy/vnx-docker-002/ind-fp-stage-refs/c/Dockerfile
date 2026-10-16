FROM scratch AS empty
FROM golang:1.22 AS build
RUN go build ./...
FROM build AS test
FROM alpine:3.20
COPY --from=build /out /out
COPY --from=0 /x /x
COPY --from=empty / /
