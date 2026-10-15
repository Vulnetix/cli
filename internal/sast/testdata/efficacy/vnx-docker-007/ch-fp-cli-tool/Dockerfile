FROM golang:1.22.5 AS build
COPY . /src
RUN cd /src && go build -o /out/tool ./cmd/tool

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/tool /tool
ENTRYPOINT ["/tool"]
