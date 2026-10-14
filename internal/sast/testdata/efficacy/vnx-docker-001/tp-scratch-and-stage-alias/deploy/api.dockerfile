FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/api ./cmd/api

# scratch has no /etc/passwd and starts as uid 0
~>FROM scratch
COPY --from=build /out/api /api
ENTRYPOINT ["/api"]
