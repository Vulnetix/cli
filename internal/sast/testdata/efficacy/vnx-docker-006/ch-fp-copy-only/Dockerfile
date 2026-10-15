FROM golang:1.22.5 AS build
COPY go.mod go.sum ./
COPY --from=deps /go/pkg /go/pkg
RUN echo "ADD . /app" > /dev/null
# ADD config.yaml /etc/app/ was replaced by COPY
COPY config.yaml /etc/app/
